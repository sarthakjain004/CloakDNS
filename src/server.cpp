#include "cloakdns/server.hpp"

#include "cloakdns/aliases.hpp"
#include "cloakdns/blocklist.hpp"
#include "cloakdns/cache.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/ech_bootstrap.hpp"
#include "cloakdns/privilege.hpp"
#include "cloakdns/query_log.hpp"
#include "cloakdns/tls.hpp"
#include "cloakdns/uncloaker.hpp"
#include "cloakdns/wire_endian.hpp"

#include <asio.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <shared_mutex>

namespace cloak {

namespace {

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;
using namespace std::chrono_literals;

constexpr uint16_t kTypeA    = 1;
constexpr uint16_t kTypeAAAA = 28;

bool is_address_qtype(uint16_t q) {
    return q == kTypeA || q == kTypeAAAA;
}

// Whitelist of qtypes safe to forward as a recursive-resolver front end.
// Excludes ANY (255) and AXFR/IXFR (252/251) — abuse vectors with no
// legitimate use against a stub resolver.
bool is_forwardable_qtype(uint16_t q) {
    switch (q) {
      case 1:   // A
      case 2:   // NS
      case 5:   // CNAME
      case 6:   // SOA
      case 12:  // PTR
      case 15:  // MX
      case 16:  // TXT
      case 28:  // AAAA
      case 33:  // SRV
      case 35:  // NAPTR
      case 43:  // DS
      case 46:  // RRSIG
      case 47:  // NSEC
      case 48:  // DNSKEY
      case 64:  // SVCB
      case 65:  // HTTPS
      case 257: // CAA
        return true;
      default:
        return false;
    }
}

void log_chain(std::ostream& os, const vector<string>& chain) {
    os << " (chain:";
    for (const auto& h : chain) os << ' ' << h;
    os << ')';
}

// Hot-reload-friendly shared-pointer holder. libc++ on Apple still
// lacks atomic<shared_ptr> as of Xcode 16; shared_ptr + shared_mutex
// is portable.
using BlocklistPtr = shared_ptr<const Blocklist>;
BlocklistPtr      g_blocklist;
std::shared_mutex g_blocklist_mu;

BlocklistPtr blocklist_load() {
    std::shared_lock lk{g_blocklist_mu};
    return g_blocklist;
}

void blocklist_store(BlocklistPtr p) {
    unique_lock lk{g_blocklist_mu};
    g_blocklist = std::move(p);
}

Blocklist build_blocklist(const Config& cfg) {
    Blocklist out;
    size_t total = 0;
    for (const auto& src : cfg.blocklist.sources) {
        total += out.load_hosts_file(src);
    }
    size_t allow = 0;
    for (const auto& src : cfg.allowlist.sources) {
        allow += out.load_allowlist_file(src);
    }
    std::cout << "loaded " << total << " block rule(s) from "
              << cfg.blocklist.sources.size() << " source(s)";
    if (!cfg.allowlist.sources.empty()) {
        std::cout << ", " << allow << " allow rule(s) from "
                  << cfg.allowlist.sources.size() << " source(s)";
    }
    std::cout << std::endl;
    return out;
}

awaitable<void> handle(vector<byte> query_buf,
                       udp::endpoint from,
                       udp::socket& sock,
                       BlocklistPtr bl_snapshot,
                       resolver::Resolver& resolver,
                       CnameUncloaker& uncloaker,
                       DnsCache& cache,
                       QueryLogger& logger) {
    const auto& bl = *bl_snapshot;
    const auto t0  = chrono::steady_clock::now();
    const auto wallclock_start = chrono::system_clock::now();
    const auto query = span<const byte>{query_buf};

    auto log_record = [&](LogAction action,
                          const string& qname,
                          uint16_t qtype,
                          string rule = "",
                          vector<string> chain = {},
                          optional<string> upstream = nullopt,
                          optional<tls::EchStatus> ech = nullopt) {
        QueryLog rec;
        rec.ts          = wallclock_start;
        rec.qname       = qname;
        rec.qtype       = qtype;
        rec.action      = action;
        rec.rule        = std::move(rule);
        rec.cname_chain = std::move(chain);
        rec.upstream    = std::move(upstream);
        rec.client      = cloak::to_string_via_stream(from);
        rec.latency_ms  = chrono::duration<double, std::milli>(
            chrono::steady_clock::now() - t0).count();
        if (ech && *ech != tls::EchStatus::NotTried) {
            rec.tls_ech_status = string{tls::to_string(*ech)};
        }
        logger.log(std::move(rec));
    };

    try {
        const auto msg = parse(query);
        const auto& qname = msg.questions.empty()
            ? string{"<no-question>"}
            : msg.questions[0].qname;
        const uint16_t qtype = msg.questions.empty() ? 0 : msg.questions[0].qtype;

        if (msg.questions.size() != 1 || !is_forwardable_qtype(qtype)) {
            auto response = build_refused_response(query, msg);
            std::cout << "refuse  " << qname << "  qtype=" << qtype << std::endl;
            log_record(LogAction::Refuse, qname, qtype);
            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
            co_return;
        }

        const auto hit = bl.match(qname);
        if (hit.blocked) {
            vector<byte> response;
            switch (qtype) {
              case kTypeA:
                response = build_block_a_response(query, msg); break;
              case kTypeAAAA:
                response = build_block_aaaa_response(query, msg); break;
              default:
                response = build_block_nodata_response(query, msg); break;
            }
            std::cout << "block   " << qname << "  via " << hit.rule
                      << "  qtype=" << qtype << std::endl;
            log_record(LogAction::Block, qname, qtype, hit.rule);
            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
            co_return;
        }

        if (auto key = make_cache_key(msg)) {
            if (auto cached = cache.lookup(*key, msg.header.id)) {
                co_await apply_jitter(cache.jitter_max());
                co_await sock.async_send_to(
                    asio::buffer(*cached), from, use_awaitable);
                std::cout << "cached  " << qname << std::endl;
                log_record(LogAction::Cached, qname, qtype);
                co_return;
            }
        }

        vector<byte> response;
        try {
            auto fwd_result    = co_await resolver.forward_with_source(query);
            auto upstream_resp = std::move(fwd_result.response);
            const auto upstream_str = fwd_result.upstream;
            const auto upstream_ech = fwd_result.ech_status;

            auto try_cache_insert = [&]() {
                if (auto key = make_cache_key(msg)) {
                    try {
                        const auto resp_msg = parse(span<const byte>{upstream_resp});
                        const auto ttl = compute_cache_ttl(resp_msg);
                        if (ttl.count() > 0) {
                            cache.insert(*key, upstream_resp, resp_msg, ttl);
                        }
                    } catch (const ParseError&) {
                        // Upstream response unparseable; skip cache.
                    }
                }
            };

            if (is_address_qtype(qtype)) {
                auto result = co_await uncloaker.uncloak(qname, upstream_resp);

                switch (result.status) {
                case UncloakStatus::Blocked:
                    response = qtype == kTypeAAAA
                        ? build_block_aaaa_response(query, msg)
                        : build_block_a_response(query, msg);
                    std::cout << "uncloak " << qname
                              << "  via " << result.hit.rule;
                    log_chain(std::cout, result.chain);
                    std::cout << std::endl;
                    log_record(LogAction::Uncloak, qname, qtype,
                               result.hit.rule, result.chain, upstream_str,
                               upstream_ech);
                    break;
                case UncloakStatus::Aborted:
                    response = build_servfail_response(query, msg);
                    std::cout << "servfail " << qname
                              << "  (" << result.abort_reason << ")"
                              << std::endl;
                    log_record(LogAction::ServFail, qname, qtype,
                               result.abort_reason, {}, upstream_str,
                               upstream_ech);
                    break;
                case UncloakStatus::Clean:
                    try_cache_insert();
                    response = std::move(upstream_resp);
                    if (result.crossed_etldp1) {
                        std::cout << "suspect " << qname
                                  << "  -> " << result.crossed_to;
                        log_chain(std::cout, result.chain);
                        std::cout << std::endl;
                        log_record(LogAction::Suspicious, qname, qtype,
                                   "etldp1-cross:" + result.crossed_to,
                                   result.chain, upstream_str, upstream_ech);
                    } else {
                        std::cout << "forward " << qname;
                        if (result.chain.size() > 1)
                            log_chain(std::cout, result.chain);
                        std::cout << std::endl;
                        log_record(LogAction::Allow, qname, qtype,
                                   "", result.chain, upstream_str, upstream_ech);
                    }
                    break;
                }
            } else {
                try_cache_insert();
                response = std::move(upstream_resp);
                std::cout << "forward " << qname << "  qtype=" << qtype << std::endl;
                log_record(LogAction::Allow, qname, qtype,
                           "", {}, upstream_str, upstream_ech);
            }
        } catch (const exception& e) {
            response = build_servfail_response(query, msg);
            std::cout << "servfail " << qname << "  (" << e.what() << ")" << std::endl;
            log_record(LogAction::ServFail, qname, qtype, e.what());
        }

        co_await sock.async_send_to(
            asio::buffer(response), from, use_awaitable);
    } catch (const ParseError& e) {
        std::cout << "drop malformed from " << from
                  << ": " << e.what() << std::endl;
    } catch (const exception& e) {
        std::cout << "handler error: " << e.what() << std::endl;
    }
}

awaitable<void> serve(udp::socket& sock,
                      resolver::Resolver& resolver,
                      CnameUncloaker& uncloaker,
                      DnsCache& cache,
                      QueryLogger& logger) {
    auto executor = co_await asio::this_coro::executor;
    array<byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        size_t n = 0;
        try {
            n = co_await sock.async_receive_from(
                asio::buffer(buf), from, use_awaitable);
        } catch (const system_error& e) {
            // On Windows, sending UDP to a closed client port produces
            // ICMP port-unreachable surfaced as WSAECONNRESET on the
            // *next* recvfrom. SIO_UDP_CONNRESET = FALSE on bind disables
            // the bounce, but keep this catch as a safety net.
            std::cerr << "recv error (continuing): " << e.what() << std::endl;
            continue;
        }
        vector<byte> copy(buf.data(), buf.data() + n);
        auto snapshot = blocklist_load();
        co_spawn(executor,
                 handle(std::move(copy), from, sock, std::move(snapshot),
                        resolver, uncloaker, cache, logger),
                 detached);
    }
}

} // anonymous namespace

struct Server::Impl {
    asio::io_context&                ctx;
    Config                           cfg;
    unique_ptr<resolver::Resolver>   resolver;
    fs::path                         reload_path;

    optional<DnsCache>               cache;
    optional<QueryLogger>            logger;
    optional<CnameUncloaker>         uncloaker;
    optional<udp::socket>            sock;
    BlocklistPtr                     uncloak_blocklist_pin;

    Impl(asio::io_context& c, Config in_cfg,
         unique_ptr<resolver::Resolver> r, fs::path rp)
        : ctx{c},
          cfg{std::move(in_cfg)},
          resolver{std::move(r)},
          reload_path{std::move(rp)} {}

    // Eager ECH bootstrap (ADR 0003). Mutates cfg.upstream.ech_config_list
    // on success and stamps the snapshot's fetched_at.
    bool bootstrap_ech_at_startup() {
        if (!cfg.upstream.ech_enabled || !cfg.upstream.ech_autobootstrap)
            return false;

        vector<asio::ip::udp::endpoint> bootstrap_eps;
        for (const auto& ep : cfg.upstream.ech_bootstrap_servers) {
            bootstrap_eps.emplace_back(make_address(ep.host), ep.port);
        }
        std::cout << "ech bootstrap: querying " << cfg.upstream.servername
                  << " HTTPS via " << bootstrap_eps.size() << " resolver(s)"
                  << std::endl;
        auto fut = asio::co_spawn(
            ctx,
            cloak::bootstrap_ech_config(
                ctx,
                span<const asio::ip::udp::endpoint>{bootstrap_eps},
                cfg.upstream.servername,
                cfg.upstream.timeout),
            asio::use_future);
        ctx.run();
        ctx.restart();
        if (auto bytes = fut.get(); bytes && !bytes->empty()) {
            cfg.upstream.ech_config_list = std::move(*bytes);
            return true;
        }
        if (cfg.upstream.ech_config_list.empty()) {
            throw runtime_error{
                "ech bootstrap failed and no inline ech_config_list_b64 "
                "fallback — refusing to start with ECH enabled but no "
                "config bytes"};
        }
        std::cerr << "ech bootstrap failed; falling back to inline "
                  << "ech_config_list_b64 ("
                  << cfg.upstream.ech_config_list.size() << " bytes)"
                  << std::endl;
        return false;
    }

    // Atomically swap a freshly-built ECHConfigList into every Adapter
    // that has a tls::Context. `from_bootstrap=true` stamps fetched_at
    // with now() so staleness tracking knows the bytes are fresh.
    void swap_ech(const Config& c, bool from_bootstrap) {
        const auto now = chrono::system_clock::now();
        if (from_bootstrap) {
            for (const auto& s : resolver->control().stats()) {
                if (s.ech_fetched_at) {
                    const auto age_h = chrono::duration_cast<chrono::hours>(
                        now - *s.ech_fetched_at);
                    std::cout << "ech: refreshed config — previous was "
                              << age_h.count() << "h old" << std::endl;
                    break;
                }
            }
        }
        resolver->control().swap_ech_config(
            c.upstream.ech_config_list,
            c.upstream.ech_outer_servername,
            from_bootstrap ? now : chrono::system_clock::time_point{});
        std::cout << "reload: swapped ECH config ("
                  << c.upstream.ech_config_list.size() << " bytes)"
                  << std::endl;
    }

    int run() {
        const bool bootstrap_succeeded = bootstrap_ech_at_startup();

        blocklist_store(make_shared<Blocklist>(build_blocklist(cfg)));

        if (bootstrap_succeeded) {
            resolver->control().swap_ech_config(
                cfg.upstream.ech_config_list,
                cfg.upstream.ech_outer_servername,
                chrono::system_clock::now());
        }

        // Pin the initial Blocklist snapshot for the Uncloaker's lifetime
        // — hot reload swaps g_blocklist, but the Uncloaker holds a
        // const reference and would dangle without this pin.
        uncloak_blocklist_pin = blocklist_load();
        uncloaker.emplace(*resolver, *uncloak_blocklist_pin,
            CnameUncloaker::Config{.max_depth = cfg.uncloak.max_depth});

        cache.emplace(DnsCache::Config{
            .jitter_max     = cfg.cache.jitter_max,
            .sweep_interval = cfg.cache.sweep_interval,
            .max_entries    = cfg.cache.max_entries,
        });

        logger.emplace(QueryLogger::Config{
            .path           = cfg.logging.path,
            .async          = cfg.logging.async,
            .queue_size     = cfg.logging.queue_size,
            .max_size_bytes = cfg.logging.max_size_bytes,
            .redact_client  = cfg.logging.redact_client,
        });

        sock.emplace(ctx, udp::endpoint{
            make_address(cfg.server.listen_addr), cfg.server.listen_port});

#if defined(_WIN32)
        // SIO_UDP_CONNRESET = FALSE on the listen socket — see KB 263823.
        // Without this, an ICMP port-unreachable bounce kills the receive
        // loop on the next packet.
        {
            DWORD bytes_returned = 0;
            BOOL conn_reset = FALSE;
            constexpr DWORD kSioUdpConnReset = _WSAIOW(IOC_VENDOR, 12);
            if (::WSAIoctl(sock->native_handle(), kSioUdpConnReset,
                           &conn_reset, sizeof(conn_reset),
                           nullptr, 0, &bytes_returned,
                           nullptr, nullptr) == SOCKET_ERROR) {
                std::cerr << "warn: WSAIoctl(SIO_UDP_CONNRESET) failed: "
                          << ::WSAGetLastError() << std::endl;
            }
        }
#endif

        // Drop privileges AFTER bind — bind(53) needs CAP_NET_BIND_SERVICE
        // / root, but the hot path shouldn't.
        drop_privileges(cfg.service.run_as_user, cfg.service.run_as_group);

        std::cout << "cloakdns listening on "
                  << cfg.server.listen_addr << ":" << cfg.server.listen_port
                  << std::endl;
        std::cout << "upstream:";
        for (const auto& ep : cfg.upstream.servers)
            std::cout << " " << ep.host << ":" << ep.port;
        std::cout << "  (timeout " << cfg.upstream.timeout.count() << "ms)"
                  << std::endl;
        std::cout << "cname uncloaking: max depth " << cfg.uncloak.max_depth
                  << std::endl;
        std::cout << "cache: " << cfg.cache.max_entries << " entries, jitter 0-"
                  << cfg.cache.jitter_max.count() << "ms on hit, sweep "
                  << cfg.cache.sweep_interval.count() << "s" << std::endl;
        std::cout << "padding: ";
        if (cfg.upstream.padding_block_size == 0) std::cout << "disabled";
        else std::cout << cfg.upstream.padding_block_size << "-byte blocks";
        std::cout << std::endl;
        std::cout << "logging: ";
        if (cfg.logging.path.empty()) std::cout << "disabled";
        else std::cout << cfg.logging.path.string()
                       << (cfg.logging.async ? " (async)" : " (sync)");
        std::cout << std::endl;

        asio::signal_set stop_signals{ctx, SIGINT, SIGTERM};
        stop_signals.async_wait([this](const error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

#if defined(_WIN32)
        constexpr int kReloadSignal = SIGBREAK;
        const char* kReloadName = "SIGBREAK";
#else
        constexpr int kReloadSignal = SIGHUP;
        const char* kReloadName = "SIGHUP";
#endif
        asio::signal_set reload_signals{ctx, kReloadSignal};
        std::function<void(const error_code&, int)> on_reload;
        on_reload = [this, &reload_signals, &on_reload, kReloadName]
                    (const error_code& ec, int) {
            if (ec) return;
            try {
                std::cout << "\nreload (" << kReloadName
                          << "): rebuilding blocklist" << std::endl;
                Config fresh_cfg = cfg;
                if (!reload_path.empty()) {
                    fresh_cfg = load_config(reload_path);
                }
                auto fresh = make_shared<Blocklist>(build_blocklist(fresh_cfg));
                blocklist_store(std::move(fresh));

                if (fresh_cfg.upstream.ech_enabled &&
                    fresh_cfg.upstream.ech_autobootstrap &&
                    fresh_cfg.upstream.protocol != UpstreamProtocol::Udp) {
                    // Re-bootstrap async so we don't deadlock the
                    // bootstrap's own UDP I/O on this signal handler.
                    vector<asio::ip::udp::endpoint> bootstrap_eps;
                    for (const auto& ep : fresh_cfg.upstream.ech_bootstrap_servers) {
                        bootstrap_eps.emplace_back(make_address(ep.host), ep.port);
                    }
                    asio::co_spawn(
                        ctx,
                        [this, fresh_cfg, bootstrap_eps]() mutable
                            -> awaitable<void> {
                            auto bytes = co_await cloak::bootstrap_ech_config(
                                ctx,
                                span<const asio::ip::udp::endpoint>{bootstrap_eps},
                                fresh_cfg.upstream.servername,
                                fresh_cfg.upstream.timeout);
                            const bool got_fresh = bytes && !bytes->empty();
                            if (got_fresh) {
                                fresh_cfg.upstream.ech_config_list = std::move(*bytes);
                            } else {
                                std::cerr << "reload: ech bootstrap returned "
                                          << "no bytes; keeping previous "
                                          << "config" << std::endl;
                            }
                            swap_ech(fresh_cfg, got_fresh);
                            co_return;
                        },
                        asio::detached);
                } else {
                    swap_ech(fresh_cfg, /*from_bootstrap=*/false);
                }
            } catch (const exception& e) {
                std::cerr << "reload failed (" << e.what()
                          << ") — keeping previous blocklist" << std::endl;
            }
            reload_signals.async_wait(on_reload);
        };
        reload_signals.async_wait(on_reload);

        co_spawn(ctx, serve(*sock, *resolver, *uncloaker, *cache, *logger),
                 detached);
        ctx.run();
        return 0;
    }

    void stop() { ctx.stop(); }
};

Server::Server(asio::io_context& ctx,
               Config cfg,
               unique_ptr<resolver::Resolver> r,
               fs::path reload_path)
    : impl_{make_unique<Impl>(ctx, std::move(cfg), std::move(r),
                              std::move(reload_path))} {}

Server::~Server() = default;

int  Server::run()  { return impl_->run(); }
void Server::stop() { impl_->stop(); }

} // namespace cloak
