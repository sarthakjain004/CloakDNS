#include "cloakdns/blocklist.hpp"
#include "cloakdns/cache.hpp"
#include "cloakdns/config.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/paths.hpp"
#include "cloakdns/privilege.hpp"
#include "cloakdns/query_log.hpp"
#include "cloakdns/uncloaker.hpp"
#include "cloakdns/upstream.hpp"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/this_coro.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

constexpr uint16_t kTypeA    = 1;
constexpr uint16_t kTypeAAAA = 28;

bool is_address_qtype(uint16_t q) {
    return q == kTypeA || q == kTypeAAAA;
}

// Whitelist of qtypes safe to forward as a recursive-resolver front end.
// Notably excludes ANY (255) and AXFR/IXFR (252/251) — abuse vectors with
// no legitimate use against a stub resolver. SVCB (64) and HTTPS (65)
// are included so Chrome's H3 endpoint hints reach upstream and tracker
// blocking covers the SVCB-only request paths surfaced in the
// learnings/real-chrome-capture.md run.
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

void log_chain(std::ostream& os, const std::vector<std::string>& chain) {
    os << " (chain:";
    for (const auto& h : chain) os << ' ' << h;
    os << ')';
}

template <class T>
std::string to_string_via_stream(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

} // namespace

awaitable<void> handle(std::vector<std::byte> query_buf,
                       udp::endpoint from,
                       udp::socket& sock,
                       std::shared_ptr<const cloak::Blocklist> bl_snapshot,
                       cloak::UpstreamForwarder& fwd,
                       cloak::CnameUncloaker& uncloaker,
                       cloak::DnsCache& cache,
                       cloak::QueryLogger& logger) {
    const auto& bl = *bl_snapshot;
    const auto t0 = std::chrono::steady_clock::now();
    const auto wallclock_start = std::chrono::system_clock::now();
    const auto query = std::span<const std::byte>{query_buf};

    auto log_record = [&](cloak::LogAction action,
                          const std::string& qname,
                          uint16_t qtype,
                          std::string rule = "",
                          std::vector<std::string> chain = {},
                          std::optional<std::string> upstream = std::nullopt) {
        cloak::QueryLog rec;
        rec.ts          = wallclock_start;
        rec.qname       = qname;
        rec.qtype       = qtype;
        rec.action      = action;
        rec.rule        = std::move(rule);
        rec.cname_chain = std::move(chain);
        rec.upstream    = std::move(upstream);
        rec.client      = to_string_via_stream(from);
        rec.latency_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        logger.log(std::move(rec));
    };

    try {
        const auto msg = cloak::parse(query);
        const auto& qname = msg.questions.empty()
            ? std::string{"<no-question>"}
            : msg.questions[0].qname;
        const uint16_t qtype = msg.questions.empty() ? 0 : msg.questions[0].qtype;

        // 1. Reject multi-question and unsupported qtypes (ANY, AXFR, ...)
        //    before consulting the blocklist. Chrome never asks these; if
        //    something does, it's almost certainly abuse.
        if (msg.questions.size() != 1 || !is_forwardable_qtype(qtype)) {
            auto response = cloak::build_refused_response(query, msg);
            std::cout << "refuse  " << qname << "  qtype=" << qtype << std::endl;
            log_record(cloak::LogAction::Refuse, qname, qtype);
            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
            co_return;
        }

        // 2. Blocklist hit on the qname → synthesize a qtype-shaped "no":
        //    A → 0.0.0.0, AAAA → ::, anything else → empty NOERROR (NODATA).
        const auto hit = bl.match(qname);
        if (hit.blocked) {
            std::vector<std::byte> response;
            switch (qtype) {
              case kTypeA:
                response = cloak::build_block_a_response(query, msg); break;
              case kTypeAAAA:
                response = cloak::build_block_aaaa_response(query, msg); break;
              default:
                response = cloak::build_block_nodata_response(query, msg); break;
            }
            std::cout << "block   " << qname << "  via " << hit.rule
                      << "  qtype=" << qtype << std::endl;
            log_record(cloak::LogAction::Block, qname, qtype, hit.rule);
            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
            co_return;
        }

        // 3. Cache lookup — already qtype-keyed via make_cache_key.
        if (auto key = cloak::make_cache_key(msg)) {
            if (auto cached = cache.lookup(*key, msg.header.id)) {
                co_await cloak::apply_jitter(cache.jitter_max());
                co_await sock.async_send_to(
                    asio::buffer(*cached), from, use_awaitable);
                std::cout << "cached  " << qname << std::endl;
                log_record(cloak::LogAction::Cached, qname, qtype);
                co_return;
            }
        }

        // 4. Forward upstream. Address qtypes (A/AAAA) get CNAME-chain
        //    uncloaking; other qtypes forward as-is (qname-level blocking
        //    above already covered the tracker case for them).
        std::vector<std::byte> response;
        try {
            auto fwd_result = co_await fwd.forward_with_source(query);
            auto upstream_resp = std::move(fwd_result.response);
            const auto upstream_str = to_string_via_stream(fwd_result.answered_by);

            auto try_cache_insert = [&]() {
                if (auto key = cloak::make_cache_key(msg)) {
                    try {
                        const auto resp_msg = cloak::parse(
                            std::span<const std::byte>{upstream_resp});
                        const auto ttl = cloak::compute_cache_ttl(resp_msg);
                        if (ttl.count() > 0) {
                            cache.insert(*key, upstream_resp, resp_msg, ttl);
                        }
                    } catch (const cloak::ParseError&) {
                        // Upstream response unparseable; skip cache, forward as-is.
                    }
                }
            };

            if (is_address_qtype(qtype)) {
                auto result = co_await uncloaker.uncloak(qname, upstream_resp);

                switch (result.status) {
                case cloak::UncloakStatus::Blocked:
                    response = qtype == kTypeAAAA
                        ? cloak::build_block_aaaa_response(query, msg)
                        : cloak::build_block_a_response(query, msg);
                    std::cout << "uncloak " << qname
                              << "  via " << result.hit.rule;
                    log_chain(std::cout, result.chain);
                    std::cout << std::endl;
                    log_record(cloak::LogAction::Uncloak, qname, qtype,
                               result.hit.rule, result.chain, upstream_str);
                    break;
                case cloak::UncloakStatus::Aborted:
                    response = cloak::build_servfail_response(query, msg);
                    std::cout << "servfail " << qname
                              << "  (" << result.abort_reason << ")"
                              << std::endl;
                    log_record(cloak::LogAction::ServFail, qname, qtype,
                               result.abort_reason, {}, upstream_str);
                    break;
                case cloak::UncloakStatus::Clean:
                    try_cache_insert();
                    response = std::move(upstream_resp);
                    std::cout << "forward " << qname;
                    if (result.chain.size() > 1) log_chain(std::cout, result.chain);
                    std::cout << std::endl;
                    log_record(cloak::LogAction::Allow, qname, qtype,
                               "", result.chain, upstream_str);
                    break;
                }
            } else {
                try_cache_insert();
                response = std::move(upstream_resp);
                std::cout << "forward " << qname << "  qtype=" << qtype << std::endl;
                log_record(cloak::LogAction::Allow, qname, qtype,
                           "", {}, upstream_str);
            }
        } catch (const std::exception& e) {
            response = cloak::build_servfail_response(query, msg);
            std::cout << "servfail " << qname << "  (" << e.what() << ")" << std::endl;
            log_record(cloak::LogAction::ServFail, qname, qtype, e.what());
        }

        co_await sock.async_send_to(
            asio::buffer(response), from, use_awaitable);
    } catch (const cloak::ParseError& e) {
        std::cout << "drop malformed from " << from
                  << ": " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cout << "handler error: " << e.what() << std::endl;
    }
}

// Atomic shared-pointer holder used for hot reload. main() builds
// each Blocklist, atomically stores it here, and serve() reads a
// snapshot per query.
using BlocklistPtr = std::shared_ptr<const cloak::Blocklist>;
std::atomic<BlocklistPtr> g_blocklist;

awaitable<void> serve(udp::socket& sock,
                      cloak::UpstreamForwarder& fwd,
                      cloak::CnameUncloaker& uncloaker,
                      cloak::DnsCache& cache,
                      cloak::QueryLogger& logger) {
    auto executor = co_await asio::this_coro::executor;
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        size_t n = 0;
        try {
            n = co_await sock.async_receive_from(
                asio::buffer(buf), from, use_awaitable);
        } catch (const std::system_error& e) {
            // On Windows, sending a UDP response to a client whose port
            // already closed produces an ICMP port-unreachable, which the
            // OS surfaces as WSAECONNRESET on the *next* recvfrom. The
            // listening socket is still healthy — keep going. We disable
            // SIO_UDP_CONNRESET on bind (see main()), so this is a safety
            // net for any other transient errno. asio::detached otherwise
            // silently swallows the throw and stops the receive loop,
            // wedging the resolver while leaving the process alive.
            std::cerr << "recv error (continuing): " << e.what() << std::endl;
            continue;
        }
        std::vector<std::byte> copy(buf.data(), buf.data() + n);
        auto snapshot = g_blocklist.load();
        co_spawn(executor,
                 handle(std::move(copy), from, sock, std::move(snapshot),
                        fwd, uncloaker, cache, logger),
                 detached);
    }
}

namespace {

std::vector<asio::ip::udp::endpoint>
resolve_servers(const std::vector<cloak::Endpoint>& list) {
    std::vector<asio::ip::udp::endpoint> out;
    out.reserve(list.size());
    for (const auto& ep : list) {
        out.emplace_back(make_address(ep.host), ep.port);
    }
    return out;
}

cloak::Config load_or_default(int argc, char** argv) {
    if (argc > 1) {
        const std::filesystem::path p{argv[1]};
        const auto ext = p.extension().string();
        if (ext == ".toml") return cloak::load_config(p);
        // Legacy mode: argv[1] is a bare blocklist file path.
        cloak::Config c;
        c.blocklist.sources = {p};
        return c;
    }
    if (auto discovered = cloak::find_config_path(argc > 0 ? argv[0] : "")) {
        std::cout << "config: " << discovered->string() << std::endl;
        return cloak::load_config(*discovered);
    }
    return cloak::Config{};
}

} // namespace

namespace {

cloak::Blocklist build_blocklist(const cloak::Config& cfg) {
    cloak::Blocklist out;
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

} // namespace

int main(int argc, char** argv) {
    try {
        const auto cfg = load_or_default(argc, argv);

        g_blocklist.store(std::make_shared<cloak::Blocklist>(build_blocklist(cfg)));

        asio::io_context ctx;

        cloak::UpstreamForwarder forwarder{ctx,
            cloak::UpstreamForwarder::Config{
                .servers            = resolve_servers(cfg.upstream.servers),
                .timeout            = cfg.upstream.timeout,
                .retries_on_primary = cfg.upstream.retries_on_primary,
                .padding_block_size = cfg.upstream.padding_block_size,
            }};

        // Uncloaker holds a `const Blocklist&` to its initial snapshot.
        // Hot reload swaps `g_blocklist`, but the uncloaker's reference
        // must remain valid — so we pin the initial snapshot here for
        // the uncloaker's lifetime. Without this pin, the first SIGHUP
        // would drop the original Blocklist's refcount to zero and the
        // uncloaker would dangle (use-after-free).
        const auto uncloak_blocklist_pin = g_blocklist.load();
        cloak::CnameUncloaker uncloaker{forwarder, *uncloak_blocklist_pin,
            cloak::CnameUncloaker::Config{.max_depth = cfg.uncloak.max_depth}};

        cloak::DnsCache cache{cloak::DnsCache::Config{
            .jitter_max     = cfg.cache.jitter_max,
            .sweep_interval = cfg.cache.sweep_interval,
            .max_entries    = cfg.cache.max_entries,
        }};

        cloak::QueryLogger logger{cloak::QueryLogger::Config{
            .path           = cfg.logging.path,
            .async          = cfg.logging.async,
            .queue_size     = cfg.logging.queue_size,
            .max_size_bytes = cfg.logging.max_size_bytes,
            .redact_client  = cfg.logging.redact_client,
        }};

        udp::socket sock{ctx,
            udp::endpoint{make_address(cfg.server.listen_addr), cfg.server.listen_port}};

#if defined(_WIN32)
        // SIO_UDP_CONNRESET: when our sendto() reaches a client port that
        // has already closed, Windows bounces an ICMP port-unreachable
        // and surfaces it as WSAECONNRESET on the *next* recvfrom. With
        // this option set to FALSE the OS swallows the bounce instead.
        // Without this, the receive loop in serve() throws on the next
        // packet and asio::detached silently swallows it — server stays
        // alive but stops answering. Standard fix for any UDP server on
        // Windows; see KB 263823.
        {
            DWORD bytes_returned = 0;
            BOOL conn_reset = FALSE;
            constexpr DWORD kSioUdpConnReset = _WSAIOW(IOC_VENDOR, 12);
            if (::WSAIoctl(sock.native_handle(), kSioUdpConnReset,
                           &conn_reset, sizeof(conn_reset),
                           nullptr, 0, &bytes_returned,
                           nullptr, nullptr) == SOCKET_ERROR) {
                std::cerr << "warn: WSAIoctl(SIO_UDP_CONNRESET) failed: "
                          << ::WSAGetLastError() << std::endl;
            }
        }
#endif

        // Drop privileges AFTER binding the port — bind(53) needs
        // CAP_NET_BIND_SERVICE / root, but the hot path shouldn't.
        // No-op on Windows and when run_as_user is empty.
        cloak::drop_privileges(cfg.service.run_as_user, cfg.service.run_as_group);

        std::cout << "cloakdns listening on "
                  << cfg.server.listen_addr << ":" << cfg.server.listen_port << std::endl;
        std::cout << "upstream:";
        for (const auto& ep : cfg.upstream.servers)
            std::cout << " " << ep.host << ":" << ep.port;
        std::cout << "  (timeout " << cfg.upstream.timeout.count() << "ms)" << std::endl;
        std::cout << "cname uncloaking: max depth " << cfg.uncloak.max_depth << std::endl;
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
        stop_signals.async_wait([&](const std::error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

        // Hot reload: SIGHUP on Linux, SIGBREAK on Windows (Ctrl+Break).
        // Re-loads block + allow lists; cache is intentionally preserved
        // so legitimate queries don't re-traverse upstream after reload.
#if defined(_WIN32)
        constexpr int kReloadSignal = SIGBREAK;
        const char* kReloadName = "SIGBREAK";
#else
        constexpr int kReloadSignal = SIGHUP;
        const char* kReloadName = "SIGHUP";
#endif
        asio::signal_set reload_signals{ctx, kReloadSignal};
        std::function<void(const std::error_code&, int)> on_reload;
        on_reload = [&](const std::error_code& ec, int) {
            if (ec) return;   // cancelled (e.g. shutdown)
            try {
                std::cout << "\nreload (" << kReloadName << "): rebuilding blocklist" << std::endl;
                auto fresh = std::make_shared<cloak::Blocklist>(build_blocklist(cfg));
                g_blocklist.store(std::move(fresh));
            } catch (const std::exception& e) {
                std::cerr << "reload failed (" << e.what()
                          << ") — keeping previous blocklist" << std::endl;
            }
            // Re-arm.
            reload_signals.async_wait(on_reload);
        };
        reload_signals.async_wait(on_reload);

        co_spawn(ctx, serve(sock, forwarder, uncloaker, cache, logger), detached);
        ctx.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
