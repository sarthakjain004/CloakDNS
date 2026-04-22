#include "cloakdns/blocklist.hpp"
#include "cloakdns/cache.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/uncloaker.hpp"
#include "cloakdns/upstream.hpp"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/this_coro.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <iostream>
#include <span>
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

constexpr uint16_t kTypeA = 1;

cloak::MatchResult decide(const cloak::DnsMessage& msg,
                          const cloak::Blocklist& bl) {
    if (msg.questions.size() != 1 || msg.questions[0].qtype != kTypeA)
        return {};
    return bl.match(msg.questions[0].qname);
}

void log_chain(std::ostream& os, const std::vector<std::string>& chain) {
    os << " (chain:";
    for (const auto& h : chain) os << ' ' << h;
    os << ')';
}

} // namespace

awaitable<void> handle(std::vector<std::byte> query_buf,
                       udp::endpoint from,
                       udp::socket& sock,
                       const cloak::Blocklist& bl,
                       cloak::UpstreamForwarder& fwd,
                       cloak::CnameUncloaker& uncloaker,
                       cloak::DnsCache& cache) {
    const auto query = std::span<const std::byte>{query_buf};
    try {
        const auto msg = cloak::parse(query);
        const auto hit = decide(msg, bl);
        const auto& qname = msg.questions.empty()
            ? std::string{"<no-question>"}
            : msg.questions[0].qname;

        std::vector<std::byte> response;
        if (hit.blocked) {
            response = cloak::build_block_a_response(query, msg);
            std::cout << "block   " << qname << "  via " << hit.rule << std::endl;
        } else if (msg.questions.size() == 1 &&
                   msg.questions[0].qtype == kTypeA) {
            if (auto key = cloak::make_cache_key(msg)) {
                if (auto cached = cache.lookup(*key, msg.header.id)) {
                    co_await cloak::apply_jitter(cache.jitter_max());
                    co_await sock.async_send_to(
                        asio::buffer(*cached), from, use_awaitable);
                    std::cout << "cached  " << qname << std::endl;
                    co_return;
                }
            }
            try {
                auto upstream_resp = co_await fwd.forward(query);
                auto result = co_await uncloaker.uncloak(qname, upstream_resp);

                switch (result.status) {
                case cloak::UncloakStatus::Blocked:
                    response = cloak::build_block_a_response(query, msg);
                    std::cout << "uncloak " << qname
                              << "  via " << result.hit.rule;
                    log_chain(std::cout, result.chain);
                    std::cout << std::endl;
                    break;
                case cloak::UncloakStatus::Aborted:
                    response = cloak::build_servfail_response(query, msg);
                    std::cout << "servfail " << qname
                              << "  (" << result.abort_reason << ")"
                              << std::endl;
                    break;
                case cloak::UncloakStatus::Clean:
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
                    response = std::move(upstream_resp);
                    std::cout << "forward " << qname;
                    if (result.chain.size() > 1) log_chain(std::cout, result.chain);
                    std::cout << std::endl;
                    break;
                }
            } catch (const std::exception& e) {
                response = cloak::build_servfail_response(query, msg);
                std::cout << "servfail " << qname << "  (" << e.what() << ")" << std::endl;
            }
        } else {
            response = cloak::build_refused_response(query, msg);
            std::cout << "refuse  " << qname << std::endl;
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

awaitable<void> serve(udp::socket& sock,
                      const cloak::Blocklist& bl,
                      cloak::UpstreamForwarder& fwd,
                      cloak::CnameUncloaker& uncloaker,
                      cloak::DnsCache& cache) {
    auto executor = co_await asio::this_coro::executor;
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        const auto n = co_await sock.async_receive_from(
            asio::buffer(buf), from, use_awaitable);
        std::vector<std::byte> copy(buf.data(), buf.data() + n);
        co_spawn(executor,
                 handle(std::move(copy), from, sock, bl, fwd, uncloaker, cache),
                 detached);
    }
}

int main(int argc, char** argv) {
    try {
        const std::filesystem::path blocklist_path =
            argc > 1 ? std::filesystem::path{argv[1]}
                     : std::filesystem::path{"blocklists/tier1.txt"};

        cloak::Blocklist blocklist;
        const auto n = blocklist.load_hosts_file(blocklist_path);
        std::cout << "loaded " << n << " rules from "
                  << blocklist_path << std::endl;

        asio::io_context ctx;

        cloak::UpstreamForwarder forwarder{ctx,
            cloak::UpstreamForwarder::Config{
                .servers = {
                    {make_address("1.1.1.1"), 53},
                    {make_address("9.9.9.9"), 53},
                },
                .timeout = 2000ms,
                .retries_on_primary = 1,
            }};

        cloak::CnameUncloaker uncloaker{forwarder, blocklist};
        cloak::DnsCache cache;

        udp::socket sock{ctx,
            udp::endpoint{make_address("127.0.0.1"), 5354}};

        std::cout << "cloakdns listening on 127.0.0.1:5354" << std::endl;
        std::cout << "upstream: 1.1.1.1, 9.9.9.9  (timeout 2000ms)" << std::endl;
        std::cout << "cname uncloaking: max depth 8" << std::endl;
        std::cout << "cache: 50000 entries, jitter 0-5ms on hit, sweep 30s" << std::endl;

        asio::signal_set signals{ctx, SIGINT, SIGTERM};
        signals.async_wait([&](const std::error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

        co_spawn(ctx, serve(sock, blocklist, forwarder, uncloaker, cache), detached);
        ctx.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
