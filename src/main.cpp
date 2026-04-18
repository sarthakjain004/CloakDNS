#include "cloakdns/blocklist.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
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

} // namespace

awaitable<void> handle(std::vector<std::byte> query_buf,
                       udp::endpoint from,
                       udp::socket& sock,
                       const cloak::Blocklist& bl,
                       cloak::UpstreamForwarder& fwd) {
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
            try {
                response = co_await fwd.forward(query);
                std::cout << "forward " << qname << std::endl;
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
                      cloak::UpstreamForwarder& fwd) {
    auto executor = co_await asio::this_coro::executor;
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        const auto n = co_await sock.async_receive_from(
            asio::buffer(buf), from, use_awaitable);
        std::vector<std::byte> copy(buf.data(), buf.data() + n);
        co_spawn(executor,
                 handle(std::move(copy), from, sock, bl, fwd),
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

        udp::socket sock{ctx,
            udp::endpoint{make_address("127.0.0.1"), 5354}};

        std::cout << "cloakdns listening on 127.0.0.1:5354" << std::endl;
        std::cout << "upstream: 1.1.1.1, 9.9.9.9  (timeout 2000ms)" << std::endl;

        asio::signal_set signals{ctx, SIGINT, SIGTERM};
        signals.async_wait([&](const std::error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

        co_spawn(ctx, serve(sock, blocklist, forwarder), detached);
        ctx.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
