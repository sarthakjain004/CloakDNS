#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"

#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <iostream>
#include <span>
#include <string_view>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;

namespace {

constexpr std::string_view kBlockedDomain = "ads.test";
constexpr uint16_t kTypeA = 1;

bool should_block(const cloak::DnsMessage& msg) {
    return msg.questions.size() == 1
        && msg.questions[0].qname == kBlockedDomain
        && msg.questions[0].qtype == kTypeA;
}

} // namespace

awaitable<void> serve(udp::socket sock) {
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        const auto n = co_await sock.async_receive_from(
            asio::buffer(buf), from, use_awaitable);

        const auto query = std::span<const std::byte>{buf.data(), n};

        try {
            const auto msg = cloak::parse(query);
            const auto response = should_block(msg)
                ? cloak::build_block_a_response(query, msg)
                : cloak::build_refused_response(query, msg);

            std::cout << (should_block(msg) ? "block " : "refuse ")
                      << (msg.questions.empty() ? "<no-question>"
                                                : msg.questions[0].qname)
                      << " from " << from << std::endl;

            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
        } catch (const cloak::ParseError& e) {
            std::cout << "drop malformed from " << from
                      << ": " << e.what() << std::endl;
        }
    }
}

int main() {
    try {
        asio::io_context ctx;
        udp::socket sock{ctx,
            udp::endpoint{make_address("127.0.0.1"), 5354}};

        std::cout << "cloakdns listening on 127.0.0.1:5354" << std::endl;
        std::cout << "blocking: " << kBlockedDomain << std::endl;

        asio::signal_set signals{ctx, SIGINT, SIGTERM};
        signals.async_wait([&](const std::error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

        co_spawn(ctx, serve(std::move(sock)), detached);
        ctx.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
