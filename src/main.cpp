#include "cloakdns/blocklist.hpp"
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
#include <filesystem>
#include <iostream>
#include <span>
#include <string>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;

namespace {

constexpr uint16_t kTypeA = 1;

cloak::MatchResult decide(const cloak::DnsMessage& msg,
                          const cloak::Blocklist& bl) {
    if (msg.questions.size() != 1 || msg.questions[0].qtype != kTypeA)
        return {};
    return bl.match(msg.questions[0].qname);
}

} // namespace

awaitable<void> serve(udp::socket sock, const cloak::Blocklist& blocklist) {
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        const auto n = co_await sock.async_receive_from(
            asio::buffer(buf), from, use_awaitable);

        const auto query = std::span<const std::byte>{buf.data(), n};

        try {
            const auto msg = cloak::parse(query);
            const auto hit = decide(msg, blocklist);

            const auto response = hit.blocked
                ? cloak::build_block_a_response(query, msg)
                : cloak::build_refused_response(query, msg);

            const auto& qname = msg.questions.empty()
                ? std::string{"<no-question>"}
                : msg.questions[0].qname;
            if (hit.blocked) {
                std::cout << "block  " << qname
                          << "  via " << hit.rule << std::endl;
            } else {
                std::cout << "refuse " << qname << std::endl;
            }

            co_await sock.async_send_to(
                asio::buffer(response), from, use_awaitable);
        } catch (const cloak::ParseError& e) {
            std::cout << "drop malformed from " << from
                      << ": " << e.what() << std::endl;
        }
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
        udp::socket sock{ctx,
            udp::endpoint{make_address("127.0.0.1"), 5354}};

        std::cout << "cloakdns listening on 127.0.0.1:5354" << std::endl;

        asio::signal_set signals{ctx, SIGINT, SIGTERM};
        signals.async_wait([&](const std::error_code&, int) {
            std::cout << "\nshutting down" << std::endl;
            ctx.stop();
        });

        co_spawn(ctx, serve(std::move(sock), std::ref(blocklist)), detached);
        ctx.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << std::endl;
        return 1;
    }
}
