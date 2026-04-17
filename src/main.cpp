#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>

#include <array>
#include <cstddef>
#include <exception>
#include <iostream>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;

awaitable<void> serve(udp::socket sock) {
    std::array<std::byte, 4096> buf;
    for (;;) {
        udp::endpoint from;
        auto n = co_await sock.async_receive_from(
            asio::buffer(buf), from, use_awaitable);
        std::cout << "rx " << n << " bytes from " << from << std::endl;
        co_await sock.async_send_to(
            asio::buffer(buf.data(), n), from, use_awaitable);
    }
}

int main() {
    try {
        asio::io_context ctx;
        udp::socket sock{ctx,
            udp::endpoint{make_address("127.0.0.1"), 5354}};

        std::cout << "cloakdns listening on 127.0.0.1:5354" << std::endl;

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
