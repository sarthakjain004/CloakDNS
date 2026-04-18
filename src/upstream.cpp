#include "cloakdns/upstream.hpp"

#include <asio/buffer.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <system_error>

namespace cloak {
namespace {

constexpr size_t kMaxResponse = 4096;

uint16_t read_u16_be(std::span<const std::byte> b, size_t off) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(std::to_integer<uint8_t>(b[off])) << 8) |
         static_cast<uint16_t>(std::to_integer<uint8_t>(b[off + 1])));
}

void write_u16_be(std::span<std::byte> b, size_t off, uint16_t v) {
    b[off]     = std::byte{static_cast<uint8_t>((v >> 8) & 0xff)};
    b[off + 1] = std::byte{static_cast<uint8_t>(v & 0xff)};
}

} // namespace

UpstreamForwarder::UpstreamForwarder(asio::io_context& ctx, Config cfg)
    : ctx_(ctx), cfg_(std::move(cfg)), rng_(std::random_device{}()) {
    if (cfg_.servers.empty())
        throw std::invalid_argument{"UpstreamForwarder: no servers"};
}

asio::awaitable<std::optional<std::vector<std::byte>>>
UpstreamForwarder::try_once(std::span<const std::byte> outbound,
                            const asio::ip::udp::endpoint& server,
                            uint16_t our_id) {
    auto s = std::make_shared<asio::ip::udp::socket>(ctx_);
    s->open(asio::ip::udp::v4());
    s->bind(asio::ip::udp::endpoint{asio::ip::udp::v4(), 0});

    co_await s->async_send_to(
        asio::buffer(outbound.data(), outbound.size()),
        server, asio::use_awaitable);

    asio::steady_timer timer{ctx_};
    timer.expires_after(cfg_.timeout);
    timer.async_wait([s](const std::error_code& ec) {
        if (!ec) {
            std::error_code ignore;
            s->cancel(ignore);
        }
    });

    std::array<std::byte, kMaxResponse> buf;
    asio::ip::udp::endpoint from;

    try {
        const auto n = co_await s->async_receive_from(
            asio::buffer(buf.data(), buf.size()), from,
            asio::use_awaitable);
        timer.cancel();
        if (from != server) co_return std::nullopt;
        if (n < 2) co_return std::nullopt;
        const uint16_t resp_id = read_u16_be(
            std::span<const std::byte>{buf.data(), n}, 0);
        if (resp_id != our_id) co_return std::nullopt;
        co_return std::vector<std::byte>(buf.data(), buf.data() + n);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }
}

asio::awaitable<std::vector<std::byte>>
UpstreamForwarder::forward(std::span<const std::byte> client_query) {
    if (client_query.size() < 12)
        throw std::runtime_error{"upstream: query too short"};

    const uint16_t client_id = read_u16_be(client_query, 0);

    std::uniform_int_distribution<uint32_t> dist{0, 0xffff};
    const uint16_t our_id = static_cast<uint16_t>(dist(rng_));

    std::vector<std::byte> outbound(client_query.begin(), client_query.end());
    write_u16_be(std::span<std::byte>{outbound}, 0, our_id);

    bool is_primary = true;
    for (const auto& server : cfg_.servers) {
        const int attempts = is_primary ? (1 + cfg_.retries_on_primary) : 1;
        is_primary = false;
        for (int a = 0; a < attempts; ++a) {
            auto resp = co_await try_once(outbound, server, our_id);
            if (resp) {
                write_u16_be(std::span<std::byte>{*resp}, 0, client_id);
                co_return std::move(*resp);
            }
        }
    }
    throw std::runtime_error{"upstream: all servers exhausted"};
}

} // namespace cloak
