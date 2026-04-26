#include "cloakdns/upstream.hpp"

#include "cloakdns/dns_parser.hpp"
#include "cloakdns/edns_padding.hpp"

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
                            uint16_t our_id,
                            std::span<const std::byte> client_query) {
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

        // RFC 5452 §6: validate the question section echoes our request.
        // We have ID, source-IP, and ephemeral-port matching already; this
        // closes one more poisoning vector at near-zero cost.
        const std::span<const std::byte> reply{buf.data(), n};
        try {
            const auto req_msg = parse(client_query);
            const auto rep_msg = parse(reply);
            if (req_msg.questions.size() != rep_msg.questions.size())
                co_return std::nullopt;
            for (size_t i = 0; i < req_msg.questions.size(); ++i) {
                const auto& q = req_msg.questions[i];
                const auto& r = rep_msg.questions[i];
                if (q.qname  != r.qname)  co_return std::nullopt;
                if (q.qtype  != r.qtype)  co_return std::nullopt;
                if (q.qclass != r.qclass) co_return std::nullopt;
            }
        } catch (const ParseError&) {
            co_return std::nullopt;
        }

        co_return std::vector<std::byte>(buf.data(), buf.data() + n);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }
}

asio::awaitable<ForwardResult>
UpstreamForwarder::forward_with_source(std::span<const std::byte> client_query) {
    if (client_query.size() < 12)
        throw std::runtime_error{"upstream: query too short"};

    const uint16_t client_id = read_u16_be(client_query, 0);

    std::uniform_int_distribution<uint32_t> dist{0, 0xffff};
    const uint16_t our_id = static_cast<uint16_t>(dist(rng_));

    std::vector<std::byte> outbound;
    if (cfg_.padding_block_size == 0) {
        outbound.assign(client_query.begin(), client_query.end());
    } else {
        outbound = pad_query(client_query, cfg_.padding_block_size);
    }
    write_u16_be(std::span<std::byte>{outbound}, 0, our_id);

    bool is_primary = true;
    for (const auto& server : cfg_.servers) {
        const int attempts = is_primary ? (1 + cfg_.retries_on_primary) : 1;
        is_primary = false;
        for (int a = 0; a < attempts; ++a) {
            auto resp = co_await try_once(outbound, server, our_id, client_query);
            if (resp) {
                write_u16_be(std::span<std::byte>{*resp}, 0, client_id);
                co_return ForwardResult{
                    .response    = std::move(*resp),
                    .answered_by = server,
                };
            }
        }
    }
    throw std::runtime_error{"upstream: all servers exhausted"};
}

asio::awaitable<std::vector<std::byte>>
UpstreamForwarder::forward(std::span<const std::byte> client_query) {
    auto r = co_await forward_with_source(client_query);
    co_return std::move(r.response);
}

} // namespace cloak
