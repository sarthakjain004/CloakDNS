#pragma once

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <random>
#include <span>
#include <vector>

namespace cloak {

class UpstreamForwarder {
public:
    struct Config {
        std::vector<asio::ip::udp::endpoint> servers;
        std::chrono::milliseconds timeout{2000};
        int retries_on_primary{1};
    };

    UpstreamForwarder(asio::io_context& ctx, Config cfg);

    // Forward the client's query bytes upstream. On success returns
    // the upstream response with the ID rewritten back to the client's
    // original ID, ready to sendto() the client. Throws std::runtime_error
    // on total failure (all upstreams exhausted).
    asio::awaitable<std::vector<std::byte>>
    forward(std::span<const std::byte> client_query);

private:
    asio::awaitable<std::optional<std::vector<std::byte>>>
    try_once(std::span<const std::byte> outbound,
             const asio::ip::udp::endpoint& server,
             uint16_t our_id);

    asio::io_context& ctx_;
    Config cfg_;
    std::mt19937 rng_;
};

} // namespace cloak
