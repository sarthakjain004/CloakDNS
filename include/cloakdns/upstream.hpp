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
#include <string>
#include <vector>

namespace cloak {

struct ForwardResult {
    std::vector<std::byte>          response;
    asio::ip::udp::endpoint         answered_by;   // which server replied
};

class UpstreamForwarder {
public:
    struct Config {
        std::vector<asio::ip::udp::endpoint> servers;
        std::chrono::milliseconds timeout{2000};
        int retries_on_primary{1};
        size_t padding_block_size{128};    // kPadBlockDefault; 0 = disabled
    };

    UpstreamForwarder(asio::io_context& ctx, Config cfg);

    // Forward the client's query bytes upstream. On success returns
    // the upstream response (ID rewritten back to the client's original
    // ID, ready to sendto()) and the endpoint that answered. Throws
    // std::runtime_error on total failure (all upstreams exhausted).
    asio::awaitable<ForwardResult>
    forward_with_source(std::span<const std::byte> client_query);

    // Convenience wrapper for callers that don't care about the source.
    asio::awaitable<std::vector<std::byte>>
    forward(std::span<const std::byte> client_query);

private:
    asio::awaitable<std::optional<std::vector<std::byte>>>
    try_once(std::span<const std::byte> outbound,
             const asio::ip::udp::endpoint& server,
             uint16_t our_id,
             std::span<const std::byte> client_query);

    asio::io_context& ctx_;
    Config cfg_;
    std::mt19937 rng_;
};

} // namespace cloak
