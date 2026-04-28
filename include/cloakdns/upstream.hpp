#pragma once

#include "cloakdns/tls.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace cloak {

// Internal: result of one single-shot upstream exchange. Used to plumb
// ECH state from detail::dot_try_once / detail::doh_try_once back to
// the forwarder so it can attach status to ForwardResult.
struct UpstreamReply {
    std::vector<std::byte> bytes;
    tls::EchStatus         ech_status{tls::EchStatus::NotTried};
};

// Result of a successful upstream forward. `upstream` is pre-stringified
// ("1.1.1.1:53" / "1.1.1.1:853") so the query log can record which server
// answered without having to know the protocol.
struct ForwardResult {
    std::vector<std::byte> response;
    std::string            upstream;
    // ECH state on the answering connection. NotTried for UDP and for
    // non-ECH builds; otherwise reflects SSL_ech_get1_status.
    tls::EchStatus         ech_status{tls::EchStatus::NotTried};
};

class UpstreamForwarder {
public:
    enum class Protocol { Udp, Dot, Doh };

    struct Config {
        Protocol protocol{Protocol::Udp};

        // UDP path uses `servers`; DoT/DoH use `tcp_servers`. The other
        // vector should be left empty for the active protocol.
        std::vector<asio::ip::udp::endpoint> servers;
        std::vector<asio::ip::tcp::endpoint> tcp_servers;

        // SNI to send on TLS handshakes (DoT/DoH). Required when servers
        // are reached by IP literal (e.g. "1.1.1.1:853") so the cert SAN
        // check has a hostname to validate against.
        std::string servername;

        // RFC 7469 SPKI pins ("sha256/<base64>"). Empty = chain validation
        // only. Pinning is additive on top of chain validation, never a
        // replacement.
        std::vector<std::string> spki_pins;

        // DoH request path. Standard is "/dns-query"; some operators
        // expose alternate paths. Ignored unless protocol == Doh.
        std::string doh_path{"/dns-query"};

        // Encrypted Client Hello (RFC 9849). When ech_config_list is
        // non-empty AND the build has CLOAKDNS_HAVE_ECH, the upstream
        // TLS handshake runs ECH; otherwise standard SNI.
        std::string            ech_outer_servername;
        std::vector<std::byte> ech_config_list;

        std::chrono::milliseconds timeout{2000};
        int                       retries_on_primary{1};
        std::size_t               padding_block_size{128};   // 0 disables
    };

    UpstreamForwarder(asio::io_context& ctx, Config cfg);
    ~UpstreamForwarder();

    UpstreamForwarder(const UpstreamForwarder&) = delete;
    UpstreamForwarder& operator=(const UpstreamForwarder&) = delete;

    asio::awaitable<ForwardResult>
    forward_with_source(std::span<const std::byte> client_query);

    asio::awaitable<std::vector<std::byte>>
    forward(std::span<const std::byte> client_query);

    Protocol protocol() const noexcept { return cfg_.protocol; }

    // Live TLS context, or nullptr for protocol == Udp. SIGHUP uses this
    // to swap a fresh ECHConfigList in without rebuilding the forwarder.
    tls::Context* tls_context() noexcept { return tls_ctx_.get(); }

private:
    asio::awaitable<std::optional<std::vector<std::byte>>>
    try_once_udp(std::span<const std::byte> outbound,
                 const asio::ip::udp::endpoint& server,
                 std::uint16_t our_id,
                 std::span<const std::byte> client_query);

    asio::io_context& ctx_;
    Config cfg_;
    std::mt19937 rng_;

    // TLS context lives for the forwarder's lifetime. Allocated only when
    // protocol != Udp. Forward-declared to keep OpenSSL headers out of
    // this header — destructor is out-of-line in upstream.cpp.
    std::unique_ptr<tls::ContextConfig> tls_cfg_;
    std::unique_ptr<tls::Context>       tls_ctx_;
};

} // namespace cloak
