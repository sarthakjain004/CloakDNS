#pragma once

#include "cloakdns/tls.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cloak::resolver {

// Result of one Adapter try_once exchange.
struct UpstreamReply {
    std::vector<std::byte> bytes;
    tls::EchStatus         ech_status{tls::EchStatus::NotTried};
};

// Returned from forward_with_source(). Carries the answering Adapter's
// pre-stringified label so the Query Logger can record which server
// answered without knowing the protocol.
struct ForwardResult {
    std::vector<std::byte> response;
    std::string            upstream;
    tls::EchStatus         ech_status{tls::EchStatus::NotTried};
};

// One protocol-specific single-shot exchange. Owns its own tls::Context
// when the protocol needs one (DoT, DoH); UDP has none. Adapters never
// see retry, ID rewrite, or EDNS0 padding — the Resolver applies those
// once before delegating.
//
// Implementations:
//   - UDP  — udp_adapter.cpp
//   - DoT  — dot_adapter.cpp
//   - DoH  — doh_adapter.cpp
//   - Fake — tests/fakes/fake_adapter.hpp (retry/match-id unit tests)
class Adapter {
public:
    virtual ~Adapter() = default;

    // Send `outbound` once; await reply or `nullopt` on transport /
    // framing / TLS failure. The Resolver picks the next Adapter on
    // nullopt.
    virtual asio::awaitable<std::optional<UpstreamReply>>
        try_once(std::span<const std::byte> outbound,
                 std::chrono::milliseconds  timeout) = 0;

    // Pre-stringified endpoint, e.g. "1.1.1.1:53" / "1.1.1.1:853".
    virtual std::string_view label() const noexcept = 0;

    // Returns nullptr for UDP. The SIGHUP path reaches in here via
    // Control to swap ECHConfigList atomically. The pointer is valid
    // for the lifetime of *this Adapter — which equals the Resolver's
    // lifetime — so it's safe to dereference under any code path that
    // already holds a Resolver& or Control. Do not store across a
    // suspension point that could outlive the Resolver.
    virtual tls::Context* tls_context() noexcept { return nullptr; }
};

using AdapterPtr = std::unique_ptr<Adapter>;

// Forward decl — Control is the secondary surface for SIGHUP / stats.
class Control;

class Resolver {
public:
    struct Config {
        std::chrono::milliseconds timeout{2000};
        // Extra attempts on the primary (index 0) Adapter before
        // falling through to fallbacks. Fallbacks get one attempt each.
        int                       retries_on_primary{1};
        // EDNS0 padding block size per RFC 8467; 0 disables. Padding
        // is applied once before the first try_once and reused across
        // all retries / fallbacks so all upstreams see identical wire
        // bytes.
        std::size_t               padding_block_size{128};
    };

    // Adapters are walked primary → fallback in vector order. Empty
    // vector throws invalid_argument.
    //
    // Thread-safety: the io_context must be single-threaded. forward()
    // is not safe to call concurrently — the internal RNG used for
    // RFC 5452 transaction ID entropy is std::mt19937, not thread-safe.
    // Asio coroutines on a single-threaded io_context are interleaved,
    // never parallel, so this is safe under the standard run pattern.
    Resolver(asio::io_context& ctx,
             Config cfg,
             std::vector<AdapterPtr> adapters);
    ~Resolver();

    Resolver(const Resolver&) = delete;
    Resolver& operator=(const Resolver&) = delete;

    // Primary surface. Pads the query, rewrites the transaction ID,
    // tries each Adapter (with retries on the primary), validates each
    // reply against RFC 5452 (ID match + question echo), restores the
    // client's original transaction ID, returns the response bytes.
    // Throws runtime_error if every Adapter is exhausted.
    asio::awaitable<std::vector<std::byte>>
        forward(std::span<const std::byte> client_query);

    // Same body as forward(); also reports the answering Adapter's
    // label and ECH status for the Query Logger. Use this when you
    // need to record which upstream answered.
    asio::awaitable<ForwardResult>
        forward_with_source(std::span<const std::byte> client_query);

    // Opt-in handle for SIGHUP, /stats, Query Logger introspection.
    // Cheap (16-byte non-owning view) — take a fresh one per call site.
    Control control() noexcept;

private:
    friend class Control;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Secondary surface. Bifurcation point: Uncloaker / Server hot loop
// hold a Resolver&; SIGHUP / stats hold a Control. Exposing only what
// each caller actually needs is the architectural property — Uncloaker
// cannot reach tls::Context* from the type it imports.
class Control {
public:
    // Atomic per-Adapter ECHConfigList swap. Iterates Adapters; for
    // each one whose tls_context() returns non-null, atomically stores
    // the new snapshot. Lock-free reads on the hot path; this is the
    // only writer.
    //
    // Empty `ech_config_list` disables ECH on every Adapter that has TLS.
    void swap_ech_config(std::span<const std::byte> ech_config_list,
                         std::string outer_servername,
                         std::chrono::system_clock::time_point fetched_at);

    struct AdapterStats {
        std::string label;
        std::size_t queries_answered{0};
        std::size_t timeouts{0};
        // nullopt when the Adapter has no TLS context (UDP) or has
        // never had ECH bytes installed.
        std::optional<std::chrono::system_clock::time_point> ech_fetched_at;
    };
    std::vector<AdapterStats> stats() const;

private:
    friend class Resolver;
    explicit Control(Resolver* r) noexcept : r_{r} {}
    Resolver* r_;
};

// ──────────────────────────────────────────────────────────────────────
// Adapter factories. Each owns its own tls::Context (DoT/DoH) or none
// (UDP). Constructor failure throws.

struct UdpAdapterConfig {
    asio::ip::udp::endpoint server;
    std::string             label;   // pre-stringified, e.g. "1.1.1.1:53"
};
AdapterPtr make_udp_adapter(asio::io_context&, UdpAdapterConfig);

struct DotAdapterConfig {
    asio::ip::tcp::endpoint  server;
    std::string              servername;        // SNI / cert SAN match
    std::vector<std::string> spki_pins;         // RFC 7469 sha256/<b64>
    std::string              ca_file;           // empty → system trust
    std::string              ech_outer_servername;
    std::vector<std::byte>   ech_config_list;
    bool                     ech_grease{false};
    std::string              label;             // "1.1.1.1:853"
};
AdapterPtr make_dot_adapter(asio::io_context&, DotAdapterConfig);

struct DohAdapterConfig {
    asio::ip::tcp::endpoint  server;
    std::string              servername;        // SNI + Host header
    std::string              doh_path{"/dns-query"};
    std::vector<std::string> spki_pins;
    std::string              ca_file;
    std::string              ech_outer_servername;
    std::vector<std::byte>   ech_config_list;
    bool                     ech_grease{false};
    std::string              label;
};
AdapterPtr make_doh_adapter(asio::io_context&, DohAdapterConfig);

} // namespace cloak::resolver
