#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace cloak {

struct ServerConfig {
    std::string listen_addr{"127.0.0.1"};
    uint16_t    listen_port{5354};
};

struct Endpoint {
    std::string host;
    uint16_t    port{53};

    bool operator==(const Endpoint&) const = default;
};

enum class UpstreamProtocol { Udp, Dot, Doh };

struct UpstreamConfig {
    UpstreamProtocol           protocol{UpstreamProtocol::Udp};
    std::vector<Endpoint>      servers{{"1.1.1.1", 53}, {"9.9.9.9", 53}};
    std::chrono::milliseconds  timeout{2000};
    int                        retries_on_primary{1};
    size_t                     padding_block_size{128};

    // SNI to use during DoT/DoH TLS handshakes. Required when servers are
    // reached by IP literal. Ignored for protocol == Udp.
    std::string                servername;

    // RFC 7469 SPKI pins ("sha256/<base64>"). Empty = chain validation only.
    std::vector<std::string>   spki_pins;

    // PEM file of trusted CA certificates for upstream chain validation.
    // Required on Windows when the binary is built against an OpenSSL
    // distribution with no compiled-in trust store (FireDaemon OpenSSL 4
    // ships zero CA certs). Leave empty on Linux / macOS to use system
    // defaults; the TLS layer also auto-discovers `cacert.pem` next to
    // the executable on Windows when this is unset.
    std::string                ca_file;

    // DoH request path. Standard is "/dns-query". Only consulted when
    // protocol = "doh".
    std::string                doh_path{"/dns-query"};

    // Encrypted Client Hello (RFC 9849). Opt-in; requires this build to
    // have been compiled with CLOAKDNS_ECH=ON (OpenSSL 4.0+).
    //
    // ech_outer_servername: cleartext SNI on the wire. Empty lets
    //   OpenSSL pick a sensible default from the ECHConfigList.
    // ech_config_list: pre-decoded ECHConfigList bytes. Source: copy
    //   from `dig +https <hostname>` HTTPS RR's `ech` SvcParam, decode
    //   to bytes, store here. (config.cpp does the base64 decode at
    //   load time so consumers get raw bytes.)
    bool                       ech_enabled{false};
    std::string                ech_outer_servername;
    std::vector<std::byte>     ech_config_list;

    // Auto-fetch the ECHConfigList from the upstream's HTTPS DNS RR at
    // startup (and on SIGHUP). When true, ech_config_list_b64 in TOML
    // becomes a fallback used only if every bootstrap server fails.
    // The bootstrap query is plain UDP — a one-time cleartext leak that
    // reveals only the upstream hostname (already in this config).
    bool                       ech_autobootstrap{false};
    std::vector<Endpoint>      ech_bootstrap_servers{
                                  {"1.0.0.1", 53}, {"8.8.8.8", 53}};

    // Send GREASE ECH on connections where real ECH isn't configured
    // (RFC 9849 §6.2). Off by default — enable when you want this build
    // to be wire-indistinguishable from an ECH-using client even when
    // talking to a non-ECH upstream.
    bool                       ech_grease{false};
};

struct BlocklistConfig {
    // A named research tier: its domains are loaded and tagged with
    // `name`, so a block can be attributed to it in the query log.
    // Declared via [[blocklist.tier]] tables in the config.
    struct Tier {
        std::string                        name;
        std::vector<std::filesystem::path> sources;
    };
    // Uncategorized core list(s). Blocks from these carry no category.
    std::vector<std::filesystem::path> sources{"blocklists/tier1.txt"};
    std::vector<Tier>                  tiers;
};

struct AllowlistConfig {
    std::vector<std::filesystem::path> sources;   // empty = no allowlist
};

struct CacheConfig {
    size_t                    max_entries{50000};
    std::chrono::milliseconds jitter_max{5};
    std::chrono::seconds      sweep_interval{30};
};

struct UncloakConfig {
    int max_depth{8};
};

struct LoggingConfig {
    std::filesystem::path path;                // empty = disabled
    bool                  async{true};
    size_t                queue_size{8192};
    size_t                max_size_bytes{0};   // 0 = no rotation
    bool                  redact_client{false}; // hash client addr if true
};

struct ServiceConfig {
    std::string run_as_user;    // empty = don't drop privileges (dev mode)
    std::string run_as_group;   // empty = same as user
};

struct Config {
    ServerConfig    server{};
    UpstreamConfig  upstream{};
    BlocklistConfig blocklist{};
    AllowlistConfig allowlist{};
    CacheConfig     cache{};
    UncloakConfig   uncloak{};
    LoggingConfig   logging{};
    ServiceConfig   service{};
};

struct ConfigError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Parse a TOML configuration file. Missing sections get documented
// defaults. Unknown top-level keys are ignored (for forward-compat).
// Throws ConfigError with an actionable message on schema violations:
//   - required key missing
//   - wrong TOML type for a known key
//   - value out of range (e.g. port > 65535, negative durations)
//   - malformed upstream "host:port" strings
Config load_config(const std::filesystem::path& path);

// Same as load_config but parses from a string — used by unit tests
// to exercise schema failures without a temp file per case.
Config parse_config_toml(std::string_view text);

} // namespace cloak
