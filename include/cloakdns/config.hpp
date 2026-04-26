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

struct UpstreamConfig {
    std::vector<Endpoint>      servers{{"1.1.1.1", 53}, {"9.9.9.9", 53}};
    std::chrono::milliseconds  timeout{2000};
    int                        retries_on_primary{1};
    size_t                     padding_block_size{128};
};

struct BlocklistConfig {
    std::vector<std::filesystem::path> sources{"blocklists/tier1.txt"};
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
