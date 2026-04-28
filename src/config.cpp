#include "cloakdns/config.hpp"

#include "cloakdns/tls.hpp"

#include <asio/ip/address.hpp>
#include <toml++/toml.hpp>

#include <charconv>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>

namespace cloak {
namespace {

[[noreturn]] void fail(const std::string& msg) {
    throw ConfigError{msg};
}

bool parse_uint16(std::string_view s, uint16_t& out) {
    uint32_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return false;
    if (v > 0xffff) return false;
    out = static_cast<uint16_t>(v);
    return true;
}

Endpoint parse_endpoint(std::string_view s) {
    const auto colon = s.rfind(':');
    if (colon == std::string_view::npos)
        fail("upstream.servers: '" + std::string{s} + "' missing ':port'");
    if (colon == 0)
        fail("upstream.servers: '" + std::string{s} + "' has empty host");
    uint16_t port = 0;
    if (!parse_uint16(s.substr(colon + 1), port))
        fail("upstream.servers: '" + std::string{s} + "' port not 0-65535");
    return Endpoint{std::string{s.substr(0, colon)}, port};
}

ServerConfig parse_server(const toml::table& t) {
    ServerConfig out;
    if (auto v = t["listen_addr"].value<std::string>(); v) out.listen_addr = *v;
    if (auto v = t["listen_port"].value<int64_t>(); v) {
        if (*v < 0 || *v > 0xffff)
            fail("server.listen_port: " + std::to_string(*v) + " out of 0..65535");
        out.listen_port = static_cast<uint16_t>(*v);
    }
    // Validate the listen address up front so a typo fails the load,
    // not the bind() call later. Accepts both IPv4 and IPv6 literals.
    std::error_code ec;
    (void)asio::ip::make_address(out.listen_addr, ec);
    if (ec)
        fail("server.listen_addr: '" + out.listen_addr +
             "' is not a valid IP address (" + ec.message() + ")");
    return out;
}

UpstreamConfig parse_upstream(const toml::table& t) {
    UpstreamConfig out;
    if (auto v = t["protocol"].value<std::string>(); v) {
        if      (*v == "udp") out.protocol = UpstreamProtocol::Udp;
        else if (*v == "dot") out.protocol = UpstreamProtocol::Dot;
        else if (*v == "doh") out.protocol = UpstreamProtocol::Doh;
        else fail("upstream.protocol: '" + *v + "' must be one of \"udp\", \"dot\", \"doh\"");
    }
    if (auto arr = t["servers"].as_array()) {
        out.servers.clear();
        for (const auto& el : *arr) {
            auto s = el.value<std::string>();
            if (!s)
                fail("upstream.servers: entries must be strings like \"ip:port\"");
            out.servers.push_back(parse_endpoint(*s));
        }
        if (out.servers.empty())
            fail("upstream.servers: must contain at least one entry");
    }
    if (auto v = t["timeout_ms"].value<int64_t>(); v) {
        if (*v <= 0)
            fail("upstream.timeout_ms: must be positive");
        out.timeout = std::chrono::milliseconds{*v};
    }
    if (auto v = t["retries_on_primary"].value<int64_t>(); v) {
        if (*v < 0)
            fail("upstream.retries_on_primary: must be >= 0");
        out.retries_on_primary = static_cast<int>(*v);
    }
    if (auto v = t["padding_block_size"].value<int64_t>(); v) {
        if (*v < 0)
            fail("upstream.padding_block_size: must be >= 0 (0 disables)");
        out.padding_block_size = static_cast<size_t>(*v);
    }
    if (auto v = t["servername"].value<std::string>(); v) {
        out.servername = *v;
    }
    if (auto arr = t["spki_pins"].as_array()) {
        for (const auto& el : *arr) {
            auto s = el.value<std::string>();
            if (!s)
                fail("upstream.spki_pins: entries must be strings (\"sha256/<base64>\")");
            if (!s->starts_with("sha256/"))
                fail("upstream.spki_pins: '" + *s + "' must start with \"sha256/\"");
            out.spki_pins.push_back(*s);
        }
    }
    if (auto v = t["doh_path"].value<std::string>(); v) {
        if (v->empty() || v->front() != '/')
            fail("upstream.doh_path: '" + *v + "' must start with '/'");
        out.doh_path = *v;
    }
    if (auto v = t["ech_enabled"].value<bool>(); v) {
        out.ech_enabled = *v;
    }
    if (auto v = t["ech_outer_servername"].value<std::string>(); v) {
        out.ech_outer_servername = *v;
    }
    if (auto v = t["ech_config_list_b64"].value<std::string>(); v) {
        if (auto bytes = tls::base64_decode(*v); bytes) {
            out.ech_config_list = std::move(*bytes);
        } else {
            fail("upstream.ech_config_list_b64: not valid base64");
        }
    }
    if (out.ech_enabled) {
        if (!tls::ech_supported()) {
            fail("upstream.ech_enabled = true but this build was compiled "
                 "without ECH support (CLOAKDNS_ECH=OFF). Rebuild with "
                 "-DCLOAKDNS_ECH=ON against OpenSSL 4.0+, or unset "
                 "ech_enabled.");
        }
        if (out.ech_config_list.empty()) {
            fail("upstream.ech_enabled = true but ech_config_list_b64 is "
                 "missing or empty. Provide the ECHConfigList from the "
                 "upstream's HTTPS DNS record.");
        }
    }
    if ((out.protocol == UpstreamProtocol::Dot || out.protocol == UpstreamProtocol::Doh)
        && out.servername.empty()) {
        // Allow empty when the user is pointing at a hostname that itself
        // serves as the SNI (we'll resolve and validate by that name in a
        // future iteration). For now require it explicitly.
        fail("upstream.servername: required when protocol = \"dot\" or \"doh\"");
    }
    return out;
}

BlocklistConfig parse_blocklist(const toml::table& t) {
    BlocklistConfig out;
    if (auto arr = t["sources"].as_array()) {
        out.sources.clear();
        for (const auto& el : *arr) {
            auto s = el.value<std::string>();
            if (!s)
                fail("blocklist.sources: entries must be path strings");
            out.sources.emplace_back(*s);
        }
        if (out.sources.empty())
            fail("blocklist.sources: must contain at least one path");
    }
    return out;
}

AllowlistConfig parse_allowlist(const toml::table& t) {
    AllowlistConfig out;
    if (auto arr = t["sources"].as_array()) {
        for (const auto& el : *arr) {
            auto s = el.value<std::string>();
            if (!s)
                fail("allowlist.sources: entries must be path strings");
            out.sources.emplace_back(*s);
        }
    }
    return out;
}

CacheConfig parse_cache(const toml::table& t) {
    CacheConfig out;
    if (auto v = t["max_entries"].value<int64_t>(); v) {
        if (*v < 0)
            fail("cache.max_entries: must be >= 0");
        out.max_entries = static_cast<size_t>(*v);
    }
    if (auto v = t["jitter_max_ms"].value<int64_t>(); v) {
        if (*v < 0)
            fail("cache.jitter_max_ms: must be >= 0");
        out.jitter_max = std::chrono::milliseconds{*v};
    }
    if (auto v = t["sweep_interval_s"].value<int64_t>(); v) {
        if (*v <= 0)
            fail("cache.sweep_interval_s: must be positive");
        out.sweep_interval = std::chrono::seconds{*v};
    }
    return out;
}

UncloakConfig parse_uncloak(const toml::table& t) {
    UncloakConfig out;
    if (auto v = t["max_depth"].value<int64_t>(); v) {
        if (*v < 1 || *v > 64)
            fail("uncloak.max_depth: must be in 1..64");
        out.max_depth = static_cast<int>(*v);
    }
    return out;
}

LoggingConfig parse_logging(const toml::table& t) {
    LoggingConfig out;
    if (auto v = t["path"].value<std::string>(); v)
        out.path = *v;
    if (auto v = t["async"].value<bool>(); v)
        out.async = *v;
    if (auto v = t["queue_size"].value<int64_t>(); v) {
        if (*v <= 0)
            fail("logging.queue_size: must be positive");
        out.queue_size = static_cast<size_t>(*v);
    }
    if (auto v = t["max_size_bytes"].value<int64_t>(); v) {
        if (*v < 0)
            fail("logging.max_size_bytes: must be >= 0 (0 disables rotation)");
        out.max_size_bytes = static_cast<size_t>(*v);
    }
    if (auto v = t["redact_client"].value<bool>(); v)
        out.redact_client = *v;
    return out;
}

ServiceConfig parse_service(const toml::table& t) {
    ServiceConfig out;
    if (auto v = t["run_as_user"].value<std::string>(); v)
        out.run_as_user = *v;
    if (auto v = t["run_as_group"].value<std::string>(); v)
        out.run_as_group = *v;
    return out;
}

} // namespace

Config parse_config_toml(std::string_view text) {
    toml::table tbl;
    try {
        tbl = toml::parse(text);
    } catch (const toml::parse_error& e) {
        std::ostringstream os;
        os << "TOML parse error: " << e.description()
           << " at line " << e.source().begin.line
           << ", column " << e.source().begin.column;
        fail(os.str());
    }

    Config cfg;
    if (auto t = tbl["server"].as_table())    cfg.server    = parse_server(*t);
    if (auto t = tbl["upstream"].as_table())  cfg.upstream  = parse_upstream(*t);
    if (auto t = tbl["blocklist"].as_table()) cfg.blocklist = parse_blocklist(*t);
    if (auto t = tbl["allowlist"].as_table()) cfg.allowlist = parse_allowlist(*t);
    if (auto t = tbl["cache"].as_table())     cfg.cache     = parse_cache(*t);
    if (auto t = tbl["uncloak"].as_table())   cfg.uncloak   = parse_uncloak(*t);
    if (auto t = tbl["logging"].as_table())   cfg.logging   = parse_logging(*t);
    if (auto t = tbl["service"].as_table())   cfg.service   = parse_service(*t);
    return cfg;
}

Config load_config(const std::filesystem::path& path) {
    std::ifstream in{path};
    if (!in) fail("cannot open config: " + path.string());
    std::ostringstream buf;
    buf << in.rdbuf();
    if (in.bad()) fail("I/O error reading config: " + path.string());
    return parse_config_toml(buf.str());
}

} // namespace cloak
