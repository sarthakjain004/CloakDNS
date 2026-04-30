#pragma once

#include "cloakdns/tls.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cloak::resolver::detail {

// Inputs shared by every TLS-bearing Resolver Adapter. Mirrors the
// per-Adapter Config types (DotAdapterConfig, DohAdapterConfig) without
// pulling resolver.hpp's higher-level types in here.
struct TlsAdapterFields {
    const std::vector<std::string>& spki_pins;
    const std::string&              servername;
    const std::string&              ca_file;
    bool                            ech_grease;
    const std::string&              ech_outer_servername;
    const std::vector<std::byte>&   ech_config_list;
};

// Build the (ContextConfig, Context) pair every TLS Adapter needs.
// Both halves are heap-owned because tls::ContextConfig is non-movable
// and tls::Context borrows a reference to it for its lifetime.
//
// `alpn` differs per protocol: DoT = None, DoH = Http1Only.
inline std::pair<std::unique_ptr<tls::ContextConfig>,
                 std::unique_ptr<tls::Context>>
make_tls_for_adapter(const TlsAdapterFields& fields, tls::HttpAlpn alpn) {
    auto cfg = std::make_unique<tls::ContextConfig>();
    cfg->spki_pins  = fields.spki_pins;
    cfg->servername = fields.servername;
    cfg->ca_file    = fields.ca_file;
    cfg->ech_grease = fields.ech_grease;
    cfg->alpn       = alpn;
    cfg->ech.store(tls::EchConfig::Snapshot{
        .bytes = fields.ech_config_list.empty()
            ? nullptr
            : std::make_shared<const std::vector<std::byte>>(
                fields.ech_config_list),
        .outer_servername = fields.ech_outer_servername,
    });
    auto ctx = std::make_unique<tls::Context>(*cfg);
    return {std::move(cfg), std::move(ctx)};
}

} // namespace cloak::resolver::detail
