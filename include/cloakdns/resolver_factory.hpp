#pragma once

#include "cloakdns/config.hpp"
#include "cloakdns/resolver.hpp"

#include <asio/io_context.hpp>

#include <memory>

namespace cloak::resolver {

// Build a wired Resolver from the high-level Upstream config: resolves
// each `host:port` to an endpoint, picks the right Adapter factory per
// protocol, copies SPKI pins / CA file / ECH bytes / SNI into each
// Adapter's config.
//
// The Resolver returned holds 1..N Adapters in primary→fallback order
// matching `cfg.servers`. Throws on the same conditions the Adapter
// factories throw on (bad endpoint string, missing servername for
// DoT/DoH, etc.).
std::unique_ptr<Resolver>
build_from_config(asio::io_context& ctx, const UpstreamConfig& cfg);

} // namespace cloak::resolver
