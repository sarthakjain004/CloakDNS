#pragma once

#include "cloakdns/dns_message.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace cloak {

// Build an A 0.0.0.0 response for a parsed query. `query` must be the
// byte buffer `parsed` was produced from. Returns a new owning byte
// vector ready for sendto().
std::vector<std::byte>
build_block_a_response(std::span<const std::byte> query,
                       const DnsMessage& parsed);

// Build a REFUSED response (RCODE=5, no answers) for a parsed query.
std::vector<std::byte>
build_refused_response(std::span<const std::byte> query,
                       const DnsMessage& parsed);

// Build a SERVFAIL response (RCODE=2, no answers) for a parsed query.
std::vector<std::byte>
build_servfail_response(std::span<const std::byte> query,
                        const DnsMessage& parsed);

// Build a standard outgoing A IN query for the given qname with flags
// RD=1. Throws std::invalid_argument on an empty/oversized/malformed
// qname. The uncloaker uses this to re-query intermediate CNAME hops.
std::vector<std::byte>
build_a_query(std::string_view qname, uint16_t id);

} // namespace cloak
