#pragma once

#include "cloakdns/dns_message.hpp"

#include <cstddef>
#include <span>
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

} // namespace cloak
