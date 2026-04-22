#pragma once

#include "cloakdns/dns_message.hpp"

#include <cstddef>
#include <span>
#include <stdexcept>

namespace cloak {

struct ParseError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

DnsMessage parse(std::span<const std::byte> packet);

// Decode a DNS name from `pkt` starting at `offset`, applying the same
// bounds, loop, label, and total-length limits as the header parser.
// Exposed separately because CNAME RDATA may contain compression
// pointers back into earlier packet bytes, so the caller needs a way to
// decode from an arbitrary offset rather than streaming from a cursor.
std::string decode_name_at(std::span<const std::byte> pkt, size_t offset);

} // namespace cloak
