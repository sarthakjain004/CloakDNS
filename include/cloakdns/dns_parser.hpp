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

} // namespace cloak
