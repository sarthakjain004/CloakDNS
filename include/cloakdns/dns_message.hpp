#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace cloak {

namespace dns_type {
inline constexpr uint16_t A     = 1;
inline constexpr uint16_t CNAME = 5;
inline constexpr uint16_t AAAA  = 28;
inline constexpr uint16_t OPT   = 41;  // EDNS0 — "TTL" field is extended rcode + flags, not a lifetime
} // namespace dns_type

struct Header {
    uint16_t id{};
    bool qr{};
    bool aa{};
    bool tc{};
    bool rd{};
    bool ra{};
    uint8_t opcode{};
    uint8_t rcode{};
    uint16_t qdcount{};
    uint16_t ancount{};
    uint16_t nscount{};
    uint16_t arcount{};
};

struct Question {
    std::string qname;
    uint16_t qtype{};
    uint16_t qclass{};
};

struct ResourceRecord {
    std::string name;
    uint16_t type{};
    uint16_t rclass{};
    uint32_t ttl{};
    std::span<const std::byte> rdata;
};

struct DnsMessage {
    Header header{};
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authority;
    std::vector<ResourceRecord> additional;

    // Absolute byte offset in the source packet immediately after the
    // last question. Used by the writer to splice responses.
    size_t question_section_end{};
};

} // namespace cloak
