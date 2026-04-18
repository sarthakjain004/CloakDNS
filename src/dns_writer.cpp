#include "cloakdns/dns_writer.hpp"

#include <cstdint>
#include <cstring>

namespace cloak {
namespace {

constexpr size_t kHeaderSize = 12;

void write_u16_be(std::vector<std::byte>& out, size_t off, uint16_t v) {
    out[off]     = std::byte{static_cast<uint8_t>((v >> 8) & 0xff)};
    out[off + 1] = std::byte{static_cast<uint8_t>(v & 0xff)};
}

uint16_t read_u16_be(std::span<const std::byte> b, size_t off) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(std::to_integer<uint8_t>(b[off])) << 8) |
         static_cast<uint16_t>(std::to_integer<uint8_t>(b[off + 1])));
}

// Build a response header in `out` based on `query` flags and rcode.
// Preserves the query's opcode (bits 14..11) and RD bit (bit 8).
void write_response_header(std::vector<std::byte>& out,
                           std::span<const std::byte> query,
                           uint16_t ancount, uint8_t rcode) {
    out[0] = query[0];  // ID high
    out[1] = query[1];  // ID low

    const uint16_t q_flags = read_u16_be(query, 2);
    uint16_t r_flags = 0x8000;                 // QR=1
    r_flags |= static_cast<uint16_t>(q_flags & 0x7800);  // opcode
    r_flags |= static_cast<uint16_t>(q_flags & 0x0100);  // RD
    r_flags |= 0x0080;                         // RA=1
    r_flags |= static_cast<uint16_t>(rcode & 0x000F);
    write_u16_be(out, 2, r_flags);

    write_u16_be(out, 4, 1);         // QDCOUNT = 1
    write_u16_be(out, 6, ancount);
    write_u16_be(out, 8, 0);         // NSCOUNT
    write_u16_be(out, 10, 0);        // ARCOUNT
}

void copy_question_bytes(std::vector<std::byte>& out,
                         std::span<const std::byte> query,
                         size_t question_end) {
    for (size_t i = kHeaderSize; i < question_end; ++i) {
        out[i] = query[i];
    }
}

} // namespace

std::vector<std::byte>
build_block_a_response(std::span<const std::byte> query,
                       const DnsMessage& parsed) {
    constexpr size_t kAnswerLen = 16;   // pointer(2) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4)
    const size_t q_end = parsed.question_section_end;
    std::vector<std::byte> out(q_end + kAnswerLen);

    write_response_header(out, query, /*ancount=*/1, /*rcode=*/0);
    copy_question_bytes(out, query, q_end);

    size_t a = q_end;
    out[a++] = std::byte{0xc0};                  // NAME = pointer
    out[a++] = std::byte{0x0c};                  //       to offset 12
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x01};  // TYPE = A
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x01};  // CLASS = IN
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x00};
    out[a++] = std::byte{0x01}; out[a++] = std::byte{0x2c};  // TTL = 300
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x04};  // RDLEN = 4
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x00};
    out[a++] = std::byte{0x00}; out[a++] = std::byte{0x00};  // 0.0.0.0
    return out;
}

std::vector<std::byte>
build_refused_response(std::span<const std::byte> query,
                       const DnsMessage& parsed) {
    const size_t q_end = parsed.question_section_end;
    std::vector<std::byte> out(q_end);

    write_response_header(out, query, /*ancount=*/0, /*rcode=*/5);
    copy_question_bytes(out, query, q_end);
    return out;
}

std::vector<std::byte>
build_servfail_response(std::span<const std::byte> query,
                        const DnsMessage& parsed) {
    const size_t q_end = parsed.question_section_end;
    std::vector<std::byte> out(q_end);

    write_response_header(out, query, /*ancount=*/0, /*rcode=*/2);
    copy_question_bytes(out, query, q_end);
    return out;
}

} // namespace cloak
