#include "cloakdns/dns_parser.hpp"

#include <cstdint>

namespace cloak {
namespace {

constexpr size_t kHeaderSize = 12;
constexpr size_t kMaxNameSize = 255;
constexpr int kMaxPointerHops = 16;

uint16_t read_u16_be(std::span<const std::byte> b, size_t off) {
    if (off + 2 > b.size()) throw ParseError{"u16 out of bounds"};
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(std::to_integer<uint8_t>(b[off])) << 8) |
         static_cast<uint16_t>(std::to_integer<uint8_t>(b[off + 1])));
}

uint32_t read_u32_be(std::span<const std::byte> b, size_t off) {
    if (off + 4 > b.size()) throw ParseError{"u32 out of bounds"};
    return (static_cast<uint32_t>(std::to_integer<uint8_t>(b[off]))     << 24) |
           (static_cast<uint32_t>(std::to_integer<uint8_t>(b[off + 1])) << 16) |
           (static_cast<uint32_t>(std::to_integer<uint8_t>(b[off + 2])) <<  8) |
            static_cast<uint32_t>(std::to_integer<uint8_t>(b[off + 3]));
}

std::string decode_name(std::span<const std::byte> pkt, size_t& cursor_inout) {
    std::string out;
    int hops = 0;
    size_t cursor = cursor_inout;
    bool after_pointer = false;

    for (;;) {
        if (cursor >= pkt.size())
            throw ParseError{"name: offset out of bounds"};

        const uint8_t len = std::to_integer<uint8_t>(pkt[cursor]);
        const uint8_t top = len & 0xC0;

        if (top == 0xC0) {
            if (++hops > kMaxPointerHops)
                throw ParseError{"name: pointer loop exceeded 16 hops"};
            if (cursor + 1 >= pkt.size())
                throw ParseError{"name: pointer truncated"};
            const uint16_t target =
                static_cast<uint16_t>(
                    (static_cast<uint16_t>(len & 0x3F) << 8) |
                     std::to_integer<uint8_t>(pkt[cursor + 1]));
            if (target >= pkt.size())
                throw ParseError{"name: pointer target out of bounds"};
            if (!after_pointer) {
                cursor_inout = cursor + 2;
                after_pointer = true;
            }
            cursor = target;
            continue;
        }

        if (top != 0x00)
            throw ParseError{"name: reserved label bits"};

        if (len == 0) {
            if (!after_pointer) cursor_inout = cursor + 1;
            return out;
        }

        // len is 0..63 by construction: top two bits are 00, so len <= 0x3F.
        if (cursor + 1 + len > pkt.size())
            throw ParseError{"name: label out of bounds"};

        if (!out.empty()) out.push_back('.');
        for (size_t i = 0; i < len; ++i) {
            char c = static_cast<char>(std::to_integer<uint8_t>(pkt[cursor + 1 + i]));
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            out.push_back(c);
        }
        cursor += 1 + len;

        if (out.size() > kMaxNameSize)
            throw ParseError{"name: exceeds 255 bytes"};
    }
}

void parse_rr_section(std::span<const std::byte> pkt, size_t& cursor,
                      uint16_t count, std::vector<ResourceRecord>& out) {
    out.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        ResourceRecord rr;
        rr.name = decode_name(pkt, cursor);
        if (cursor + 10 > pkt.size())
            throw ParseError{"truncated resource record header"};
        rr.type   = read_u16_be(pkt, cursor);
        rr.rclass = read_u16_be(pkt, cursor + 2);
        rr.ttl    = read_u32_be(pkt, cursor + 4);
        const uint16_t rdlen = read_u16_be(pkt, cursor + 8);
        cursor += 10;
        if (cursor + rdlen > pkt.size())
            throw ParseError{"truncated RDATA"};
        rr.rdata = pkt.subspan(cursor, rdlen);
        cursor += rdlen;
        out.push_back(std::move(rr));
    }
}

} // namespace

DnsMessage parse(std::span<const std::byte> packet) {
    if (packet.size() < kHeaderSize)
        throw ParseError{"truncated header"};

    DnsMessage msg;

    msg.header.id = read_u16_be(packet, 0);
    const uint16_t flags = read_u16_be(packet, 2);
    msg.header.qr     = ((flags >> 15) & 0x01) != 0;
    msg.header.opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
    msg.header.aa     = ((flags >> 10) & 0x01) != 0;
    msg.header.tc     = ((flags >>  9) & 0x01) != 0;
    msg.header.rd     = ((flags >>  8) & 0x01) != 0;
    msg.header.ra     = ((flags >>  7) & 0x01) != 0;
    msg.header.rcode  = static_cast<uint8_t>(flags & 0x0F);
    msg.header.qdcount = read_u16_be(packet, 4);
    msg.header.ancount = read_u16_be(packet, 6);
    msg.header.nscount = read_u16_be(packet, 8);
    msg.header.arcount = read_u16_be(packet, 10);

    size_t cursor = kHeaderSize;

    msg.questions.reserve(msg.header.qdcount);
    for (uint16_t i = 0; i < msg.header.qdcount; ++i) {
        Question q;
        q.qname = decode_name(packet, cursor);
        if (cursor + 4 > packet.size())
            throw ParseError{"truncated question"};
        q.qtype  = read_u16_be(packet, cursor);
        q.qclass = read_u16_be(packet, cursor + 2);
        cursor += 4;
        msg.questions.push_back(std::move(q));
    }
    msg.question_section_end = cursor;

    parse_rr_section(packet, cursor, msg.header.ancount, msg.answers);
    parse_rr_section(packet, cursor, msg.header.nscount, msg.authority);
    parse_rr_section(packet, cursor, msg.header.arcount, msg.additional);

    return msg;
}

} // namespace cloak
