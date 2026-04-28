#include "cloakdns/edns_padding.hpp"

#include "cloakdns/dns_message.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/aliases.hpp"

#include <cstdint>
#include <limits>

namespace cloak {
namespace {

constexpr uint16_t kOptionCodePadding = 12;          // RFC 7830
constexpr uint16_t kDefaultUdpPayload = 4096;        // EDNS0 common default

// Wire sizes we need to reserve when synthesizing:
//   OPT RR skeleton: NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLEN(2) = 11
//   Padding option header: OPTION-CODE(2) + OPTION-LENGTH(2) = 4
constexpr size_t kOptRrSkeleton      = 11;
constexpr size_t kPaddingOptionHead  = 4;

size_t round_up(size_t n, size_t block) {
    return ((n + block - 1) / block) * block;
}

void write_u16_be(vector<byte>& out, size_t off, uint16_t v) {
    out[off]     = byte{static_cast<uint8_t>((v >> 8) & 0xff)};
    out[off + 1] = byte{static_cast<uint8_t>(v & 0xff)};
}

void append_u16_be(vector<byte>& out, uint16_t v) {
    out.push_back(byte{static_cast<uint8_t>((v >> 8) & 0xff)});
    out.push_back(byte{static_cast<uint8_t>(v & 0xff)});
}

void append_padding_option(vector<byte>& out, size_t pad_len) {
    append_u16_be(out, kOptionCodePadding);
    append_u16_be(out, static_cast<uint16_t>(pad_len));
    out.insert(out.end(), pad_len, byte{0});
}

enum class OptState { None, Last, NotLast };

struct OptScan {
    OptState state{OptState::None};
    const ResourceRecord* rr{nullptr};
};

OptScan scan_opt(const DnsMessage& msg, span<const byte> query) {
    for (const auto& rr : msg.additional) {
        if (rr.type != dns_type::OPT) continue;
        const auto* end = rr.rdata.data() + rr.rdata.size();
        if (end == query.data() + query.size()) return {OptState::Last, &rr};
        return {OptState::NotLast, &rr};
    }
    return {OptState::None, nullptr};
}

} // namespace

vector<byte>
pad_query(span<const byte> query, size_t block_size) {
    vector<byte> out(query.begin(), query.end());
    if (block_size == 0) return out;

    DnsMessage msg;
    try {
        msg = parse(query);
    } catch (const ParseError&) {
        return out;
    }

    const auto opt = scan_opt(msg, query);
    if (opt.state == OptState::NotLast) return out;

    if (opt.state == OptState::Last) {
        const size_t min_new = query.size() + kPaddingOptionHead;
        const size_t target  = round_up(min_new, block_size);
        const size_t pad_len = target - min_new;

        // RFC 6891 limits RDLEN to uint16_t; bail if extending would overflow.
        const size_t new_rdlen_full =
            opt.rr->rdata.size() + kPaddingOptionHead + pad_len;
        if (new_rdlen_full > std::numeric_limits<uint16_t>::max()) return out;

        // RDLEN sits 2 bytes before RDATA begins.
        const size_t rdlen_off = static_cast<size_t>(
            opt.rr->rdata.data() - query.data() - 2);
        write_u16_be(out, rdlen_off, static_cast<uint16_t>(new_rdlen_full));

        out.reserve(target);
        append_padding_option(out, pad_len);
        return out;
    }

    // Refuse to bump ARCOUNT past uint16_t max.
    const uint16_t arcount_hi =
        static_cast<uint16_t>(to_integer<uint8_t>(query[10]));
    const uint16_t arcount_lo =
        static_cast<uint16_t>(to_integer<uint8_t>(query[11]));
    const uint16_t old_arcount = static_cast<uint16_t>((arcount_hi << 8) | arcount_lo);
    if (old_arcount == std::numeric_limits<uint16_t>::max()) return out;

    const size_t min_new = query.size() + kOptRrSkeleton + kPaddingOptionHead;
    const size_t target  = round_up(min_new, block_size);
    const size_t pad_len = target - min_new;

    out.reserve(target);
    out.push_back(byte{0});                     // NAME = root label
    append_u16_be(out, dns_type::OPT);
    append_u16_be(out, kDefaultUdpPayload);
    append_u16_be(out, 0);                           // TTL hi: extended rcode + version
    append_u16_be(out, 0);                           // TTL lo: DO + Z
    append_u16_be(out, static_cast<uint16_t>(kPaddingOptionHead + pad_len));
    append_padding_option(out, pad_len);

    write_u16_be(out, 10, static_cast<uint16_t>(old_arcount + 1));
    return out;
}

} // namespace cloak
