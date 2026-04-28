#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/edns_padding.hpp"
#include "cloakdns/aliases.hpp"
#include "fixtures.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace cloak;

namespace {

template <size_t N>
span<const byte> as_span(const array<byte, N>& a) {
    return span<const byte>{a.data(), a.size()};
}

span<const byte> as_span(const vector<byte>& v) {
    return span<const byte>{v.data(), v.size()};
}

string chunked_label_name(size_t total_chars) {
    string out;
    for (size_t i = 0; i < total_chars; i += 63) {
        if (!out.empty()) out += '.';
        const auto chunk = std::min<size_t>(63, total_chars - i);
        out.append(chunk, 'a');
    }
    return out + ".ex";
}

} // namespace

TEST(EdnsPadding, ZeroBlockSizePassesThrough) {
    auto q = build_a_query("foo.example", 0x1234);
    auto padded = pad_query(as_span(q), 0);
    ASSERT_EQ(padded.size(), q.size());
    EXPECT_TRUE(std::equal(padded.begin(), padded.end(), q.begin()));
}

TEST(EdnsPadding, NoOptShortQueryRoundedTo128) {
    auto q = build_a_query("foo.example", 0x1234);
    ASSERT_LT(q.size(), 128u);
    auto padded = pad_query(as_span(q), 128);

    EXPECT_EQ(padded.size(), 128u);
}

TEST(EdnsPadding, NoOptQueryGetsValidOpt) {
    auto q = build_a_query("foo.example", 0x1234);
    auto padded = pad_query(as_span(q), 128);
    auto msg = parse(as_span(padded));

    EXPECT_EQ(msg.header.id, 0x1234);
    EXPECT_EQ(msg.header.arcount, 1);
    ASSERT_EQ(msg.questions.size(), 1u);
    EXPECT_EQ(msg.questions[0].qname, "foo.example");
    const bool has_opt = std::any_of(msg.additional.begin(), msg.additional.end(),
        [](const auto& rr) { return rr.type == dns_type::OPT; });
    EXPECT_TRUE(has_opt);
}

TEST(EdnsPadding, ExistingOptQueryRoundedTo128) {
    // kExampleQueryEdns is 40 bytes with an OPT record (RDLEN=0) as the
    // last record. Padding adds only a padding option, not a new OPT RR.
    auto padded = pad_query(as_span(fixtures::kExampleQueryEdns), 128);
    EXPECT_EQ(padded.size(), 128u);

    auto msg = parse(as_span(padded));
    const auto opt_count = std::count_if(
        msg.additional.begin(), msg.additional.end(),
        [](const auto& rr) { return rr.type == dns_type::OPT; });
    EXPECT_EQ(opt_count, 1);
    EXPECT_EQ(msg.header.arcount, 1);
}

TEST(EdnsPadding, PaddedOutputReparsesCleanly) {
    auto q = build_a_query("a.really.long.qname.for.coverage.example", 0xdead);
    auto padded = pad_query(as_span(q), 128);
    EXPECT_NO_THROW(parse(as_span(padded)));
}

TEST(EdnsPadding, LargeQueryRoundedToNextMultiple) {
    auto long_q = build_a_query(chunked_label_name(180), 0x4242);
    ASSERT_GT(long_q.size(), 128u);
    auto padded = pad_query(as_span(long_q), 128);
    EXPECT_EQ(padded.size(), 256u);
}

TEST(EdnsPadding, MalformedInputPassesThrough) {
    vector<byte> junk(4, byte{0xab});
    auto padded = pad_query(as_span(junk), 128);
    EXPECT_EQ(padded.size(), junk.size());
}

TEST(EdnsPadding, BlockSize468ForDot) {
    auto q = build_a_query("foo.example", 1);
    auto padded = pad_query(as_span(q), kPadBlockDot);
    EXPECT_EQ(padded.size(), kPadBlockDot);
}

TEST(EdnsPadding, NonLastOptPassesThrough) {
    // Build a response-shaped packet (as a test stand-in) where the
    // additional section has an OPT followed by another record,
    // making OPT non-last. pad_query must decline to modify it.
    //
    // We hand-assemble bytes: header + 1 question + 2 additional RRs
    // where the first is OPT and the second is a non-OPT RR.
    vector<byte> pkt;
    auto w16 = [&](uint16_t v) {
        pkt.push_back(byte{static_cast<uint8_t>(v >> 8)});
        pkt.push_back(byte{static_cast<uint8_t>(v & 0xff)});
    };
    auto emit_name = [&](string_view name) {
        size_t start = 0;
        for (size_t i = 0; i <= name.size(); ++i) {
            if (i == name.size() || name[i] == '.') {
                const auto len = static_cast<uint8_t>(i - start);
                pkt.push_back(byte{len});
                for (size_t j = start; j < i; ++j)
                    pkt.push_back(byte{static_cast<uint8_t>(name[j])});
                start = i + 1;
            }
        }
        pkt.push_back(byte{0});
    };
    // header: id=1, flags=0x0100, qd=1, an=0, ns=0, ar=2
    w16(1); w16(0x0100); w16(1); w16(0); w16(0); w16(2);
    emit_name("foo.example");
    w16(1); w16(1);                        // QTYPE=A QCLASS=IN
    // additional[0]: OPT (type 41) with RDLEN 0
    pkt.push_back(byte{0});           // root name
    w16(dns_type::OPT); w16(4096); w16(0); w16(0); w16(0);
    // additional[1]: A record for foo.example → 1.2.3.4 (makes OPT non-last)
    emit_name("foo.example");
    w16(1); w16(1); w16(0); w16(60); w16(4);
    pkt.push_back(byte{1}); pkt.push_back(byte{2});
    pkt.push_back(byte{3}); pkt.push_back(byte{4});

    auto padded = pad_query(as_span(pkt), 128);
    EXPECT_EQ(padded.size(), pkt.size());  // unchanged because OPT not last
}
