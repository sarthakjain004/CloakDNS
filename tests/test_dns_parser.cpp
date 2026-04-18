#include "cloakdns/dns_parser.hpp"
#include "fixtures.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <span>
#include <vector>

using namespace cloak;
using namespace cloak::fixtures;

namespace {

template <size_t N>
std::span<const std::byte> as_span(const std::array<std::byte, N>& a) {
    return std::span<const std::byte>{a.data(), a.size()};
}

// Minimal header with all-zero flags and user-specified counts.
std::vector<std::byte> make_header(uint16_t qd, uint16_t an = 0,
                                   uint16_t ns = 0, uint16_t ar = 0) {
    std::vector<std::byte> h(12);
    h[0] = std::byte{0x00}; h[1] = std::byte{0x01};       // id
    h[2] = std::byte{0x00}; h[3] = std::byte{0x00};       // flags
    h[4] = std::byte{uint8_t(qd >> 8)}; h[5] = std::byte{uint8_t(qd & 0xff)};
    h[6] = std::byte{uint8_t(an >> 8)}; h[7] = std::byte{uint8_t(an & 0xff)};
    h[8] = std::byte{uint8_t(ns >> 8)}; h[9] = std::byte{uint8_t(ns & 0xff)};
    h[10] = std::byte{uint8_t(ar >> 8)}; h[11] = std::byte{uint8_t(ar & 0xff)};
    return h;
}

} // namespace

// ---- positive tests ----

TEST(DnsParser, HeaderDecoded) {
    auto msg = parse(as_span(kExampleQueryEdns));
    EXPECT_EQ(msg.header.id, 0xa37c);
    EXPECT_FALSE(msg.header.qr);
    EXPECT_EQ(msg.header.opcode, 0);
    EXPECT_FALSE(msg.header.aa);
    EXPECT_FALSE(msg.header.tc);
    EXPECT_TRUE(msg.header.rd);
    EXPECT_FALSE(msg.header.ra);
    EXPECT_EQ(msg.header.rcode, 0);
    EXPECT_EQ(msg.header.qdcount, 1);
    EXPECT_EQ(msg.header.ancount, 0);
    EXPECT_EQ(msg.header.nscount, 0);
    EXPECT_EQ(msg.header.arcount, 1);
}

TEST(DnsParser, QuestionDecoded) {
    auto msg = parse(as_span(kExampleQueryEdns));
    ASSERT_EQ(msg.questions.size(), 1u);
    EXPECT_EQ(msg.questions[0].qname, "example.com");
    EXPECT_EQ(msg.questions[0].qtype, 1);   // A
    EXPECT_EQ(msg.questions[0].qclass, 1);  // IN
}

TEST(DnsParser, EdnsOptAppearsInAdditional) {
    auto msg = parse(as_span(kExampleQueryEdns));
    ASSERT_EQ(msg.additional.size(), 1u);
    EXPECT_EQ(msg.additional[0].type, 41);        // OPT
    EXPECT_EQ(msg.additional[0].name, "");        // root label
    EXPECT_EQ(msg.additional[0].rdata.size(), 0u);
}

TEST(DnsParser, QnameIsLowercased) {
    // Same as kExampleQueryEdns but with "EXAMPLE" in uppercase.
    auto pkt = std::vector<std::byte>(kExampleQueryEdns.begin(),
                                      kExampleQueryEdns.end());
    for (size_t i = 13; i < 20; ++i) {   // offsets of "example"
        const auto c = std::to_integer<uint8_t>(pkt[i]);
        if (c >= 'a' && c <= 'z') pkt[i] = std::byte{uint8_t(c - 32)};
    }
    auto msg = parse(std::span<const std::byte>{pkt.data(), pkt.size()});
    EXPECT_EQ(msg.questions[0].qname, "example.com");
}

TEST(DnsParser, CompressionPointerResolves) {
    auto msg = parse(as_span(kExampleResponseCompressed));
    ASSERT_EQ(msg.questions.size(), 1u);
    EXPECT_EQ(msg.questions[0].qname, "www.example.com");
    ASSERT_EQ(msg.answers.size(), 1u);
    EXPECT_EQ(msg.answers[0].name, "www.example.com");
    EXPECT_EQ(msg.answers[0].type, 1);
    EXPECT_EQ(msg.answers[0].ttl, 300u);
    EXPECT_EQ(msg.answers[0].rdata.size(), 4u);
}

TEST(DnsParser, RdataIsViewIntoPacket) {
    auto pkt = as_span(kExampleResponseCompressed);
    auto msg = parse(pkt);
    ASSERT_EQ(msg.answers.size(), 1u);
    const auto rdata = msg.answers[0].rdata;
    EXPECT_GE(rdata.data(), pkt.data());
    EXPECT_LE(rdata.data() + rdata.size(), pkt.data() + pkt.size());
    // RDATA is the last 4 bytes of the packet.
    EXPECT_EQ(rdata.data(), pkt.data() + pkt.size() - 4);
}

TEST(DnsParser, ResponseFlagsDecoded) {
    auto msg = parse(as_span(kExampleResponseCompressed));
    EXPECT_TRUE(msg.header.qr);
    EXPECT_TRUE(msg.header.rd);
    EXPECT_TRUE(msg.header.ra);
    EXPECT_EQ(msg.header.rcode, 0);
}

// ---- negative tests (one per defensive cap) ----

TEST(DnsParser, TruncatedHeaderThrows) {
    std::array<std::byte, 5> pkt{};
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, TruncatedQuestionThrows) {
    // Header says QDCOUNT=1 but the question name has no terminator.
    auto pkt = make_header(1);
    pkt.push_back(std::byte{0x07});
    for (char c : "example") pkt.push_back(std::byte{uint8_t(c)}); // no \0
    pkt.pop_back();  // drop the NUL that for-loop added
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, ReservedLabelBitsThrow_10) {
    auto pkt = make_header(1);
    pkt.push_back(std::byte{0x80});   // top two bits = 10 (reserved)
    pkt.push_back(std::byte{0x00});
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, ReservedLabelBitsThrow_01) {
    auto pkt = make_header(1);
    pkt.push_back(std::byte{0x40});   // top two bits = 01 (reserved)
    pkt.push_back(std::byte{0x00});
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, NameTooLongThrows) {
    // Five labels of 63 bytes each = 315 bytes of label body, which exceeds
    // the 255-byte name cap even before a sixth label is needed.
    auto pkt = make_header(1);
    for (int i = 0; i < 5; ++i) {
        pkt.push_back(std::byte{0x3f});  // label length 63
        for (int j = 0; j < 63; ++j) pkt.push_back(std::byte{'a'});
    }
    pkt.push_back(std::byte{0x00});       // terminator (unreached)
    // trailing qtype/qclass for shape; parser should throw before reading.
    for (int i = 0; i < 4; ++i) pkt.push_back(std::byte{0x00});
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, PointerOutOfBoundsThrows) {
    auto pkt = make_header(1);
    pkt.push_back(std::byte{0xc0});   // pointer
    pkt.push_back(std::byte{0xff});   // target offset 255 (> packet size)
    // Pad out to 40 bytes so the packet is larger than the header but
    // smaller than the pointer target.
    while (pkt.size() < 40) pkt.push_back(std::byte{0x00});
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, PointerLoopThrows) {
    // offset 12: pointer to offset 14
    // offset 14: pointer to offset 12
    auto pkt = make_header(1);
    pkt.push_back(std::byte{0xc0}); pkt.push_back(std::byte{0x0e}); // -> 14
    pkt.push_back(std::byte{0xc0}); pkt.push_back(std::byte{0x0c}); // -> 12
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}

TEST(DnsParser, TruncatedRdataThrows) {
    // Header: QDCOUNT=0, ANCOUNT=1.
    auto pkt = make_header(0, 1);
    pkt.push_back(std::byte{0x00});   // RR NAME = root
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x01}); // TYPE=A
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x01}); // CLASS=IN
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x00});
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x3c}); // TTL=60
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x04}); // RDLEN=4
    pkt.push_back(std::byte{0x01}); pkt.push_back(std::byte{0x02}); // only 2 bytes
    EXPECT_THROW(parse(std::span<const std::byte>{pkt.data(), pkt.size()}),
                 ParseError);
}
