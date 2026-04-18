#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "fixtures.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <span>

using namespace cloak;
using namespace cloak::fixtures;

namespace {

template <size_t N>
std::span<const std::byte> as_span(const std::array<std::byte, N>& a) {
    return std::span<const std::byte>{a.data(), a.size()};
}

std::span<const std::byte> as_span(const std::vector<std::byte>& v) {
    return std::span<const std::byte>{v.data(), v.size()};
}

} // namespace

// ---- parser extension ----

TEST(DnsParser, QuestionSectionEndOffset) {
    // kExampleQueryEdns: 12 header + 13 name ("example.com") + 4 qtype+qclass = 29
    auto msg = parse(as_span(kExampleQueryEdns));
    EXPECT_EQ(msg.question_section_end, 29u);
}

// ---- block A response ----

TEST(DnsWriter, BlockResponseIdPreserved) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    auto reparsed = parse(as_span(resp));
    EXPECT_EQ(reparsed.header.id, parsed.header.id);
}

TEST(DnsWriter, BlockResponseFlags) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    auto r = parse(as_span(resp));
    EXPECT_TRUE(r.header.qr);
    EXPECT_TRUE(r.header.ra);
    EXPECT_EQ(r.header.rd, parsed.header.rd);   // mirrored
    EXPECT_FALSE(r.header.aa);
    EXPECT_FALSE(r.header.tc);
    EXPECT_EQ(r.header.opcode, 0);
    EXPECT_EQ(r.header.rcode, 0);
}

TEST(DnsWriter, BlockResponseCounts) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    auto r = parse(as_span(resp));
    EXPECT_EQ(r.header.qdcount, 1);
    EXPECT_EQ(r.header.ancount, 1);
    EXPECT_EQ(r.header.nscount, 0);
    EXPECT_EQ(r.header.arcount, 0);
}

TEST(DnsWriter, BlockResponseQuestionEchoed) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    auto r = parse(as_span(resp));
    ASSERT_EQ(r.questions.size(), 1u);
    EXPECT_EQ(r.questions[0].qname, "example.com");
    EXPECT_EQ(r.questions[0].qtype, 1);
    EXPECT_EQ(r.questions[0].qclass, 1);
}

TEST(DnsWriter, BlockResponseAnswerRecord) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    auto r = parse(as_span(resp));
    ASSERT_EQ(r.answers.size(), 1u);
    const auto& a = r.answers[0];
    EXPECT_EQ(a.name, "example.com");          // proves 0xc00c resolved
    EXPECT_EQ(a.type, 1);                       // A
    EXPECT_EQ(a.rclass, 1);                     // IN
    EXPECT_EQ(a.ttl, 300u);
    ASSERT_EQ(a.rdata.size(), 4u);
    for (size_t i = 0; i < 4; ++i)
        EXPECT_EQ(std::to_integer<uint8_t>(a.rdata[i]), 0);
}

TEST(DnsWriter, BlockResponseLength) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_block_a_response(q, parsed);
    // question_section_end + 16 bytes for the A record.
    EXPECT_EQ(resp.size(), parsed.question_section_end + 16);
}

// ---- REFUSED response ----

TEST(DnsWriter, RefusedResponseRcode) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_refused_response(q, parsed);
    auto r = parse(as_span(resp));
    EXPECT_EQ(r.header.rcode, 5);
    EXPECT_TRUE(r.header.qr);
    EXPECT_TRUE(r.header.ra);
}

TEST(DnsWriter, RefusedResponseNoAnswers) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_refused_response(q, parsed);
    auto r = parse(as_span(resp));
    EXPECT_EQ(r.header.ancount, 0);
    EXPECT_EQ(r.header.nscount, 0);
    EXPECT_EQ(r.header.arcount, 0);
    EXPECT_TRUE(r.answers.empty());
}

TEST(DnsWriter, RefusedResponseQuestionEchoed) {
    auto q = as_span(kExampleQueryEdns);
    auto parsed = parse(q);
    auto resp = build_refused_response(q, parsed);
    auto r = parse(as_span(resp));
    ASSERT_EQ(r.questions.size(), 1u);
    EXPECT_EQ(r.questions[0].qname, "example.com");
    // Exact byte length: header (12) + question_section_end - 12 = question_section_end.
    EXPECT_EQ(resp.size(), parsed.question_section_end);
}
