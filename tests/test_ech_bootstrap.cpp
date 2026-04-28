// Unit tests for the SVCB / HTTPS-RR rdata parser used by the ECH
// auto-bootstrap path. We only need to extract the ech= SvcParam (key 5)
// from a single ServiceMode record — the parser deliberately rejects
// AliasMode and compressed TargetNames.
//
// Test fixtures use hand-built byte sequences that mirror the wire
// format described in RFC 9460 §2.2:
//   SvcPriority (u16 BE)   — 0 = AliasMode, >0 = ServiceMode
//   TargetName  (DNS name) — 0x00 means "use the queried name"
//   SvcParams*  (key u16 BE | value-len u16 BE | value bytes)

#include "cloakdns/ech_bootstrap.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

void push_u16_be(std::vector<std::byte>& v, std::uint16_t x) {
    v.push_back(std::byte{static_cast<std::uint8_t>((x >> 8) & 0xff)});
    v.push_back(std::byte{static_cast<std::uint8_t>(x & 0xff)});
}

void push_byte(std::vector<std::byte>& v, std::uint8_t x) {
    v.push_back(std::byte{x});
}

void push_param(std::vector<std::byte>& v, std::uint16_t key,
                std::initializer_list<std::uint8_t> value) {
    push_u16_be(v, key);
    push_u16_be(v, static_cast<std::uint16_t>(value.size()));
    for (auto b : value) push_byte(v, b);
}

} // namespace

TEST(SvcbExtractEch, ExtractsKeyFiveValue) {
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 1);         // ServiceMode (priority 1)
    push_byte(rdata, 0);           // TargetName = "." (root)
    // alpn (key 1) — the parser must skip past unknown keys
    push_param(rdata, 1, {0x02, 'h', '2'});
    // ech (key 5) — what we want
    push_param(rdata, 5, {0xfe, 0x0d, 0x42, 0xab});
    // ipv4hint (key 4) appearing AFTER ech — parser shouldn't get
    // confused by post-ech params
    push_param(rdata, 4, {0xc0, 0xa8, 0x01, 0x01});

    auto out = cloak::svcb_extract_ech(rdata);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(out->size(), 4u);
    EXPECT_EQ(std::to_integer<std::uint8_t>((*out)[0]), 0xfeu);
    EXPECT_EQ(std::to_integer<std::uint8_t>((*out)[1]), 0x0du);
    EXPECT_EQ(std::to_integer<std::uint8_t>((*out)[2]), 0x42u);
    EXPECT_EQ(std::to_integer<std::uint8_t>((*out)[3]), 0xabu);
}

TEST(SvcbExtractEch, RejectsAliasMode) {
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 0);         // AliasMode (priority 0)
    push_byte(rdata, 0);           // TargetName = "."
    push_param(rdata, 5, {0xfe, 0x0d});

    EXPECT_FALSE(cloak::svcb_extract_ech(rdata).has_value());
}

TEST(SvcbExtractEch, ReturnsNulloptWhenNoEchParam) {
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 1);
    push_byte(rdata, 0);
    push_param(rdata, 1, {0x02, 'h', '2'});
    push_param(rdata, 4, {0xc0, 0xa8, 0x01, 0x01});

    EXPECT_FALSE(cloak::svcb_extract_ech(rdata).has_value());
}

TEST(SvcbExtractEch, RejectsCompressedTargetName) {
    // A pointer label has the top two bits set (0xc0 / 0xc1 etc.). We
    // don't follow pointers — bail out.
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 1);
    push_byte(rdata, 0xc0);        // pointer high byte
    push_byte(rdata, 0x0c);        // offset
    push_param(rdata, 5, {0xfe, 0x0d});

    EXPECT_FALSE(cloak::svcb_extract_ech(rdata).has_value());
}

TEST(SvcbExtractEch, RejectsTruncatedParamLength) {
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 1);
    push_byte(rdata, 0);
    // Claim 8 bytes of value but only emit 2 — the parser must refuse.
    push_u16_be(rdata, 5);
    push_u16_be(rdata, 8);
    push_byte(rdata, 0xfe);
    push_byte(rdata, 0x0d);

    EXPECT_FALSE(cloak::svcb_extract_ech(rdata).has_value());
}

TEST(SvcbExtractEch, EmptyRdataIsNullopt) {
    std::vector<std::byte> rdata;
    EXPECT_FALSE(cloak::svcb_extract_ech(rdata).has_value());
}

TEST(SvcbExtractEch, ExtractsWithSimpleTargetName) {
    // TargetName = "alt.example." — three labels, then root terminator.
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 1);
    // "alt"
    push_byte(rdata, 3); push_byte(rdata, 'a'); push_byte(rdata, 'l'); push_byte(rdata, 't');
    // "example"
    push_byte(rdata, 7);
    for (char c : std::string{"example"}) push_byte(rdata, static_cast<std::uint8_t>(c));
    // root terminator
    push_byte(rdata, 0);
    push_param(rdata, 5, {0x99});

    auto out = cloak::svcb_extract_ech(rdata);
    ASSERT_TRUE(out.has_value());
    ASSERT_EQ(out->size(), 1u);
    EXPECT_EQ(std::to_integer<std::uint8_t>((*out)[0]), 0x99u);
}
