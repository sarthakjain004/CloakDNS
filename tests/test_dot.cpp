// DoT framing and forwarder unit tests. The integration test that spins
// up an Asio TLS test server with a self-signed cert lives in a separate
// "online" test file (not added in this PR) — keeping the basic suite
// network-free and deterministic.

#include "cloakdns/upstream.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

// dot_frame is in the cloak::detail namespace — declared here for the
// test rather than exposed in the public header.
namespace cloak::detail {
std::vector<std::byte> dot_frame(std::span<const std::byte> msg);
}

TEST(DotFraming, PrependsTwoByteLengthBigEndian) {
    const std::vector<std::byte> msg(0x1234, std::byte{0x5a});
    const auto framed = cloak::detail::dot_frame(msg);
    ASSERT_EQ(framed.size(), msg.size() + 2u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed[0]), 0x12u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed[1]), 0x34u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed[2]), 0x5au);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed.back()), 0x5au);
}

TEST(DotFraming, EmptyMessageIsLengthZero) {
    const std::vector<std::byte> msg;
    const auto framed = cloak::detail::dot_frame(msg);
    ASSERT_EQ(framed.size(), 2u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed[0]), 0u);
    EXPECT_EQ(std::to_integer<std::uint8_t>(framed[1]), 0u);
}

TEST(DotFraming, RejectsOversizedMessage) {
    const std::vector<std::byte> msg(0x10000, std::byte{0});
    EXPECT_THROW(cloak::detail::dot_frame(msg), std::runtime_error);
}

TEST(DotConfig, ProtocolEnumDefaultsToUdp) {
    cloak::UpstreamForwarder::Config cfg;
    EXPECT_EQ(cfg.protocol, cloak::UpstreamForwarder::Protocol::Udp);
}
