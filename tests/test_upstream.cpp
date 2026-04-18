#include "cloakdns/upstream.hpp"

#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::make_address;
using asio::ip::udp;
using namespace std::chrono_literals;

namespace {

// Build a minimal 29-byte A-query for example.com with the given ID.
std::vector<std::byte> make_query(uint16_t id) {
    std::vector<std::byte> q = {
        std::byte{uint8_t(id >> 8)}, std::byte{uint8_t(id & 0xff)},
        std::byte{0x01}, std::byte{0x00},  // flags: RD=1
        std::byte{0x00}, std::byte{0x01},  // QDCOUNT=1
        std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0x00}, std::byte{0x00},
        std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
        std::byte{'m'},  std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
        std::byte{0x03}, std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
        std::byte{0x00},                   // terminator
        std::byte{0x00}, std::byte{0x01},  // QTYPE=A
        std::byte{0x00}, std::byte{0x01}   // QCLASS=IN
    };
    return q;
}

// Starts a coroutine that reads one packet on `fake`, optionally mutates
// it (flipping QR and setting RA) or overriding the id, and sends it
// back. `captured_id` is set to the id seen on the wire (from us).
void fake_responder(udp::socket& fake,
                    std::atomic<uint16_t>& captured_id,
                    std::optional<uint16_t> override_id = std::nullopt) {
    auto buf = std::make_shared<std::array<std::byte, 4096>>();
    auto from = std::make_shared<udp::endpoint>();
    fake.async_receive_from(asio::buffer(*buf), *from,
        [&, buf, from, override_id](std::error_code ec, std::size_t n) {
            if (ec) return;
            captured_id = static_cast<uint16_t>(
                (uint16_t(std::to_integer<uint8_t>((*buf)[0])) << 8) |
                 uint16_t(std::to_integer<uint8_t>((*buf)[1])));
            if (override_id) {
                (*buf)[0] = std::byte{uint8_t((*override_id) >> 8)};
                (*buf)[1] = std::byte{uint8_t((*override_id) & 0xff)};
            }
            // Flip QR and set RA to look like a response.
            const uint8_t f0 = std::to_integer<uint8_t>((*buf)[2]);
            (*buf)[2] = std::byte{uint8_t(f0 | 0x80)};
            const uint8_t f1 = std::to_integer<uint8_t>((*buf)[3]);
            (*buf)[3] = std::byte{uint8_t(f1 | 0x80)};
            fake.async_send_to(
                asio::buffer(buf->data(), n), *from,
                [buf](std::error_code, std::size_t) {});
        });
}

} // namespace

TEST(Upstream, SuccessPathSwapsIdBack) {
    asio::io_context ctx;
    udp::socket fake{ctx, udp::endpoint(make_address("127.0.0.1"), 0)};
    auto fake_ep = fake.local_endpoint();

    std::atomic<uint16_t> captured_id{0};
    fake_responder(fake, captured_id);

    cloak::UpstreamForwarder fwd{ctx, cloak::UpstreamForwarder::Config{
        .servers = {fake_ep},
        .timeout = 500ms,
        .retries_on_primary = 0,
    }};

    constexpr uint16_t kClientId = 0xabcd;
    auto query = make_query(kClientId);

    std::optional<std::vector<std::byte>> result;
    std::optional<std::string> error;
    co_spawn(ctx, [&]() -> awaitable<void> {
        try { result = co_await fwd.forward(query); }
        catch (const std::exception& e) { error = e.what(); }
    }(), detached);
    ctx.run();

    ASSERT_TRUE(result.has_value()) << (error ? *error : std::string{"?"});
    ASSERT_GE(result->size(), 2u);
    // ID swapped back to client's value.
    EXPECT_EQ(std::to_integer<uint8_t>((*result)[0]), 0xab);
    EXPECT_EQ(std::to_integer<uint8_t>((*result)[1]), 0xcd);
    // Upstream observed a different id (collision prob 1/65536).
    EXPECT_NE(captured_id.load(), kClientId);
}

TEST(Upstream, TimeoutThrowsAfterRetries) {
    asio::io_context ctx;
    udp::socket silent{ctx, udp::endpoint(make_address("127.0.0.1"), 0)};
    auto silent_ep = silent.local_endpoint();
    // Don't start any async read — kernel buffers the datagram silently
    // and we timeout.

    cloak::UpstreamForwarder fwd{ctx, cloak::UpstreamForwarder::Config{
        .servers = {silent_ep},
        .timeout = 80ms,
        .retries_on_primary = 1,
    }};

    auto query = make_query(0x1234);

    std::optional<std::string> error;
    co_spawn(ctx, [&]() -> awaitable<void> {
        try { (void)co_await fwd.forward(query); }
        catch (const std::exception& e) { error = e.what(); }
    }(), detached);
    const auto t0 = std::chrono::steady_clock::now();
    ctx.run();
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->find("exhausted"), std::string::npos);
    // Two attempts * 80ms = ~160ms minimum.
    EXPECT_GE(elapsed, 150ms);
}

TEST(Upstream, FailoverToSecondary) {
    asio::io_context ctx;
    udp::socket silent{ctx, udp::endpoint(make_address("127.0.0.1"), 0)};
    auto silent_ep = silent.local_endpoint();
    udp::socket good{ctx, udp::endpoint(make_address("127.0.0.1"), 0)};
    auto good_ep = good.local_endpoint();

    std::atomic<uint16_t> captured_id{0};
    fake_responder(good, captured_id);

    cloak::UpstreamForwarder fwd{ctx, cloak::UpstreamForwarder::Config{
        .servers = {silent_ep, good_ep},
        .timeout = 80ms,
        .retries_on_primary = 0,    // one try on primary, then secondary
    }};

    auto query = make_query(0x5a5a);
    std::optional<std::vector<std::byte>> result;
    std::optional<std::string> error;
    co_spawn(ctx, [&]() -> awaitable<void> {
        try { result = co_await fwd.forward(query); }
        catch (const std::exception& e) { error = e.what(); }
    }(), detached);
    ctx.run();

    ASSERT_TRUE(result.has_value()) << (error ? *error : std::string{"?"});
    EXPECT_EQ(std::to_integer<uint8_t>((*result)[0]), 0x5a);
    EXPECT_EQ(std::to_integer<uint8_t>((*result)[1]), 0x5a);
}

TEST(Upstream, RejectsWrongIdResponse) {
    asio::io_context ctx;
    udp::socket fake{ctx, udp::endpoint(make_address("127.0.0.1"), 0)};
    auto fake_ep = fake.local_endpoint();

    std::atomic<uint16_t> captured_id{0};
    // Override id: fake responds with a canned wrong id — forwarder
    // must reject it and eventually time out.
    fake_responder(fake, captured_id, /*override_id=*/uint16_t{0xdead});

    cloak::UpstreamForwarder fwd{ctx, cloak::UpstreamForwarder::Config{
        .servers = {fake_ep},
        .timeout = 80ms,
        .retries_on_primary = 0,
    }};

    auto query = make_query(0x1111);
    std::optional<std::string> error;
    co_spawn(ctx, [&]() -> awaitable<void> {
        try { (void)co_await fwd.forward(query); }
        catch (const std::exception& e) { error = e.what(); }
    }(), detached);
    ctx.run();

    ASSERT_TRUE(error.has_value());
    EXPECT_NE(error->find("exhausted"), std::string::npos);
}

TEST(Upstream, EmptyServersRejected) {
    asio::io_context ctx;
    EXPECT_THROW(
        (cloak::UpstreamForwarder{ctx, cloak::UpstreamForwarder::Config{}}),
        std::invalid_argument);
}
