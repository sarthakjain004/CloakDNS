// Resolver Module unit tests. Exercise retry, RFC 5452 ID + question
// match, and EDNS0 padding via fake Adapters — no network required.

#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/resolver.hpp"
#include "cloakdns/aliases.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using cloak::resolver::Adapter;
using cloak::resolver::AdapterPtr;
using cloak::resolver::ForwardResult;
using cloak::resolver::Resolver;
using cloak::resolver::UpstreamReply;

namespace {

// Records every try_once call and returns scripted replies. nullopt in
// the script = simulate a timeout / transport failure for that try.
class FakeAdapter final : public Adapter {
public:
    struct Call {
        vector<byte>          outbound;
        chrono::milliseconds  timeout;
    };

    FakeAdapter(string label, std::deque<optional<UpstreamReply>> script)
        : label_{std::move(label)}, script_{std::move(script)} {}

    asio::awaitable<optional<UpstreamReply>>
        try_once(span<const byte> outbound,
                 chrono::milliseconds timeout) override {
        calls_.push_back(Call{
            .outbound = vector<byte>(outbound.begin(), outbound.end()),
            .timeout  = timeout,
        });
        if (script_.empty()) co_return std::nullopt;
        auto next = std::move(script_.front());
        script_.pop_front();
        co_return next;
    }

    string_view label() const noexcept override { return label_; }

    const vector<Call>& calls() const { return calls_; }

private:
    string                              label_;
    std::deque<optional<UpstreamReply>> script_;
    vector<Call>                        calls_;
};

// Capture the transaction ID the Resolver wrote into the outbound bytes.
uint16_t read_id(span<const byte> b) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(std::to_integer<uint8_t>(b[0])) << 8) |
         static_cast<uint16_t>(std::to_integer<uint8_t>(b[1])));
}

// Run a single Resolver::forward to completion on a fresh io_context.
vector<byte> run_forward(Resolver& r, span<const byte> q) {
    asio::io_context ctx;
    optional<vector<byte>> out;
    optional<std::exception_ptr> err;
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        try {
            out = co_await r.forward(q);
        } catch (...) {
            err = std::current_exception();
        }
        co_return;
    }, asio::detached);
    ctx.run();
    if (err) std::rethrow_exception(*err);
    return std::move(*out);
}

} // namespace

TEST(Resolver, RetriesPrimaryOnTimeoutThenSucceeds) {
    auto query = cloak::build_a_query("example.com", 0xbeef);

    // Primary times out 3x (initial + 2 retries). Fallback mirrors the
    // random our_id back so RFC 5452 ID match passes.
    auto primary = std::make_unique<FakeAdapter>("primary", std::deque<optional<UpstreamReply>>{
        std::nullopt, std::nullopt, std::nullopt,
    });

    // Fallback adapter that returns a reply matching whatever id arrives.
    class MirrorAdapter final : public Adapter {
    public:
        asio::awaitable<optional<UpstreamReply>>
            try_once(span<const byte> outbound,
                     chrono::milliseconds) override {
            const uint16_t id = static_cast<uint16_t>(
                (static_cast<uint16_t>(std::to_integer<uint8_t>(outbound[0])) << 8) |
                 static_cast<uint16_t>(std::to_integer<uint8_t>(outbound[1])));
            auto reply = cloak::build_a_query("example.com", id);
            // Set QR=1 so it parses as a response.
            reply[2] = byte{static_cast<uint8_t>(
                std::to_integer<uint8_t>(reply[2]) | 0x80)};
            ++calls_;
            co_return UpstreamReply{.bytes = std::move(reply)};
        }
        string_view label() const noexcept override { return "mirror"; }
        int calls_{0};
    };

    auto fallback_owned = std::make_unique<MirrorAdapter>();
    auto* fallback_ptr  = fallback_owned.get();

    vector<AdapterPtr> adapters;
    adapters.push_back(std::move(primary));
    adapters.push_back(std::move(fallback_owned));

    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{
        .timeout            = 50ms,
        .retries_on_primary = 2,
        .padding_block_size = 0,  // disable padding — keeps outbound==query
    }, std::move(adapters)};

    auto out = run_forward(resolver, query);

    // Reply id should be restored to client's id (0xbeef).
    ASSERT_GE(out.size(), 12u);
    EXPECT_EQ(read_id(out), 0xbeef);
    // Fallback should have been called once after primary's 3 attempts.
    EXPECT_EQ(fallback_ptr->calls_, 1);
}

TEST(Resolver, RejectsReplyWithMismatchedId) {
    auto query = cloak::build_a_query("example.com", 0xcafe);

    // Stage one reply with a deliberately wrong id (0x0000 will not match
    // the random our_id with overwhelming probability).
    vector<byte> bad_reply = cloak::build_a_query("example.com", 0x0000);
    bad_reply[2] = byte{static_cast<uint8_t>(
        std::to_integer<uint8_t>(bad_reply[2]) | 0x80)};

    auto adapter = std::make_unique<FakeAdapter>("bad", std::deque<optional<UpstreamReply>>{
        UpstreamReply{.bytes = bad_reply},     // wrong id → rejected
        UpstreamReply{.bytes = bad_reply},     // wrong id again
    });

    vector<AdapterPtr> adapters;
    adapters.push_back(std::move(adapter));

    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{
        .timeout            = 50ms,
        .retries_on_primary = 1,
        .padding_block_size = 0,
    }, std::move(adapters)};

    EXPECT_THROW(run_forward(resolver, query), std::runtime_error);
}

TEST(Resolver, RejectsReplyWithMismatchedQuestion) {
    auto query = cloak::build_a_query("example.com", 0x1111);

    class WrongQnameAdapter final : public Adapter {
    public:
        asio::awaitable<optional<UpstreamReply>>
            try_once(span<const byte> outbound,
                     chrono::milliseconds) override {
            const uint16_t id = static_cast<uint16_t>(
                (static_cast<uint16_t>(std::to_integer<uint8_t>(outbound[0])) << 8) |
                 static_cast<uint16_t>(std::to_integer<uint8_t>(outbound[1])));
            // Reply mirrors the id but answers a DIFFERENT question.
            auto reply = cloak::build_a_query("evil.example.com", id);
            reply[2] = byte{static_cast<uint8_t>(
                std::to_integer<uint8_t>(reply[2]) | 0x80)};
            co_return UpstreamReply{.bytes = std::move(reply)};
        }
        string_view label() const noexcept override { return "wrong-q"; }
    };

    vector<AdapterPtr> adapters;
    adapters.push_back(std::make_unique<WrongQnameAdapter>());
    adapters.push_back(std::make_unique<WrongQnameAdapter>());

    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{
        .timeout            = 50ms,
        .retries_on_primary = 1,
        .padding_block_size = 0,
    }, std::move(adapters)};

    // Both adapters return a wrong-question reply → all exhausted.
    EXPECT_THROW(run_forward(resolver, query), std::runtime_error);
}

TEST(Resolver, AppliesEdns0PaddingExactlyOnce) {
    auto query = cloak::build_a_query("example.com", 0x2222);
    const size_t orig_len = query.size();

    // Capture the outbound size on every attempt to confirm padding is
    // applied once and reused (same length for all attempts).
    class CaptureAdapter final : public Adapter {
    public:
        asio::awaitable<optional<UpstreamReply>>
            try_once(span<const byte> outbound,
                     chrono::milliseconds) override {
            sizes.push_back(outbound.size());
            co_return std::nullopt;   // force retry / fallback
        }
        string_view label() const noexcept override { return "cap"; }
        vector<size_t> sizes;
    };

    auto cap_owned = std::make_unique<CaptureAdapter>();
    auto* cap_ptr  = cap_owned.get();

    vector<AdapterPtr> adapters;
    adapters.push_back(std::move(cap_owned));

    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{
        .timeout            = 50ms,
        .retries_on_primary = 2,            // expect 3 outbound attempts
        .padding_block_size = 128,
    }, std::move(adapters)};

    EXPECT_THROW(run_forward(resolver, query), std::runtime_error);

    ASSERT_EQ(cap_ptr->sizes.size(), 3u);
    // Padded length must be a multiple of 128 and >= orig_len.
    EXPECT_EQ(cap_ptr->sizes[0] % 128, 0u);
    EXPECT_GE(cap_ptr->sizes[0], orig_len);
    // All retries see the same outbound length — pad applied once.
    EXPECT_EQ(cap_ptr->sizes[0], cap_ptr->sizes[1]);
    EXPECT_EQ(cap_ptr->sizes[1], cap_ptr->sizes[2]);
}

TEST(Resolver, PaddingDisabledForwardsOriginalLength) {
    auto query = cloak::build_a_query("example.com", 0x3333);
    const size_t orig_len = query.size();

    class CaptureAdapter final : public Adapter {
    public:
        asio::awaitable<optional<UpstreamReply>>
            try_once(span<const byte> outbound,
                     chrono::milliseconds) override {
            captured_size = outbound.size();
            co_return std::nullopt;
        }
        string_view label() const noexcept override { return "cap"; }
        size_t captured_size{0};
    };

    auto cap_owned = std::make_unique<CaptureAdapter>();
    auto* cap_ptr  = cap_owned.get();

    vector<AdapterPtr> adapters;
    adapters.push_back(std::move(cap_owned));

    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{
        .timeout            = 50ms,
        .retries_on_primary = 0,
        .padding_block_size = 0,    // padding off → outbound == original
    }, std::move(adapters)};

    EXPECT_THROW(run_forward(resolver, query), std::runtime_error);
    EXPECT_EQ(cap_ptr->captured_size, orig_len);
}

TEST(Resolver, ThrowsOnQueryShorterThanHeader) {
    vector<AdapterPtr> adapters;
    adapters.push_back(std::make_unique<FakeAdapter>("dummy", std::deque<optional<UpstreamReply>>{}));
    asio::io_context ctx;
    Resolver resolver{ctx, Resolver::Config{}, std::move(adapters)};

    vector<byte> tiny(5);   // < 12-byte header
    EXPECT_THROW(run_forward(resolver, tiny), std::runtime_error);
}

TEST(Resolver, RejectsConstructionWithNoAdapters) {
    asio::io_context ctx;
    EXPECT_THROW(
        Resolver(ctx, Resolver::Config{}, vector<AdapterPtr>{}),
        std::invalid_argument);
}
