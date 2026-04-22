#include "cloakdns/cache.hpp"
#include "cloakdns/dns_parser.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

using namespace std::chrono_literals;

namespace {

constexpr uint16_t kTypeA     = cloak::dns_type::A;
constexpr uint16_t kTypeCNAME = cloak::dns_type::CNAME;

void put_u16_be(std::vector<std::byte>& out, size_t off, uint16_t v) {
    out[off]     = std::byte{static_cast<uint8_t>(v >> 8)};
    out[off + 1] = std::byte{static_cast<uint8_t>(v & 0xff)};
}

void append_labels(std::vector<std::byte>& out, std::string_view name) {
    size_t start = 0;
    for (size_t i = 0; i <= name.size(); ++i) {
        if (i == name.size() || name[i] == '.') {
            const auto len = static_cast<uint8_t>(i - start);
            out.push_back(std::byte{len});
            for (size_t j = start; j < i; ++j)
                out.push_back(std::byte{static_cast<uint8_t>(name[j])});
            start = i + 1;
        }
    }
    out.push_back(std::byte{0});
}

struct Rr {
    std::string name;
    uint16_t type;
    uint32_t ttl;
    std::variant<std::array<uint8_t, 4>, std::string> rdata;
};

std::vector<std::byte>
build_response(uint16_t id, uint8_t rcode, std::string_view qname,
               const std::vector<Rr>& answers,
               const std::vector<Rr>& authority = {}) {
    std::vector<std::byte> out;
    out.resize(12);
    put_u16_be(out, 0, id);
    put_u16_be(out, 2, static_cast<uint16_t>(0x8180 | (rcode & 0x0f)));
    put_u16_be(out, 4, 1);
    put_u16_be(out, 6, static_cast<uint16_t>(answers.size()));
    put_u16_be(out, 8, static_cast<uint16_t>(authority.size()));
    put_u16_be(out, 10, 0);

    append_labels(out, qname);
    out.push_back(std::byte{0}); out.push_back(std::byte{1});
    out.push_back(std::byte{0}); out.push_back(std::byte{1});

    auto emit = [&](const std::vector<Rr>& section) {
        for (const auto& r : section) {
            append_labels(out, r.name);
            out.push_back(std::byte{static_cast<uint8_t>(r.type >> 8)});
            out.push_back(std::byte{static_cast<uint8_t>(r.type & 0xff)});
            out.push_back(std::byte{0}); out.push_back(std::byte{1});
            out.push_back(std::byte{static_cast<uint8_t>(r.ttl >> 24)});
            out.push_back(std::byte{static_cast<uint8_t>(r.ttl >> 16)});
            out.push_back(std::byte{static_cast<uint8_t>(r.ttl >>  8)});
            out.push_back(std::byte{static_cast<uint8_t>(r.ttl      )});

            std::vector<std::byte> rdata;
            if (const auto* ip = std::get_if<std::array<uint8_t, 4>>(&r.rdata)) {
                for (uint8_t b : *ip) rdata.push_back(std::byte{b});
            } else {
                append_labels(rdata, std::get<std::string>(r.rdata));
            }
            out.push_back(std::byte{static_cast<uint8_t>(rdata.size() >> 8)});
            out.push_back(std::byte{static_cast<uint8_t>(rdata.size() & 0xff)});
            for (auto b : rdata) out.push_back(b);
        }
    };
    emit(answers);
    emit(authority);
    return out;
}

std::array<uint8_t, 4> ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return {a, b, c, d};
}

cloak::CacheKey key_for(std::string_view qname) {
    return cloak::CacheKey{std::string{qname}, kTypeA, 1};
}

cloak::DnsMessage parse_bytes(const std::vector<std::byte>& bytes) {
    return cloak::parse(std::span<const std::byte>{bytes});
}

} // namespace

// ---------- make_cache_key ----------

TEST(CacheKey, MakeKeyFromSingleQuestion) {
    auto bytes = build_response(
        0xaa, 0, "foo.example", {{"foo.example", kTypeA, 60, ip(1, 2, 3, 4)}});
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    auto k = cloak::make_cache_key(msg);
    ASSERT_TRUE(k.has_value());
    EXPECT_EQ(k->qname, "foo.example");
    EXPECT_EQ(k->qtype, kTypeA);
    EXPECT_EQ(k->qclass, 1u);
}

// ---------- compute_cache_ttl ----------

TEST(ComputeCacheTtl, MinOfAnswerTtls) {
    auto bytes = build_response(0, 0, "foo.example", {
        {"foo.example", kTypeCNAME, 200, std::string{"bar.example"}},
        {"bar.example", kTypeA,      60, ip(1, 2, 3, 4)},
    });
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    EXPECT_EQ(cloak::compute_cache_ttl(msg).count(), 60);
}

TEST(ComputeCacheTtl, TtlZeroMeansNoCache) {
    auto bytes = build_response(0, 0, "foo.example", {
        {"foo.example", kTypeA, 0, ip(1, 2, 3, 4)},
    });
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    EXPECT_EQ(cloak::compute_cache_ttl(msg).count(), 0);
}

TEST(ComputeCacheTtl, NoAnswersReturnsZero) {
    auto bytes = build_response(0, 0, "foo.example", {});
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    EXPECT_EQ(cloak::compute_cache_ttl(msg).count(), 0);
}

TEST(ComputeCacheTtl, ServfailNotCacheable) {
    auto bytes = build_response(0, /*rcode=*/2, "foo.example", {
        {"foo.example", kTypeA, 60, ip(1, 2, 3, 4)},
    });
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    EXPECT_EQ(cloak::compute_cache_ttl(msg).count(), 0);
}

TEST(ComputeCacheTtl, AuthorityTtlCountsForNegativeCache) {
    auto bytes = build_response(0, /*rcode=*/0, "foo.example", {}, {
        {"example", /*type=*/6 /*SOA*/, 900, std::string{"ns.example"}},
    });
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    EXPECT_EQ(cloak::compute_cache_ttl(msg).count(), 900);
}

// ---------- collect_ttl_offsets + rewrite_ttls ----------

TEST(TtlRewrite, ParsedResponseShowsNewTtls) {
    auto bytes = build_response(0x1234, 0, "foo.example", {
        {"foo.example", kTypeCNAME, 500, std::string{"bar.example"}},
        {"bar.example", kTypeA,     500, ip(10, 0, 0, 1)},
    });
    auto msg = cloak::parse(std::span<const std::byte>{bytes});
    auto offsets = cloak::collect_ttl_offsets(bytes, msg);
    EXPECT_EQ(offsets.size(), 2u);

    auto copy = bytes;
    cloak::rewrite_ttls(std::span<std::byte>{copy}, offsets, /*ttl=*/42);
    auto reparsed = cloak::parse(std::span<const std::byte>{copy});
    ASSERT_EQ(reparsed.answers.size(), 2u);
    EXPECT_EQ(reparsed.answers[0].ttl, 42u);
    EXPECT_EQ(reparsed.answers[1].ttl, 42u);
}

// ---------- DnsCache insert + lookup ----------

TEST(DnsCache, InsertLookupRoundTrip) {
    cloak::DnsCache cache;
    auto bytes = build_response(0xaaaa, 0, "foo.example", {
        {"foo.example", kTypeA, 300, ip(1, 2, 3, 4)},
    });
    auto parsed = parse_bytes(bytes);
    cache.insert(key_for("foo.example"), bytes, parsed, 300s);
    auto hit = cache.lookup(key_for("foo.example"), /*client_id=*/0xbeef);
    ASSERT_TRUE(hit.has_value());
    auto msg = cloak::parse(std::span<const std::byte>{*hit});
    EXPECT_EQ(msg.header.id, 0xbeef);  // lookup rewrote id to client's
    ASSERT_EQ(msg.answers.size(), 1u);
    EXPECT_LE(msg.answers[0].ttl, 300u);
    EXPECT_GT(msg.answers[0].ttl, 295u);  // ~300s minus test wall time
}

TEST(DnsCache, MissReturnsNullopt) {
    cloak::DnsCache cache;
    EXPECT_FALSE(cache.lookup(key_for("nothing.example"), 0).has_value());
}

TEST(DnsCache, TtlZeroSkipsInsert) {
    cloak::DnsCache cache;
    auto bytes = build_response(0, 0, "foo.example", {
        {"foo.example", kTypeA, 1, ip(1, 2, 3, 4)},
    });
    auto parsed = parse_bytes(bytes);
    cache.insert(key_for("foo.example"), bytes, parsed, 0s);
    EXPECT_FALSE(cache.lookup(key_for("foo.example"), 0).has_value());
    EXPECT_EQ(cache.size(), 0u);
}

TEST(DnsCache, ExpiredEntryReturnsNullopt) {
    cloak::DnsCache::Config cfg;
    cfg.sweep_interval = 1h;  // effectively disable background sweeper during this test
    cloak::DnsCache cache{cfg};

    auto bytes = build_response(0, 0, "foo.example", {
        {"foo.example", kTypeA, 1, ip(1, 2, 3, 4)},
    });
    auto parsed = parse_bytes(bytes);
    // Use a sub-second chrono TTL; our `insert` takes seconds, so
    // instead insert with ttl=1s and then sleep a little past it.
    cache.insert(key_for("foo.example"), bytes, parsed, 1s);
    EXPECT_TRUE(cache.lookup(key_for("foo.example"), 0).has_value());
    std::this_thread::sleep_for(1100ms);
    EXPECT_FALSE(cache.lookup(key_for("foo.example"), 0).has_value());
}

TEST(DnsCache, SweepRemovesExpired) {
    cloak::DnsCache::Config cfg;
    cfg.sweep_interval = 1h;  // manual sweep only
    cloak::DnsCache cache{cfg};

    auto bytes = build_response(0, 0, "a.example", {
        {"a.example", kTypeA, 1, ip(1, 2, 3, 4)},
    });
    auto parsed = parse_bytes(bytes);
    cache.insert(key_for("a.example"), bytes, parsed, 1s);
    EXPECT_EQ(cache.size(), 1u);
    std::this_thread::sleep_for(1100ms);
    EXPECT_EQ(cache.sweep_expired(), 1u);
    EXPECT_EQ(cache.size(), 0u);
}

TEST(DnsCache, LookupRewritesTtlToRemaining) {
    cloak::DnsCache cache;
    auto bytes = build_response(0, 0, "foo.example", {
        {"foo.example", kTypeA, 1000, ip(1, 2, 3, 4)},
    });
    auto parsed = parse_bytes(bytes);
    cache.insert(key_for("foo.example"), bytes, parsed, 1000s);

    auto hit = cache.lookup(key_for("foo.example"), 0);
    ASSERT_TRUE(hit.has_value());
    auto msg = cloak::parse(std::span<const std::byte>{*hit});
    ASSERT_EQ(msg.answers.size(), 1u);
    // Remaining TTL must be <= inserted TTL (can't exceed) and close to it.
    EXPECT_LE(msg.answers[0].ttl, 1000u);
    EXPECT_GT(msg.answers[0].ttl, 995u);
}

TEST(DnsCache, MaxEntriesCapRespected) {
    cloak::DnsCache::Config cfg;
    cfg.max_entries = 2;
    cfg.sweep_interval = 1h;
    cloak::DnsCache cache{cfg};

    auto mk = [](std::string_view name) {
        auto b = build_response(0, 0, name,
            {{std::string{name}, kTypeA, 300, ip(1, 2, 3, 4)}});
        return std::pair{b, parse_bytes(b)};
    };

    {
        auto [a, ap] = mk("a.example");
        cache.insert(key_for("a.example"), a, ap, 300s);
    }
    {
        auto [b, bp] = mk("b.example");
        cache.insert(key_for("b.example"), b, bp, 300s);
    }
    {
        auto [c, cp] = mk("c.example");
        cache.insert(key_for("c.example"), c, cp, 300s);  // refused: full
    }
    EXPECT_EQ(cache.size(), 2u);
    EXPECT_TRUE(cache.lookup(key_for("a.example"), 0).has_value());
    EXPECT_TRUE(cache.lookup(key_for("b.example"), 0).has_value());
    EXPECT_FALSE(cache.lookup(key_for("c.example"), 0).has_value());
}

// ---------- apply_jitter ----------

TEST(ApplyJitter, ZeroMaxIsNoop) {
    asio::io_context ctx;
    bool done = false;
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        co_await cloak::apply_jitter(0ms);
        done = true;
    }(), asio::detached);
    ctx.run();
    EXPECT_TRUE(done);
}

TEST(ApplyJitter, NonZeroMaxSleepsWithinBound) {
    asio::io_context ctx;
    auto t0 = std::chrono::steady_clock::now();
    asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
        co_await cloak::apply_jitter(20ms);
    }(), asio::detached);
    ctx.run();
    auto elapsed = std::chrono::steady_clock::now() - t0;
    // Sanity bound: ~5x the max jitter accommodates Windows timer
    // resolution and coroutine scheduling. Catches "slept forever" bugs.
    EXPECT_LT(elapsed, 100ms);
}

// Guards against a silent no-op regression: across many samples at
// least one should land on a delay observable above timer resolution.
TEST(ApplyJitter, ActuallySleepsSomeOfTheTime) {
    asio::io_context ctx;
    bool observed_delay = false;
    for (int i = 0; i < 50; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        asio::co_spawn(ctx, [&]() -> asio::awaitable<void> {
            co_await cloak::apply_jitter(20ms);
        }(), asio::detached);
        ctx.run();
        ctx.restart();
        if (std::chrono::steady_clock::now() - t0 >= 1ms) {
            observed_delay = true;
            break;
        }
    }
    EXPECT_TRUE(observed_delay);
}
