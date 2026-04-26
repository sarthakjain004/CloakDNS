#include "cloakdns/blocklist.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/uncloaker.hpp"
#include "cloakdns/upstream.hpp"

#include <asio/buffer.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>
#include <asio/use_awaitable.hpp>

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::ip::make_address;
using asio::ip::udp;
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

constexpr uint16_t kTypeAAAA = cloak::dns_type::AAAA;

struct Rr {
    std::string name;
    uint16_t type;
    // Either a 4-byte IPv4 address, a 16-byte IPv6 address, or a CNAME
    // target name (plain string).
    std::variant<std::array<uint8_t, 4>,
                 std::array<uint8_t, 16>,
                 std::string> rdata;
};

// Build a DNS response for `qname` (class IN) with the given answer
// records. `qtype` defaults to A; pass kTypeAAAA for IPv6 tests. No
// compression; test fixtures prioritize clarity.
std::vector<std::byte>
build_response(uint16_t id, std::string_view qname,
               const std::vector<Rr>& answers,
               uint16_t qtype = 1) {
    std::vector<std::byte> out;
    out.resize(12);
    put_u16_be(out, 0, id);
    put_u16_be(out, 2, 0x8180);  // QR=1, RD=1, RA=1
    put_u16_be(out, 4, 1);
    put_u16_be(out, 6, static_cast<uint16_t>(answers.size()));
    put_u16_be(out, 8, 0);
    put_u16_be(out, 10, 0);

    append_labels(out, qname);
    out.push_back(std::byte{static_cast<uint8_t>(qtype >> 8)});
    out.push_back(std::byte{static_cast<uint8_t>(qtype & 0xff)});
    out.push_back(std::byte{0}); out.push_back(std::byte{1});   // QCLASS=IN

    for (const auto& a : answers) {
        append_labels(out, a.name);
        out.push_back(std::byte{static_cast<uint8_t>(a.type >> 8)});
        out.push_back(std::byte{static_cast<uint8_t>(a.type & 0xff)});
        out.push_back(std::byte{0}); out.push_back(std::byte{1});  // class IN
        // TTL = 300 (0x0000012c)
        out.push_back(std::byte{0}); out.push_back(std::byte{0});
        out.push_back(std::byte{1}); out.push_back(std::byte{0x2c});

        std::vector<std::byte> rdata;
        if (const auto* ip4 = std::get_if<std::array<uint8_t, 4>>(&a.rdata)) {
            for (uint8_t b : *ip4) rdata.push_back(std::byte{b});
        } else if (const auto* ip6 = std::get_if<std::array<uint8_t, 16>>(&a.rdata)) {
            for (uint8_t b : *ip6) rdata.push_back(std::byte{b});
        } else {
            const auto& target = std::get<std::string>(a.rdata);
            append_labels(rdata, target);
        }

        out.push_back(std::byte{static_cast<uint8_t>(rdata.size() >> 8)});
        out.push_back(std::byte{static_cast<uint8_t>(rdata.size() & 0xff)});
        for (auto b : rdata) out.push_back(b);
    }
    return out;
}

// Fake upstream that responds to incoming queries using staged responses
// keyed by qname. Lifetime: bound to the io_context lifetime.
class FakeUpstream {
public:
    explicit FakeUpstream(asio::io_context& ctx)
        : sock_(ctx, udp::endpoint(make_address("127.0.0.1"), 0)) {
        accept();
    }

    void stage(std::string qname, std::vector<std::byte> response) {
        canned_[std::move(qname)] = std::move(response);
    }

    udp::endpoint endpoint() const { return sock_.local_endpoint(); }

    int queries_served() const { return served_; }

    // Close the listening socket so pending async_receive_from completes
    // with operation_aborted and the io_context can drain.
    void stop() {
        std::error_code ec;
        sock_.close(ec);
    }

private:
    void accept() {
        auto buf  = std::make_shared<std::array<std::byte, 4096>>();
        auto from = std::make_shared<udp::endpoint>();
        sock_.async_receive_from(asio::buffer(*buf), *from,
            [this, buf, from](std::error_code ec, std::size_t n) {
                if (ec) return;
                respond(*buf, n, *from);
                accept();
            });
    }

    void respond(std::array<std::byte, 4096>& buf, std::size_t n,
                 const udp::endpoint& peer) {
        try {
            const auto msg = cloak::parse(
                std::span<const std::byte>{buf.data(), n});
            if (msg.questions.empty()) return;
            const auto it = canned_.find(msg.questions[0].qname);
            if (it == canned_.end()) return;
            // Own the response in a shared_ptr so the async_send_to
            // buffer view stays valid until the completion handler runs.
            auto keepalive = std::make_shared<std::vector<std::byte>>(it->second);
            (*keepalive)[0] = buf[0];
            (*keepalive)[1] = buf[1];
            ++served_;
            sock_.async_send_to(asio::buffer(*keepalive), peer,
                [keepalive](auto, auto) {});
        } catch (...) {
            // Malformed query: silently drop; the upstream forwarder
            // will eventually time out.
        }
    }

    udp::socket sock_;
    std::map<std::string, std::vector<std::byte>> canned_;
    int served_{0};
};

std::array<uint8_t, 4> ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return {a, b, c, d};
}

} // namespace

// ---------- dns_writer::build_a_query ----------

TEST(BuildAQuery, ParsesToExpectedQuestion) {
    auto q = cloak::build_a_query("ads.example.com", 0x1234);
    auto msg = cloak::parse(std::span<const std::byte>{q});
    EXPECT_EQ(msg.header.id, 0x1234);
    EXPECT_TRUE(msg.header.rd);
    EXPECT_FALSE(msg.header.qr);
    ASSERT_EQ(msg.questions.size(), 1u);
    EXPECT_EQ(msg.questions[0].qname, "ads.example.com");
    EXPECT_EQ(msg.questions[0].qtype, 1);
    EXPECT_EQ(msg.questions[0].qclass, 1);
}

TEST(BuildAQuery, RejectsEmpty) {
    EXPECT_THROW(cloak::build_a_query("", 0), std::invalid_argument);
}

TEST(BuildAQuery, RejectsLeadingDot) {
    EXPECT_THROW(cloak::build_a_query(".foo.com", 0), std::invalid_argument);
}

TEST(BuildAQuery, RejectsTrailingDot) {
    EXPECT_THROW(cloak::build_a_query("foo.com.", 0), std::invalid_argument);
}

TEST(BuildAQuery, RejectsOversizedLabel) {
    std::string big(64, 'a');
    std::string name = big + ".com";
    EXPECT_THROW(cloak::build_a_query(name, 0), std::invalid_argument);
}

// ---------- CnameUncloaker ----------

namespace {

struct UncloakFixture {
    asio::io_context ctx;
    FakeUpstream fake{ctx};
    cloak::Blocklist bl;
    std::optional<cloak::UpstreamForwarder> fwd;
    std::optional<cloak::CnameUncloaker> uc;

    UncloakFixture() {
        fwd.emplace(ctx, cloak::UpstreamForwarder::Config{
            .servers = {fake.endpoint()},
            .timeout = 150ms,
            .retries_on_primary = 0,
        });
        uc.emplace(*fwd, bl);
    }

    cloak::UncloakResult run(std::string_view qname,
                             std::span<const std::byte> first) {
        std::optional<cloak::UncloakResult> out;
        co_spawn(ctx, [&]() -> awaitable<void> {
            out = co_await uc->uncloak(qname, first);
            fake.stop();   // release io_context so ctx.run() can return
        }, detached);
        ctx.run();
        ctx.restart();
        return std::move(*out);
    }
};

} // namespace

TEST(CnameUncloaker, CleanAResponseNoChain) {
    UncloakFixture fx;
    auto response = build_response(0xaaaa, "example.com", {
        {"example.com", kTypeA, ip(93, 184, 216, 34)},
    });
    auto r = fx.run("example.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    ASSERT_EQ(r.chain.size(), 1u);
    EXPECT_EQ(r.chain[0], "example.com");
    EXPECT_EQ(fx.fake.queries_served(), 0);
}

TEST(CnameUncloaker, FullChainInOneResponseClean) {
    UncloakFixture fx;
    auto response = build_response(0xaaaa, "metrics.site.example", {
        {"metrics.site.example", kTypeCNAME, std::string{"edge.cdn.example"}},
        {"edge.cdn.example",      kTypeCNAME, std::string{"pop.cdn.example"}},
        {"pop.cdn.example",       kTypeA,     ip(203, 0, 113, 10)},
    });
    auto r = fx.run("metrics.site.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    ASSERT_EQ(r.chain.size(), 3u);
    EXPECT_EQ(r.chain[0], "metrics.site.example");
    EXPECT_EQ(r.chain[1], "edge.cdn.example");
    EXPECT_EQ(r.chain[2], "pop.cdn.example");
    EXPECT_EQ(fx.fake.queries_served(), 0);
}

TEST(CnameUncloaker, ChainBlockedMidway) {
    UncloakFixture fx;
    fx.bl.add_suffix("criteo.example");

    auto response = build_response(0xbbbb, "metrics.nytimes.example", {
        {"metrics.nytimes.example", kTypeCNAME,
         std::string{"sdata.nytimes.d.criteo.example"}},
        {"sdata.nytimes.d.criteo.example", kTypeCNAME,
         std::string{"lb.criteo-static.example"}},
        {"lb.criteo-static.example", kTypeA, ip(178, 250, 2, 127)},
    });
    auto r = fx.run("metrics.nytimes.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Blocked);
    ASSERT_EQ(r.chain.size(), 2u);
    EXPECT_EQ(r.chain[0], "metrics.nytimes.example");
    EXPECT_EQ(r.chain[1], "sdata.nytimes.d.criteo.example");
    EXPECT_EQ(r.hit.rule, "criteo.example");
    EXPECT_EQ(r.hit.kind, cloak::MatchKind::Suffix);
}

TEST(CnameUncloaker, PartialChainTriggersRequery) {
    UncloakFixture fx;
    auto first = build_response(0xcccc, "fp.site.example", {
        {"fp.site.example", kTypeCNAME, std::string{"hop1.cdn.example"}},
    });
    fx.fake.stage("hop1.cdn.example",
        build_response(0, "hop1.cdn.example", {
            {"hop1.cdn.example", kTypeA, ip(10, 0, 0, 1)},
        }));
    auto r = fx.run("fp.site.example", first);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    ASSERT_EQ(r.chain.size(), 2u);
    EXPECT_EQ(r.chain[1], "hop1.cdn.example");
    EXPECT_EQ(fx.fake.queries_served(), 1);
}

TEST(CnameUncloaker, RequeryTargetBlocked) {
    UncloakFixture fx;
    fx.bl.add_suffix("tracker.example");

    auto first = build_response(0xdddd, "fp.site.example", {
        {"fp.site.example", kTypeCNAME, std::string{"telemetry.tracker.example"}},
    });
    // The re-query would find tracker.example via blocklist before
    // ever reaching the fake upstream, but stage a response anyway so
    // a bug skipping the pre-forward check still produces a deterministic
    // failure.
    fx.fake.stage("telemetry.tracker.example",
        build_response(0, "telemetry.tracker.example", {
            {"telemetry.tracker.example", kTypeA, ip(1, 2, 3, 4)},
        }));
    auto r = fx.run("fp.site.example", first);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Blocked);
    ASSERT_EQ(r.chain.size(), 2u);
    EXPECT_EQ(r.chain[1], "telemetry.tracker.example");
    EXPECT_EQ(r.hit.rule, "tracker.example");
    EXPECT_EQ(fx.fake.queries_served(), 0)
        << "blocklist check must happen before re-query";
}

TEST(CnameUncloaker, LoopDetectedInOneResponse) {
    UncloakFixture fx;
    auto response = build_response(0xeeee, "a.example", {
        {"a.example", kTypeCNAME, std::string{"b.example"}},
        {"b.example", kTypeCNAME, std::string{"a.example"}},
    });
    auto r = fx.run("a.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Aborted);
    EXPECT_EQ(r.abort_reason, "CNAME loop");
    EXPECT_EQ(fx.fake.queries_served(), 0)
        << "intra-response cycle must be detected without a re-query";
}

TEST(CnameUncloaker, LoopDetectedAcrossRequery) {
    UncloakFixture fx;
    auto first = build_response(0xefef, "a.example", {
        {"a.example", kTypeCNAME, std::string{"b.example"}},
    });
    // Re-query for b.example returns a CNAME to a.example — closing the loop.
    fx.fake.stage("b.example",
        build_response(0, "b.example", {
            {"b.example", kTypeCNAME, std::string{"a.example"}},
        }));
    auto r = fx.run("a.example", first);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Aborted);
    EXPECT_EQ(r.abort_reason, "CNAME loop");
    EXPECT_GE(fx.fake.queries_served(), 1);
}

TEST(CnameUncloaker, DepthLimitExceeded) {
    UncloakFixture fx;
    // Stage a nine-hop CNAME chain in the first response (qname + 8 CNAMEs +
    // no terminator). Uncloaker's max_depth is 8 — chain should fill and
    // abort.
    std::vector<Rr> answers;
    std::string current = "h0.example";
    for (int i = 0; i < 9; ++i) {
        std::string next = "h" + std::to_string(i + 1) + ".example";
        answers.push_back({current, kTypeCNAME, next});
        current = next;
    }
    auto response = build_response(0xfafa, "h0.example", answers);
    auto r = fx.run("h0.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Aborted);
    EXPECT_EQ(r.abort_reason, "depth limit reached");
    EXPECT_EQ(static_cast<int>(r.chain.size()), 8);
}

TEST(CnameUncloaker, NodataResponseIsClean) {
    UncloakFixture fx;
    // Empty answer section — simulates NODATA / NXDOMAIN.
    auto response = build_response(0x5151, "nothing.example", {});
    auto r = fx.run("nothing.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    ASSERT_EQ(r.chain.size(), 1u);
}

TEST(CnameUncloaker, QnameApexBlockedNotReachedHereByDesign) {
    // This path covers "a hop other than the qname matches". The main
    // handler checks the qname via the direct blocklist before calling
    // the uncloaker, so the uncloaker chain should never need to match
    // the qname itself. But for robustness, the uncloaker still reports
    // Blocked if a subsequent hop matches — which is the point.
    UncloakFixture fx;
    fx.bl.add_suffix("tracker.example");
    auto response = build_response(0x9999, "site.example", {
        {"site.example", kTypeCNAME, std::string{"edge.tracker.example"}},
        {"edge.tracker.example", kTypeA, ip(1, 2, 3, 4)},
    });
    auto r = fx.run("site.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Blocked);
    EXPECT_EQ(r.hit.rule, "tracker.example");
}

// ---------- AAAA / IPv6 ----------

TEST(CnameUncloaker, AaaaCleanChainTerminatesOnAaaa) {
    UncloakFixture fx;
    std::array<uint8_t, 16> v6 = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 1};
    auto response = build_response(0x6666, "edge.example.com", {
        {"edge.example.com", kTypeCNAME, std::string{"v6.cdn.example"}},
        {"v6.cdn.example",   kTypeAAAA,  v6},
    }, kTypeAAAA);
    auto r = fx.run("edge.example.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    ASSERT_EQ(r.chain.size(), 2u);
    EXPECT_EQ(r.chain[1], "v6.cdn.example");
}

TEST(CnameUncloaker, AaaaBlockedThroughCnameChain) {
    UncloakFixture fx;
    fx.bl.add_suffix("tracker.example");

    std::array<uint8_t, 16> v6 = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 0xaa};
    auto response = build_response(0x7777, "site.example", {
        {"site.example",          kTypeCNAME, std::string{"v6.tracker.example"}},
        {"v6.tracker.example",    kTypeAAAA,  v6},
    }, kTypeAAAA);
    auto r = fx.run("site.example", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Blocked);
    EXPECT_EQ(r.hit.rule, "tracker.example");
    ASSERT_EQ(r.chain.size(), 2u);
    EXPECT_EQ(r.chain[1], "v6.tracker.example");
}

// --- Suspicious-cross signal (M13, Safari-style soft action) ---

TEST(CnameUncloaker, Etldp1CrossSetWhenChainCrossesRegistrableDomain) {
    // metrics.bigsite.com → tracker.evil.com — clean by name, but
    // chain crosses eTLD+1 (bigsite.com → evil.com). The uncloaker
    // should report Clean status AND crossed_etldp1 = true.
    UncloakFixture fx;
    auto response = build_response(0x9999, "metrics.bigsite.com", {
        {"metrics.bigsite.com", kTypeCNAME, std::string{"collect.tracker.evil.com"}},
        {"collect.tracker.evil.com", kTypeA, ip(198, 51, 100, 42)},
    });
    auto r = fx.run("metrics.bigsite.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    EXPECT_TRUE(r.crossed_etldp1);
    EXPECT_EQ(r.crossed_to, "evil.com");
}

TEST(CnameUncloaker, Etldp1CrossNotSetForSameRegistrableDomain) {
    // a.bigsite.com → b.deeper.bigsite.com — both eTLD+1 = bigsite.com.
    // No cross, no signal.
    UncloakFixture fx;
    auto response = build_response(0xa1a1, "a.bigsite.com", {
        {"a.bigsite.com", kTypeCNAME, std::string{"b.deeper.bigsite.com"}},
        {"b.deeper.bigsite.com", kTypeA, ip(198, 51, 100, 1)},
    });
    auto r = fx.run("a.bigsite.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    EXPECT_FALSE(r.crossed_etldp1);
    EXPECT_EQ(r.crossed_to, "");
}

TEST(CnameUncloaker, Etldp1CrossRecordsFirstCrossNotLast) {
    // Two crossings — bigsite.com → cdn.example → tracker.example.
    // The signal latches on the FIRST crossing (cdn.example), not
    // overwritten by subsequent crossings.
    UncloakFixture fx;
    auto response = build_response(0xb2b2, "metrics.bigsite.com", {
        {"metrics.bigsite.com", kTypeCNAME, std::string{"edge.cdn.example"}},
        {"edge.cdn.example", kTypeCNAME, std::string{"pop.tracker.example"}},
        {"pop.tracker.example", kTypeA, ip(203, 0, 113, 5)},
    });
    auto r = fx.run("metrics.bigsite.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Clean);
    EXPECT_TRUE(r.crossed_etldp1);
    EXPECT_EQ(r.crossed_to, "cdn.example");
}

TEST(CnameUncloaker, Etldp1CrossSetEvenWhenBlocked) {
    // The cross signal is INDEPENDENT of status. A chain that crosses
    // AND is blocked records both — useful for analytics joining
    // "did the blocklist hit AND was it CNAME-cloaked across eTLD+1?".
    UncloakFixture fx;
    fx.bl.add_suffix("liveintent.com");
    auto response = build_response(0xc3c3, "idx.liadm.com", {
        {"idx.liadm.com", kTypeCNAME, std::string{"idx.cph.liveintent.com"}},
        {"idx.cph.liveintent.com", kTypeA, ip(54, 240, 12, 34)},
    });
    auto r = fx.run("idx.liadm.com", response);
    EXPECT_EQ(r.status, cloak::UncloakStatus::Blocked);
    EXPECT_EQ(r.hit.rule, "liveintent.com");
    EXPECT_TRUE(r.crossed_etldp1);
    EXPECT_EQ(r.crossed_to, "liveintent.com");
}
