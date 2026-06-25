#include "cloakdns/blocklist.hpp"
#include "cloakdns/aliases.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace cloak;

namespace {

fs::path make_temp_hosts(const string& body) {
    auto path = fs::temp_directory_path() /
                ("cloak_bl_" + std::to_string(std::rand()) + ".txt");
    std::ofstream out{path};
    out << body;
    return path;
}

} // namespace

// ---- core matching ----

TEST(Blocklist, ExactMatch) {
    Blocklist bl;
    bl.add_exact("foo.com");
    auto r = bl.match("foo.com");
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.kind, MatchKind::Exact);
    EXPECT_EQ(r.rule, "foo.com");
}

TEST(Blocklist, ExactMismatchNoSuffix) {
    Blocklist bl;
    bl.add_exact("foo.com");
    EXPECT_FALSE(bl.match("ads.foo.com").blocked);
}

TEST(Blocklist, SuffixMatchApex) {
    Blocklist bl;
    bl.add_suffix("doubleclick.net");
    auto r = bl.match("doubleclick.net");
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.kind, MatchKind::Suffix);
    EXPECT_EQ(r.rule, "doubleclick.net");
}

TEST(Blocklist, SuffixMatchSubdomain) {
    Blocklist bl;
    bl.add_suffix("doubleclick.net");
    EXPECT_TRUE(bl.match("ads.doubleclick.net").blocked);
}

TEST(Blocklist, SuffixMatchDeepSubdomain) {
    Blocklist bl;
    bl.add_suffix("doubleclick.net");
    EXPECT_TRUE(bl.match("a.b.c.d.doubleclick.net").blocked);
}

TEST(Blocklist, NoOverMatchPrefix) {
    Blocklist bl;
    bl.add_suffix("doubleclick.net");
    EXPECT_FALSE(bl.match("doubleclick.net.evil.com").blocked);
}

TEST(Blocklist, PartialLabelNoMatch) {
    Blocklist bl;
    bl.add_suffix("doubleclick.net");
    EXPECT_FALSE(bl.match("notdoubleclick.net").blocked);
}

TEST(Blocklist, CaseInsensitive) {
    Blocklist bl;
    bl.add_suffix("DoubleClick.NET");
    EXPECT_TRUE(bl.match("ads.doubleclick.net").blocked);
    // Contract expects input already lowercased, but adds upper->lower
    // at insert for robustness. Lookup is case-sensitive — parser feeds
    // lowercased qnames.
}

TEST(Blocklist, EmptyQnameMiss) {
    Blocklist bl;
    bl.add_suffix("foo.com");
    EXPECT_FALSE(bl.match("").blocked);
}

TEST(Blocklist, RegexMatch) {
    Blocklist bl;
    bl.add_regex("^ad[0-9]+\\.example\\.com$");
    EXPECT_TRUE(bl.match("ad1.example.com").blocked);
    EXPECT_TRUE(bl.match("ad42.example.com").blocked);
    EXPECT_FALSE(bl.match("adx.example.com").blocked);
}

TEST(Blocklist, RegexLastResort) {
    Blocklist bl;
    bl.add_suffix("foo.com");
    bl.add_regex("bar\\.net");
    auto r = bl.match("foo.com");
    EXPECT_EQ(r.kind, MatchKind::Suffix);  // suffix beats regex in order
}

TEST(Blocklist, Miss) {
    Blocklist bl;
    bl.add_suffix("foo.com");
    auto r = bl.match("github.com");
    EXPECT_FALSE(r.blocked);
    EXPECT_EQ(r.kind, MatchKind::None);
}

// ---- allow-vs-deny precedence (longest-match-wins) ----

TEST(BlocklistAllowDeny, AllowApexAllowsApex) {
    Blocklist bl;
    bl.add_allow_suffix("google.com");
    EXPECT_FALSE(bl.match("google.com").blocked);
    EXPECT_FALSE(bl.match("www.google.com").blocked);
}

TEST(BlocklistAllowDeny, MoreSpecificDenyBeatsApexAllow) {
    // Real-world case: user allowlists `google.com` so search works,
    // but a tracker blocklist contains `analytics.google.com` exact.
    // The longer/more-specific deny rule must win.
    Blocklist bl;
    bl.add_allow_suffix("google.com");
    bl.add_exact("analytics.google.com");
    EXPECT_FALSE(bl.match("google.com").blocked);
    EXPECT_FALSE(bl.match("www.google.com").blocked);
    EXPECT_TRUE(bl.match("analytics.google.com").blocked);
}

TEST(BlocklistAllowDeny, SubdomainAllowOverridesApexDeny) {
    // Inverse: blocklist has the apex, allowlist has a specific
    // subdomain — the more-specific allow wins for that subdomain.
    Blocklist bl;
    bl.add_suffix("tracker.com");
    bl.add_allow_exact("ok.tracker.com");
    EXPECT_TRUE(bl.match("tracker.com").blocked);
    EXPECT_TRUE(bl.match("foo.tracker.com").blocked);
    EXPECT_FALSE(bl.match("ok.tracker.com").blocked);
}

TEST(BlocklistAllowDeny, EqualLengthAllowWins) {
    // Same hostname listed in both allow and deny: prefer allow as
    // the more permissive default.
    Blocklist bl;
    bl.add_allow_suffix("example.com");
    bl.add_suffix("example.com");
    EXPECT_FALSE(bl.match("example.com").blocked);
    EXPECT_FALSE(bl.match("foo.example.com").blocked);
}

TEST(BlocklistAllowDeny, DenySuffixWinsOverShorterAllowSuffix) {
    Blocklist bl;
    bl.add_allow_suffix("com");                         // 3 chars
    bl.add_suffix("ads.example.com");                   // 15 chars
    EXPECT_TRUE(bl.match("ads.example.com").blocked);
    EXPECT_TRUE(bl.match("foo.ads.example.com").blocked);
    EXPECT_FALSE(bl.match("safe.example.com").blocked); // only allow matches
}

// ---- hosts-file parser ----

TEST(BlocklistHosts, ParsesBasic) {
    auto p = make_temp_hosts(
        "0.0.0.0 ads.example.com\n"
        "0.0.0.0 tracker.foo.com\n");
    Blocklist bl;
    EXPECT_EQ(bl.load_hosts_file(p), 2u);
    EXPECT_TRUE(bl.match("ads.example.com").blocked);
    EXPECT_TRUE(bl.match("tracker.foo.com").blocked);
}

TEST(BlocklistHosts, IgnoresComments) {
    auto p = make_temp_hosts(
        "# comment\n"
        "0.0.0.0 foo.com  # inline comment\n"
        "\n"
        "   \n"
        "0.0.0.0 bar.com\n");
    Blocklist bl;
    EXPECT_EQ(bl.load_hosts_file(p), 2u);
    EXPECT_TRUE(bl.match("foo.com").blocked);
    EXPECT_TRUE(bl.match("bar.com").blocked);
}

TEST(BlocklistHosts, MultiDomainLine) {
    auto p = make_temp_hosts("0.0.0.0 a.com b.com c.com\n");
    Blocklist bl;
    EXPECT_EQ(bl.load_hosts_file(p), 3u);
    EXPECT_TRUE(bl.match("a.com").blocked);
    EXPECT_TRUE(bl.match("b.com").blocked);
    EXPECT_TRUE(bl.match("c.com").blocked);
}

TEST(BlocklistHosts, SkipsMalformed) {
    auto p = make_temp_hosts(
        "0.0.0.0 good.com\n"
        "0.0.0.0 bad!!domain\n"   // invalid char
        "0.0.0.0 .leadingdot\n"
        "garbled line no valid ip\n"
        "0.0.0.0 also-good.com\n");
    Blocklist bl;
    const auto n = bl.load_hosts_file(p);
    EXPECT_TRUE(bl.match("good.com").blocked);
    EXPECT_TRUE(bl.match("also-good.com").blocked);
    EXPECT_GE(n, 2u);
}

TEST(BlocklistHosts, MissingFileThrows) {
    Blocklist bl;
    EXPECT_THROW(bl.load_hosts_file("/definitely/not/a/path.txt"),
                 runtime_error);
}

// ---- category attribution (named research tiers) ----

TEST(BlocklistCategory, TaggedTierSetsCategory) {
    auto p = make_temp_hosts("0.0.0.0 analytics.tiktok.com\n");
    Blocklist bl;
    EXPECT_EQ(bl.load_hosts_file(p, "server-side-endpoint"), 1u);
    auto r = bl.match("analytics.tiktok.com");
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.category, "server-side-endpoint");
}

TEST(BlocklistCategory, CategoryPropagatesToSubdomainHit) {
    auto p = make_temp_hosts("0.0.0.0 adnxs.com\n");
    Blocklist bl;
    bl.load_hosts_file(p, "syncing-hub");
    auto r = bl.match("ib.adnxs.com");   // suffix hit on adnxs.com
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.rule, "adnxs.com");
    EXPECT_EQ(r.category, "syncing-hub");
}

TEST(BlocklistCategory, UncategorizedSourceHasEmptyCategory) {
    auto p = make_temp_hosts("0.0.0.0 plain.example.com\n");
    Blocklist bl;
    bl.load_hosts_file(p);   // untagged overload
    auto r = bl.match("plain.example.com");
    EXPECT_TRUE(r.blocked);
    EXPECT_TRUE(r.category.empty());
}

TEST(BlocklistCategory, TaggedEvenWhenDomainAlreadyInCoreList) {
    // A high-value domain can sit in both the uncategorized core list
    // (loaded first) and a tier; it must still be attributed.
    auto core = make_temp_hosts("0.0.0.0 doubleclick.net\n");
    auto tier = make_temp_hosts("0.0.0.0 doubleclick.net\n");
    Blocklist bl;
    bl.load_hosts_file(core);                 // flat / untagged, first
    bl.load_hosts_file(tier, "syncing-hub");  // tier, second — no new suffix
    auto r = bl.match("ad.doubleclick.net");
    EXPECT_TRUE(r.blocked);
    EXPECT_EQ(r.category, "syncing-hub");
}

TEST(BlocklistCategory, FirstTierWinsOnCollision) {
    auto t1 = make_temp_hosts("0.0.0.0 shared.example.com\n");
    auto t2 = make_temp_hosts("0.0.0.0 shared.example.com\n");
    Blocklist bl;
    bl.load_hosts_file(t1, "fingerprinting");
    bl.load_hosts_file(t2, "syncing-hub");
    EXPECT_EQ(bl.match("shared.example.com").category, "fingerprinting");
}

TEST(BlocklistCategory, AllowlistStillOverridesTaggedRule) {
    auto p = make_temp_hosts("0.0.0.0 cdn.example.com\n");
    Blocklist bl;
    bl.load_hosts_file(p, "fingerprinting");
    bl.add_allow_exact("cdn.example.com");
    auto r = bl.match("cdn.example.com");
    EXPECT_FALSE(r.blocked);
    EXPECT_TRUE(r.category.empty());   // allow path carries no category
}

TEST(BlocklistCategory, EmptyCategoryBehavesLikeUntaggedOverload) {
    auto p = make_temp_hosts("0.0.0.0 x.example.com\n");
    Blocklist bl;
    EXPECT_EQ(bl.load_hosts_file(p, ""), 1u);
    auto r = bl.match("x.example.com");
    EXPECT_TRUE(r.blocked);
    EXPECT_TRUE(r.category.empty());
}

// ---- allowlist (passthrough) ----

TEST(Allowlist, ExactBeatsBlock) {
    Blocklist bl;
    bl.add_suffix("googleapis.com");
    bl.add_allow_exact("storage.googleapis.com");
    EXPECT_FALSE(bl.match("storage.googleapis.com").blocked);
    EXPECT_TRUE(bl.match("ads.googleapis.com").blocked);
}

TEST(Allowlist, SuffixBeatsBlock) {
    Blocklist bl;
    bl.add_suffix("amazonaws.com");
    bl.add_allow_suffix("s3.amazonaws.com");
    EXPECT_FALSE(bl.match("bucket.s3.amazonaws.com").blocked);
    EXPECT_FALSE(bl.match("s3.amazonaws.com").blocked);
    EXPECT_TRUE(bl.match("evil.amazonaws.com").blocked);
}

TEST(Allowlist, AllowedReportsTrue) {
    Blocklist bl;
    bl.add_allow_suffix("partner.example");
    EXPECT_TRUE(bl.allowed("api.partner.example"));
    EXPECT_FALSE(bl.allowed("attacker.example"));
}

TEST(Allowlist, LoadAllowlistFile) {
    auto p = make_temp_hosts(
        "# allow some legit subdomains\n"
        "0.0.0.0 maps.googleapis.com\n"
        "0.0.0.0 storage.googleapis.com\n");
    Blocklist bl;
    bl.add_suffix("googleapis.com");
    EXPECT_EQ(bl.load_allowlist_file(p), 2u);
    EXPECT_FALSE(bl.match("maps.googleapis.com").blocked);
    EXPECT_FALSE(bl.match("storage.googleapis.com").blocked);
    EXPECT_TRUE(bl.match("doubleclick.googleapis.com").blocked);
}

// ---- parameterized tier tests ----

#ifdef CLOAK_TEST_BLOCKLIST

struct TierCase { const char* qname; };

class Tier1ApexMatch : public ::testing::TestWithParam<TierCase> {};
TEST_P(Tier1ApexMatch, ApexDomainBlocked) {
    Blocklist bl;
    ASSERT_NO_THROW(bl.load_hosts_file(CLOAK_TEST_BLOCKLIST));
    EXPECT_TRUE(bl.match(GetParam().qname).blocked)
        << "expected " << GetParam().qname << " to be blocked";
}
INSTANTIATE_TEST_SUITE_P(Tier1_2, Tier1ApexMatch,
    ::testing::Values(
        TierCase{"doubleclick.net"},
        TierCase{"google-analytics.com"},
        TierCase{"googlesyndication.com"},
        TierCase{"googleadservices.com"},
        TierCase{"facebook.net"},
        TierCase{"fbcdn.net"},
        TierCase{"adnxs.com"},
        TierCase{"scorecardresearch.com"},
        TierCase{"rubiconproject.com"},
        TierCase{"openx.net"},
        TierCase{"turn.com"},
        TierCase{"mathtag.com"},
        TierCase{"advertising.com"},
        TierCase{"adsrvr.org"},
        TierCase{"mookie1.com"},
        TierCase{"crwdcntrl.net"},
        TierCase{"media6degrees.com"},
        TierCase{"gemius.pl"},
        TierCase{"2o7.net"},
        TierCase{"omtrdc.net"},
        TierCase{"rlcdn.com"},
        TierCase{"adverticum.net"}));

class Tier1SubdomainMatch : public ::testing::TestWithParam<TierCase> {};
TEST_P(Tier1SubdomainMatch, SubdomainBlocked) {
    Blocklist bl;
    ASSERT_NO_THROW(bl.load_hosts_file(CLOAK_TEST_BLOCKLIST));
    EXPECT_TRUE(bl.match(GetParam().qname).blocked)
        << "expected " << GetParam().qname << " to be blocked";
}
INSTANTIATE_TEST_SUITE_P(Hierarchical, Tier1SubdomainMatch,
    ::testing::Values(
        TierCase{"stats.g.doubleclick.net"},
        TierCase{"www.google-analytics.com"},
        TierCase{"connect.facebook.net"},
        TierCase{"pagead2.googlesyndication.com"},
        TierCase{"ib.adnxs.com"}));

#endif // CLOAK_TEST_BLOCKLIST
