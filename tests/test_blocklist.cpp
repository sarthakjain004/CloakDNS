#include "cloakdns/blocklist.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace cloak;

namespace {

std::filesystem::path make_temp_hosts(const std::string& body) {
    auto path = std::filesystem::temp_directory_path() /
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
                 std::runtime_error);
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
