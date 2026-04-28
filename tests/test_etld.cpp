#include "cloakdns/etld.hpp"
#include "cloakdns/aliases.hpp"

#include <gtest/gtest.h>

using cloak::etld_plus_one;

TEST(Etld, SimpleTwoLabel) {
    EXPECT_EQ(etld_plus_one("example.com"), "example.com");
    EXPECT_EQ(etld_plus_one("a.example.com"), "example.com");
    EXPECT_EQ(etld_plus_one("a.b.c.example.com"), "example.com");
}

TEST(Etld, MultiLabelCcTLD) {
    EXPECT_EQ(etld_plus_one("bbc.co.uk"), "bbc.co.uk");
    EXPECT_EQ(etld_plus_one("news.bbc.co.uk"), "bbc.co.uk");
    EXPECT_EQ(etld_plus_one("a.b.bbc.co.uk"), "bbc.co.uk");
    EXPECT_EQ(etld_plus_one("iitb.ac.in"), "iitb.ac.in");
    EXPECT_EQ(etld_plus_one("portal.iitb.ac.in"), "iitb.ac.in");
    EXPECT_EQ(etld_plus_one("foo.com.au"), "foo.com.au");
    EXPECT_EQ(etld_plus_one("a.b.foo.com.au"), "foo.com.au");
}

TEST(Etld, ReverseDnsSuffix) {
    EXPECT_EQ(etld_plus_one("1.0.0.127.in-addr.arpa"), "127.in-addr.arpa");
    EXPECT_EQ(etld_plus_one("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"),
              "0.ip6.arpa");
}

TEST(Etld, SingleLabelOrEmpty) {
    EXPECT_EQ(etld_plus_one(""), "");
    EXPECT_EQ(etld_plus_one("localhost"), "localhost");
}

TEST(Etld, TrailingDotsStripped) {
    EXPECT_EQ(etld_plus_one("example.com."), "example.com");
    EXPECT_EQ(etld_plus_one("a.bbc.co.uk."), "bbc.co.uk");
    EXPECT_EQ(etld_plus_one("..."), "");
}

TEST(Etld, SuffixOnlyDegenerate) {
    // Querying for the public suffix itself. We return as-is — not
    // semantically meaningful but stable, won't trip the cross-detector
    // because the comparison is symmetric.
    EXPECT_EQ(etld_plus_one("co.uk"), "co.uk");
    EXPECT_EQ(etld_plus_one("com"), "com");
}

TEST(Etld, RealCaptureSamples) {
    // From real-Chrome capture v2 — sanity-check that the names that
    // surfaced uncloak/forward in our logs produce stable eTLD+1.
    EXPECT_EQ(etld_plus_one("idx.liadm.com"), "liadm.com");
    EXPECT_EQ(etld_plus_one("idx.cph.liveintent.com"), "liveintent.com");
    EXPECT_EQ(etld_plus_one("nytimes.map.fastly.net"), "fastly.net");
    EXPECT_EQ(etld_plus_one("samizdat-graphql.prd.map.nytimes.xovr.nyt.net"),
              "nyt.net");
    EXPECT_EQ(etld_plus_one("v20.events.data.microsoft.com"), "microsoft.com");
}

TEST(Etld, CrossDetectionExamples) {
    // The cross-detector logic: original eTLD+1 vs hop eTLD+1.
    // These pairs SHOULD register as crosses.
    EXPECT_NE(etld_plus_one("metrics.bigsite.com"),
              etld_plus_one("collect.tracker-co.example"));
    EXPECT_NE(etld_plus_one("idx.liadm.com"),
              etld_plus_one("idx.cph.liveintent.com"));

    // These pairs should NOT register as crosses (same registrable domain).
    EXPECT_EQ(etld_plus_one("a.example.com"),
              etld_plus_one("b.deeper.example.com"));
    EXPECT_EQ(etld_plus_one("news.bbc.co.uk"),
              etld_plus_one("sport.bbc.co.uk"));
    EXPECT_EQ(etld_plus_one("static01.nyt.com"),
              etld_plus_one("nytimes.map.fastly.net.example.nyt.com"));
}
