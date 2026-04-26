#include "cloakdns/config.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace cloak;
using namespace std::chrono_literals;

// ---------- defaults ----------

TEST(Config, EmptyTomlYieldsDocumentedDefaults) {
    auto c = parse_config_toml("");
    EXPECT_EQ(c.server.listen_addr, "127.0.0.1");
    EXPECT_EQ(c.server.listen_port, 5354);
    ASSERT_EQ(c.upstream.servers.size(), 2u);
    EXPECT_EQ(c.upstream.servers[0], (Endpoint{"1.1.1.1", 53}));
    EXPECT_EQ(c.upstream.servers[1], (Endpoint{"9.9.9.9", 53}));
    EXPECT_EQ(c.upstream.timeout, 2000ms);
    EXPECT_EQ(c.upstream.retries_on_primary, 1);
    EXPECT_EQ(c.upstream.padding_block_size, 128u);
    ASSERT_EQ(c.blocklist.sources.size(), 1u);
    EXPECT_EQ(c.blocklist.sources[0].string(), "blocklists/tier1.txt");
    EXPECT_EQ(c.cache.max_entries, 50000u);
    EXPECT_EQ(c.cache.jitter_max, 5ms);
    EXPECT_EQ(c.cache.sweep_interval, 30s);
    EXPECT_EQ(c.uncloak.max_depth, 8);
}

// ---------- full round-trip ----------

TEST(Config, FullTomlParsesAllFields) {
    auto c = parse_config_toml(R"(
[server]
listen_addr = "0.0.0.0"
listen_port = 53

[upstream]
servers = ["8.8.8.8:53", "8.8.4.4:53"]
timeout_ms = 1500
retries_on_primary = 2
padding_block_size = 468

[blocklist]
sources = ["a.txt", "b.txt"]

[cache]
max_entries = 100000
jitter_max_ms = 0
sweep_interval_s = 60

[uncloak]
max_depth = 16
)");
    EXPECT_EQ(c.server.listen_addr, "0.0.0.0");
    EXPECT_EQ(c.server.listen_port, 53);
    ASSERT_EQ(c.upstream.servers.size(), 2u);
    EXPECT_EQ(c.upstream.servers[0], (Endpoint{"8.8.8.8", 53}));
    EXPECT_EQ(c.upstream.timeout, 1500ms);
    EXPECT_EQ(c.upstream.retries_on_primary, 2);
    EXPECT_EQ(c.upstream.padding_block_size, 468u);
    ASSERT_EQ(c.blocklist.sources.size(), 2u);
    EXPECT_EQ(c.cache.max_entries, 100000u);
    EXPECT_EQ(c.cache.jitter_max, 0ms);
    EXPECT_EQ(c.cache.sweep_interval, 60s);
    EXPECT_EQ(c.uncloak.max_depth, 16);
}

// ---------- schema failures ----------

TEST(Config, PortOutOfRangeRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[server]
listen_port = 70000
)"), ConfigError);
}

TEST(Config, NegativePortRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[server]
listen_port = -1
)"), ConfigError);
}

TEST(Config, UpstreamMissingColonRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
servers = ["1.1.1.1"]
)"), ConfigError);
}

TEST(Config, UpstreamPortOutOfRangeRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
servers = ["1.1.1.1:99999"]
)"), ConfigError);
}

TEST(Config, UpstreamEmptyServersRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
servers = []
)"), ConfigError);
}

TEST(Config, UpstreamNonStringEntryRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
servers = [42]
)"), ConfigError);
}

TEST(Config, NegativeTimeoutRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
timeout_ms = -5
)"), ConfigError);
}

TEST(Config, NegativeRetriesRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
retries_on_primary = -1
)"), ConfigError);
}

TEST(Config, NegativePaddingRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[upstream]
padding_block_size = -1
)"), ConfigError);
}

TEST(Config, EmptyBlocklistSourcesRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[blocklist]
sources = []
)"), ConfigError);
}

TEST(Config, CacheSweepNonPositiveRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[cache]
sweep_interval_s = 0
)"), ConfigError);
}

TEST(Config, UncloakMaxDepthOutOfRangeRejected) {
    EXPECT_THROW(parse_config_toml(R"(
[uncloak]
max_depth = 100
)"), ConfigError);
    EXPECT_THROW(parse_config_toml(R"(
[uncloak]
max_depth = 0
)"), ConfigError);
}

TEST(Config, MalformedTomlRejectedWithLineInfo) {
    try {
        parse_config_toml("this is = = not valid toml");
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& e) {
        EXPECT_NE(std::string{e.what()}.find("TOML parse error"),
                  std::string::npos);
    }
}

// ---------- partial sections ----------

TEST(Config, OnlyServerSectionFillsRestWithDefaults) {
    auto c = parse_config_toml(R"(
[server]
listen_port = 5300
)");
    EXPECT_EQ(c.server.listen_port, 5300);
    EXPECT_EQ(c.server.listen_addr, "127.0.0.1");  // default preserved
    EXPECT_EQ(c.cache.max_entries, 50000u);         // untouched
}

TEST(Config, UnknownKeysIgnoredForwardCompat) {
    auto c = parse_config_toml(R"(
[server]
listen_port = 5300
future_feature = "tbd"

[brand_new_section]
anything = true
)");
    EXPECT_EQ(c.server.listen_port, 5300);  // existing field still read
}

// ---------- load_config file I/O ----------

TEST(LoadConfig, ReadsFileAndParses) {
    auto path = std::filesystem::temp_directory_path() /
                ("cloakdns_cfg_" + std::to_string(std::rand()) + ".toml");
    {
        std::ofstream out{path};
        out << "[server]\nlisten_port = 1234\n";
    }
    auto c = load_config(path);
    EXPECT_EQ(c.server.listen_port, 1234);
    std::filesystem::remove(path);
}

TEST(LoadConfig, NonexistentPathThrowsWithHint) {
    try {
        load_config("/definitely/not/a/real/path.toml");
        FAIL() << "expected ConfigError";
    } catch (const ConfigError& e) {
        EXPECT_NE(std::string{e.what()}.find("cannot open config"),
                  std::string::npos);
    }
}
