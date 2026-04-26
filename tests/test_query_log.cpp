#include "cloakdns/query_log.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

using namespace cloak;
using namespace std::chrono_literals;

namespace {

std::filesystem::path temp_log_path() {
    return std::filesystem::temp_directory_path() /
           ("cloak_log_" + std::to_string(std::rand()) + ".jsonl");
}

QueryLog sample_record(LogAction action = LogAction::Allow) {
    QueryLog r;
    r.ts          = std::chrono::system_clock::now();
    r.qname       = "example.com";
    r.qtype       = 1;
    r.action      = action;
    r.rule        = "";
    r.upstream    = "1.1.1.1:53";
    r.latency_ms  = 4.215;
    r.client      = "192.168.1.12:54321";
    return r;
}

std::vector<std::string> read_lines(const std::filesystem::path& p) {
    std::ifstream in{p};
    std::vector<std::string> out;
    std::string line;
    while (std::getline(in, line)) out.push_back(line);
    return out;
}

} // namespace

// ---------- to_json_line ----------

TEST(JsonLine, BasicAllowShape) {
    auto line = to_json_line(sample_record());
    EXPECT_NE(line.find("\"action\":\"allow\""), std::string::npos);
    EXPECT_NE(line.find("\"qname\":\"example.com\""), std::string::npos);
    EXPECT_NE(line.find("\"qtype\":\"A\""), std::string::npos);
    EXPECT_NE(line.find("\"rule\":null"), std::string::npos);
    EXPECT_NE(line.find("\"cname_chain\":[]"), std::string::npos);
    EXPECT_NE(line.find("\"upstream\":\"1.1.1.1:53\""), std::string::npos);
    EXPECT_NE(line.find("\"latency_ms\":4.215"), std::string::npos);
    EXPECT_NE(line.find("\"client\":\"192.168.1.12:54321\""),
              std::string::npos);
    EXPECT_EQ(line.front(), '{');
    EXPECT_EQ(line.back(),  '}');
}

TEST(JsonLine, RuleAndChainPopulated) {
    auto r = sample_record(LogAction::Uncloak);
    r.rule = "criteo.com";
    r.cname_chain = {"metrics.example.com", "sdata.criteo.com"};
    r.upstream = std::nullopt;
    auto line = to_json_line(r);
    EXPECT_NE(line.find("\"action\":\"uncloak\""), std::string::npos);
    EXPECT_NE(line.find("\"rule\":\"criteo.com\""), std::string::npos);
    EXPECT_NE(line.find(
        "\"cname_chain\":[\"metrics.example.com\",\"sdata.criteo.com\"]"),
        std::string::npos);
    EXPECT_NE(line.find("\"upstream\":null"), std::string::npos);
}

TEST(JsonLine, EscapesControlChars) {
    auto r = sample_record();
    char soh = 0x01;
    r.qname = std::string{"evil"} + soh + "\nname";
    auto line = to_json_line(r);
    // 0x01 encodes as ; 0x0a encodes as \n.
    EXPECT_NE(line.find("\"qname\":\"evil\\u0001\\nname\""),
              std::string::npos);
}

TEST(JsonLine, EscapesQuotesAndBackslash) {
    auto r = sample_record();
    r.rule = "a\"b\\c";
    auto line = to_json_line(r);
    EXPECT_NE(line.find("\"rule\":\"a\\\"b\\\\c\""), std::string::npos);
}

TEST(JsonLine, UnknownQtypeFallsBackToInteger) {
    auto r = sample_record();
    r.qtype = 9999;
    auto line = to_json_line(r);
    EXPECT_NE(line.find("\"qtype\":9999"), std::string::npos);
}

TEST(JsonLine, IncludesSchemaVersion) {
    auto line = to_json_line(sample_record());
    // Schema version is the very first field — analytics consumers read
    // a fixed prefix to detect old logs.
    EXPECT_TRUE(line.starts_with("{\"v\":1,"))
        << "expected schema-version prefix, got: " << line.substr(0, 16);
}

TEST(QueryLogger, RotatesPastMaxSize) {
    auto path = temp_log_path();
    {
        QueryLogger logger{QueryLogger::Config{
            .path           = path,
            .async          = false,
            .max_size_bytes = 256,        // small; trips quickly
        }};
        for (int i = 0; i < 50; ++i) {
            auto r = sample_record();
            r.qname = "example" + std::to_string(i) + ".com";
            logger.log(r);
        }
        logger.flush();
        EXPECT_GE(logger.rotated_count(), 1u);
    }
    // At least one rotated sibling exists.
    bool found = false;
    for (auto& e : std::filesystem::directory_iterator{path.parent_path()}) {
        const auto fname = e.path().filename().string();
        if (fname.starts_with(path.filename().string()) &&
            fname.size() > path.filename().string().size() + 1) {
            found = true;
            std::filesystem::remove(e.path());
        }
    }
    EXPECT_TRUE(found) << "expected at least one rotated log sibling";
    std::filesystem::remove(path);
}

TEST(QueryLogger, RedactClientFlagHashesAddress) {
    auto path = temp_log_path();
    {
        QueryLogger logger{QueryLogger::Config{
            .path          = path,
            .async         = false,
            .redact_client = true,
        }};
        logger.log(sample_record());
        logger.flush();
    }
    auto lines = read_lines(path);
    ASSERT_EQ(lines.size(), 1u);
    EXPECT_NE(lines[0].find("\"client\":\"hash:"), std::string::npos)
        << "raw client IP must not appear when redact_client=true: " << lines[0];
    EXPECT_EQ(lines[0].find("192.168.1.12"), std::string::npos);
    std::filesystem::remove(path);
}

TEST(RedactClient, StableHashPrefix) {
    const auto a = redact_client_id("192.168.1.12:54321");
    const auto b = redact_client_id("192.168.1.12:54321");
    EXPECT_EQ(a, b);                                     // deterministic
    EXPECT_TRUE(a.starts_with("hash:"));                 // tagged
    EXPECT_NE(a, redact_client_id("10.0.0.1:1234"));     // different input
    EXPECT_EQ(a.size(), std::string{"hash:"}.size() + 8u); // 8-hex truncation
}

TEST(JsonLine, TimestampIsIso8601Utc) {
    auto r = sample_record();
    auto line = to_json_line(r);
    const auto pos = line.find("\"ts\":\"");
    ASSERT_NE(pos, std::string::npos);
    const std::string ts = line.substr(pos + 6, 24);
    ASSERT_EQ(ts.size(), 24u);
    EXPECT_EQ(ts[4],  '-');
    EXPECT_EQ(ts[7],  '-');
    EXPECT_EQ(ts[10], 'T');
    EXPECT_EQ(ts[13], ':');
    EXPECT_EQ(ts[16], ':');
    EXPECT_EQ(ts[19], '.');
    EXPECT_EQ(ts[23], 'Z');
}

// ---------- QueryLogger sync ----------

TEST(QueryLogger, SyncWritesOneLinePerRecord) {
    auto path = temp_log_path();
    {
        QueryLogger logger{QueryLogger::Config{
            .path = path, .async = false, .queue_size = 0}};
        logger.log(sample_record(LogAction::Block));
        logger.log(sample_record(LogAction::Cached));
    }
    auto lines = read_lines(path);
    ASSERT_EQ(lines.size(), 2u);
    EXPECT_NE(lines[0].find("\"action\":\"block\""),  std::string::npos);
    EXPECT_NE(lines[1].find("\"action\":\"cached\""), std::string::npos);
    std::filesystem::remove(path);
}

// ---------- QueryLogger async ----------

TEST(QueryLogger, AsyncFlushWritesAllRecords) {
    auto path = temp_log_path();
    {
        QueryLogger logger{QueryLogger::Config{
            .path = path, .async = true, .queue_size = 1024}};
        for (int i = 0; i < 10; ++i) {
            logger.log(sample_record(LogAction::Allow));
        }
        logger.flush();
    }
    auto lines = read_lines(path);
    EXPECT_EQ(lines.size(), 10u);
    std::filesystem::remove(path);
}

TEST(QueryLogger, AllRecordsAccountedForUnderPressure) {
    auto path = temp_log_path();
    size_t drops = 0;
    {
        QueryLogger logger{QueryLogger::Config{
            .path = path, .async = true, .queue_size = 2}};
        for (int i = 0; i < 500; ++i) {
            logger.log(sample_record(LogAction::Allow));
        }
        logger.flush();
        drops = logger.dropped_count();
    }
    const auto written = read_lines(path).size();
    EXPECT_EQ(written + drops, 500u);
    std::filesystem::remove(path);
}

TEST(QueryLogger, EmptyPathIsDisabled) {
    QueryLogger logger{};
    logger.log(sample_record());
    logger.flush();
    EXPECT_EQ(logger.dropped_count(), 0u);
}
