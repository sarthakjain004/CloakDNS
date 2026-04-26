// HTTP/1.1 response-head parser tests. The post_https_oneshot()
// integration test that goes against a real DoH endpoint lives in a
// separate online test file (not added in this PR) — keeping the basic
// suite network-free.

#include "cloakdns/http_client.hpp"

#include <gtest/gtest.h>

#include <string>

TEST(HttpParse, MinimalOk) {
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: 117\r\n"
        "\r\n";
    auto p = cloak::http::parse_response_head(kInput);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->status, 200);

    const auto ct = cloak::http::header_value(p->headers, "Content-Type");
    ASSERT_TRUE(ct.has_value());
    EXPECT_EQ(*ct, "application/dns-message");

    const auto cl = cloak::http::header_value(p->headers, "content-length");  // case-insensitive
    ASSERT_TRUE(cl.has_value());
    EXPECT_EQ(*cl, "117");
}

TEST(HttpParse, RejectsMissingDelimiter) {
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 5\r\n";   // no terminating \r\n
    EXPECT_FALSE(cloak::http::parse_response_head(kInput).has_value());
}

TEST(HttpParse, RejectsMalformedStatusLine) {
    constexpr std::string_view kInput =
        "HTTP/1.1\r\n"   // no status code, no reason phrase
        "\r\n";
    EXPECT_FALSE(cloak::http::parse_response_head(kInput).has_value());
}

TEST(HttpParse, AcceptsExtraBytesPastDelimiter) {
    // post_https_oneshot expects parse to succeed even if the buffer
    // contains body bytes after the head — the parser should only
    // consume the head, leaving the body for the caller.
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "BODY";
    auto p = cloak::http::parse_response_head(kInput);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->status, 200);
}

TEST(HttpParse, HeadersAreLowercasedKeys) {
    constexpr std::string_view kInput =
        "HTTP/1.1 404 Not Found\r\n"
        "X-Mixed-Case-Name: yes\r\n"
        "\r\n";
    auto p = cloak::http::parse_response_head(kInput);
    ASSERT_TRUE(p.has_value());
    ASSERT_EQ(p->headers.size(), 1u);
    EXPECT_EQ(p->headers[0].first, "x-mixed-case-name");
    EXPECT_EQ(p->headers[0].second, "yes");
}

TEST(HttpParse, TrimsHeaderValueWhitespace) {
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length:    42   \r\n"
        "\r\n";
    auto p = cloak::http::parse_response_head(kInput);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(cloak::http::header_value(p->headers, "Content-Length").value(),
              "42");
}

TEST(HttpParse, IgnoresMalformedHeaderLine) {
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "no-colon-here\r\n"   // malformed; parser must reject
        "\r\n";
    EXPECT_FALSE(cloak::http::parse_response_head(kInput).has_value());
}

TEST(HttpParse, MultipleHeaders) {
    constexpr std::string_view kInput =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 0\r\n"
        "Server: cloak-test\r\n"
        "\r\n";
    auto p = cloak::http::parse_response_head(kInput);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->headers.size(), 3u);
}
