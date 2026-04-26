#pragma once

#include "cloakdns/tls.hpp"

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace cloak::http {

struct Response {
    int                    status{0};   // HTTP status code, e.g. 200
    std::vector<std::byte> body;
    std::string            content_type;  // value of Content-Type header (lowercased)
};

// One-shot HTTPS POST. Opens a fresh TCP+TLS connection, writes the
// request, reads exactly one response, closes. No keepalive in v1 — DoH
// queries are short and the keepalive bookkeeping costs more than the
// extra handshake on a fast TLS 1.3 path. Add pooling later if profiling
// says it matters.
//
// Returns nullopt on any transport / TLS / framing failure (cert mismatch
// included). Never throws on transport error; the caller treats nullopt
// as "this attempt failed, try the next server."
//
// `host_header` is used as both SNI and the HTTP Host header — the cert
// SAN check also keys off it. Passing an empty string is an error.
asio::awaitable<std::optional<Response>>
post_https_oneshot(asio::io_context& ctx,
                   tls::Context& tls_ctx,
                   const asio::ip::tcp::endpoint& server,
                   const std::string& host_header,
                   const std::string& path,
                   const std::string& content_type,
                   std::span<const std::byte> body,
                   std::chrono::milliseconds timeout);

// Header-parsing primitive split out so the test suite can exercise it
// without the network dependency.
struct ParsedHeaders {
    int                                            status{0};
    std::vector<std::pair<std::string, std::string>> headers;
};

// Parse an HTTP/1.1 status line + header block (no body). `text` must
// end in "\r\n\r\n" or include it; only the prefix up to that delimiter
// is consumed. Header names are lowercased; values keep their case but
// are stripped of leading/trailing whitespace. Returns nullopt on any
// malformed input.
std::optional<ParsedHeaders> parse_response_head(std::string_view text);

// Case-insensitive lookup in a parsed header list.
std::optional<std::string>
header_value(const std::vector<std::pair<std::string, std::string>>& headers,
             std::string_view name);

} // namespace cloak::http
