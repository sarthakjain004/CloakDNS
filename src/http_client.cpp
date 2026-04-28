#include "cloakdns/http_client.hpp"

#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/read_until.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/streambuf.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>
#include <istream>
#include <memory>
#include <sstream>
#include <string_view>
#include <system_error>

namespace cloak::http {
namespace {

std::string to_lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t')) s.remove_suffix(1);
    return s;
}

// Read response head: "<status-line>CRLF<header-line>...CRLFCRLF". Body
// starts at headers_end+4 in the buffer. Returns the prefix length
// (i.e. the position of the body's first byte) on success.
std::size_t find_headers_end(std::string_view buf) {
    constexpr std::string_view kDelim{"\r\n\r\n"};
    const auto pos = buf.find(kDelim);
    if (pos == std::string_view::npos) return 0;
    return pos + kDelim.size();
}

} // namespace

std::optional<ParsedHeaders> parse_response_head(std::string_view text) {
    const auto end = find_headers_end(text);
    if (end == 0) return std::nullopt;

    const std::string_view block = text.substr(0, end - 4);  // strip trailing \r\n\r\n
    const auto first_crlf = block.find("\r\n");
    if (first_crlf == std::string_view::npos) return std::nullopt;

    // Status line: "HTTP/1.1 200 OK" — three space-separated tokens, second is status.
    const std::string_view status_line = block.substr(0, first_crlf);
    const auto sp1 = status_line.find(' ');
    if (sp1 == std::string_view::npos) return std::nullopt;
    const auto sp2 = status_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) return std::nullopt;
    const std::string_view status_token = status_line.substr(sp1 + 1, sp2 - sp1 - 1);
    int status = 0;
    auto [ptr, ec] = std::from_chars(status_token.data(),
                                     status_token.data() + status_token.size(),
                                     status);
    if (ec != std::errc{} || status < 100 || status > 999) return std::nullopt;

    ParsedHeaders out;
    out.status = status;

    std::size_t cursor = first_crlf + 2;
    while (cursor < block.size()) {
        const auto next = block.find("\r\n", cursor);
        const auto line_end = (next == std::string_view::npos) ? block.size() : next;
        const std::string_view line = block.substr(cursor, line_end - cursor);
        if (!line.empty()) {
            const auto colon = line.find(':');
            if (colon == std::string_view::npos) return std::nullopt;
            std::string name = to_lower(line.substr(0, colon));
            std::string value{trim(line.substr(colon + 1))};
            out.headers.emplace_back(std::move(name), std::move(value));
        }
        if (next == std::string_view::npos) break;
        cursor = next + 2;
    }
    return out;
}

std::optional<std::string>
header_value(const std::vector<std::pair<std::string, std::string>>& headers,
             std::string_view name) {
    const std::string lname = to_lower(name);
    for (const auto& [k, v] : headers) {
        if (k == lname) return v;
    }
    return std::nullopt;
}

asio::awaitable<std::optional<Response>>
post_https_oneshot(asio::io_context& ctx,
                   tls::Context& tls_ctx,
                   const asio::ip::tcp::endpoint& server,
                   const std::string& host_header,
                   const std::string& path,
                   const std::string& content_type,
                   std::span<const std::byte> body,
                   std::chrono::milliseconds timeout) {
    if (host_header.empty()) co_return std::nullopt;

    auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(
        ctx, tls_ctx.asio_context());

    asio::steady_timer timer{ctx};
    timer.expires_after(timeout);
    timer.async_wait([stream](const std::error_code& ec) {
        if (!ec) {
            std::error_code ignore;
            stream->lowest_layer().cancel(ignore);
        }
    });

    if (!tls::configure_ssl_for_connection(stream->native_handle(),
                                           tls_ctx.config(), host_header)) {
        co_return std::nullopt;
    }

    try {
        co_await stream->lowest_layer().async_connect(server, asio::use_awaitable);
        co_await stream->async_handshake(
            asio::ssl::stream_base::client, asio::use_awaitable);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }

    // Build the request head as a single string (small, ASCII).
    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host_header << "\r\n"
        << "User-Agent: cloakdns/1\r\n"
        << "Accept: " << content_type << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n";
    const std::string head = req.str();

    try {
        co_await asio::async_write(*stream,
            asio::buffer(head.data(), head.size()), asio::use_awaitable);
        if (!body.empty()) {
            co_await asio::async_write(*stream,
                asio::buffer(body.data(), body.size()), asio::use_awaitable);
        }
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }

    // Read response head + possibly some body bytes via dynamic-buffer
    // over a string. async_read_until guarantees the delimiter is
    // consumed; whatever is past it is the start of the body.
    std::string head_buf;
    head_buf.reserve(1024);
    try {
        co_await asio::async_read_until(*stream,
            asio::dynamic_buffer(head_buf, /*max_size=*/16 * 1024),
            "\r\n\r\n", asio::use_awaitable);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }

    auto parsed = parse_response_head(head_buf);
    if (!parsed) co_return std::nullopt;

    const auto cl_str = header_value(parsed->headers, "content-length");
    if (!cl_str) co_return std::nullopt;
    std::size_t body_len = 0;
    {
        const auto trimmed = trim(*cl_str);
        auto [ptr, ec] = std::from_chars(trimmed.data(),
                                         trimmed.data() + trimmed.size(),
                                         body_len);
        if (ec != std::errc{}) co_return std::nullopt;
    }
    if (body_len > 64 * 1024) co_return std::nullopt;   // sanity cap

    // Bytes already in head_buf past the "\r\n\r\n" delimiter belong to
    // the body. Move those across, then read the rest into the tail.
    const auto body_start = find_headers_end(head_buf);
    Response resp;
    resp.status = parsed->status;
    resp.content_type = header_value(parsed->headers, "content-type").value_or("");
    resp.body.resize(body_len);

    const std::size_t already = head_buf.size() - body_start;
    const std::size_t copy = std::min(already, body_len);
    if (copy > 0) {
        std::memcpy(resp.body.data(),
                    head_buf.data() + body_start,
                    copy);
    }
    if (copy < body_len) {
        try {
            co_await asio::async_read(*stream,
                asio::buffer(resp.body.data() + copy, body_len - copy),
                asio::use_awaitable);
        } catch (const std::system_error&) {
            co_return std::nullopt;
        }
    }

    timer.cancel();

    std::error_code ignore;
    stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ignore);
    stream->lowest_layer().close(ignore);

    co_return resp;
}

} // namespace cloak::http
