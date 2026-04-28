// DNS-over-TLS forwarder (RFC 7858).
//
// Wire format: a TCP connection wrapped in TLS, carrying length-prefixed
// DNS messages. The DNS message is preceded by a 2-byte big-endian length
// field (RFC 1035 §4.2.2). One query / one response per stream is the
// simplest pattern; we don't reuse the connection across queries in v1.
//
// Cert pinning: SPKI SHA-256 pins enforced via tls.cpp's verify callback.
// On TLS error we fail the query — never fall back to plain UDP.

#include "cloakdns/upstream.hpp"
#include "cloakdns/tls.hpp"

#include <asio/buffer.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

namespace cloak::detail {

namespace {

void write_u16_be(std::span<std::byte> b, std::size_t off, std::uint16_t v) {
    b[off]     = std::byte{static_cast<std::uint8_t>((v >> 8) & 0xff)};
    b[off + 1] = std::byte{static_cast<std::uint8_t>(v & 0xff)};
}

std::uint16_t read_u16_be(std::span<const std::byte> b, std::size_t off) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[off])) << 8) |
         static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[off + 1])));
}

} // namespace

// Encode a DNS message with the RFC 1035 §4.2.2 2-byte length prefix.
// Returned vector layout: [len_hi, len_lo, dns_bytes...].
std::vector<std::byte> dot_frame(std::span<const std::byte> msg) {
    if (msg.size() > 0xffffu)
        throw std::runtime_error{"dot_frame: message > 65535 bytes"};
    std::vector<std::byte> out(msg.size() + 2);
    write_u16_be(std::span<std::byte>{out}, 0,
                 static_cast<std::uint16_t>(msg.size()));
    std::copy(msg.begin(), msg.end(), out.begin() + 2);
    return out;
}

// Read one length-prefixed DNS message off `stream`. Times out via
// `timer` (caller arms it). Returns std::nullopt on timeout / IO error
// / framing error. Never throws on transport error; caller treats nullopt
// as "this attempt failed, try the next server."
asio::awaitable<std::optional<std::vector<std::byte>>>
dot_read_framed(asio::ssl::stream<asio::ip::tcp::socket>& stream,
                asio::steady_timer& /*timer*/) {
    std::array<std::byte, 2> len_buf{};
    try {
        co_await asio::async_read(stream, asio::buffer(len_buf.data(), 2),
                                  asio::use_awaitable);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }
    const std::uint16_t msg_len = read_u16_be(
        std::span<const std::byte>{len_buf.data(), 2}, 0);
    if (msg_len == 0) co_return std::nullopt;

    std::vector<std::byte> body(msg_len);
    try {
        co_await asio::async_read(stream, asio::buffer(body.data(), body.size()),
                                  asio::use_awaitable);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }
    co_return body;
}

// Single-shot DoT exchange: open TCP, TLS handshake (cert + pin verified
// inside), write framed query, read framed response. Returns nullopt on
// any failure mode that should let the caller try the next upstream.
//
// `outbound` already has the upstream's transaction ID written at offset 0
// and any EDNS padding applied — same convention as the UDP path in
// upstream.cpp.
asio::awaitable<std::optional<std::vector<std::byte>>>
dot_try_once(asio::io_context& ctx,
             tls::Context& tls_ctx,
             const asio::ip::tcp::endpoint& server,
             const std::string& servername,
             std::span<const std::byte> outbound,
             std::chrono::milliseconds timeout) {
    using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

    // RFC 9849 §6.1.6: if the server rejects ECH and supplies fresh
    // retry_configs, the client may re-attempt the handshake exactly
    // once with those bytes. The loop runs at most twice; the second
    // pass uses the swapped-in config from maybe_apply_ech_retry.
    std::shared_ptr<SslStream> stream;
    asio::steady_timer timer{ctx};
    bool handshake_ok = false;

    for (int attempt = 0; attempt < 2 && !handshake_ok; ++attempt) {
        stream = std::make_shared<SslStream>(ctx, tls_ctx.asio_context());

        timer.cancel();
        timer.expires_after(timeout);
        timer.async_wait([stream](const std::error_code& ec) {
            if (!ec) {
                std::error_code ignore;
                stream->lowest_layer().cancel(ignore);
            }
        });

        // TLS SNI + (optional) ECH: configure_ssl_for_connection installs
        // the SNI required by Cloudflare et al. when reached by IP, and
        // turns on ECH when the EchConfig snapshot carries bytes and the
        // build has CLOAKDNS_HAVE_ECH. Reads a snapshot — concurrent
        // SIGHUP / retry swaps don't affect this attempt.
        if (!servername.empty() &&
            !tls::configure_ssl_for_connection(stream->native_handle(),
                                               tls_ctx.config(), servername)) {
            co_return std::nullopt;
        }

        try {
            co_await stream->lowest_layer().async_connect(server, asio::use_awaitable);
            co_await stream->async_handshake(
                asio::ssl::stream_base::client, asio::use_awaitable);
            handshake_ok = true;
        } catch (const std::system_error&) {
            if (attempt == 0 &&
                tls::maybe_apply_ech_retry(tls_ctx, stream->native_handle())) {
                std::cerr << "ech: retry_configs received from "
                          << servername << " — retrying DoT handshake"
                          << std::endl;
                // Loop continues with a new stream + the freshly-swapped
                // ECHConfigList.
                continue;
            }
            co_return std::nullopt;
        }
    }
    if (!handshake_ok) co_return std::nullopt;

    auto framed = dot_frame(outbound);
    try {
        co_await asio::async_write(*stream,
            asio::buffer(framed.data(), framed.size()), asio::use_awaitable);
    } catch (const std::system_error&) {
        co_return std::nullopt;
    }

    auto resp = co_await dot_read_framed(*stream, timer);
    timer.cancel();

    // Best-effort shutdown; ignore close-notify alerts.
    std::error_code ignore;
    stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ignore);
    stream->lowest_layer().close(ignore);

    co_return resp;
}

} // namespace cloak::detail
