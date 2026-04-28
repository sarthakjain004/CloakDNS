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
#include "cloakdns/aliases.hpp"

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

void write_u16_be(span<byte> b, size_t off, uint16_t v) {
    b[off]     = byte{static_cast<uint8_t>((v >> 8) & 0xff)};
    b[off + 1] = byte{static_cast<uint8_t>(v & 0xff)};
}

uint16_t read_u16_be(span<const byte> b, size_t off) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(to_integer<uint8_t>(b[off])) << 8) |
         static_cast<uint16_t>(to_integer<uint8_t>(b[off + 1])));
}

} // namespace

// Encode a DNS message with the RFC 1035 §4.2.2 2-byte length prefix.
// Returned vector layout: [len_hi, len_lo, dns_bytes...].
vector<byte> dot_frame(span<const byte> msg) {
    if (msg.size() > 0xffffu)
        throw runtime_error{"dot_frame: message > 65535 bytes"};
    vector<byte> out(msg.size() + 2);
    write_u16_be(span<byte>{out}, 0,
                 static_cast<uint16_t>(msg.size()));
    std::copy(msg.begin(), msg.end(), out.begin() + 2);
    return out;
}

// Read one length-prefixed DNS message off `stream`. Times out via
// `timer` (caller arms it). Returns nullopt on timeout / IO error
// / framing error. Never throws on transport error; caller treats nullopt
// as "this attempt failed, try the next server."
asio::awaitable<optional<vector<byte>>>
dot_read_framed(asio::ssl::stream<asio::ip::tcp::socket>& stream,
                asio::steady_timer& /*timer*/) {
    array<byte, 2> len_buf{};
    try {
        co_await asio::async_read(stream, asio::buffer(len_buf.data(), 2),
                                  asio::use_awaitable);
    } catch (const system_error&) {
        co_return nullopt;
    }
    const uint16_t msg_len = read_u16_be(
        span<const byte>{len_buf.data(), 2}, 0);
    if (msg_len == 0) co_return nullopt;

    vector<byte> body(msg_len);
    try {
        co_await asio::async_read(stream, asio::buffer(body.data(), body.size()),
                                  asio::use_awaitable);
    } catch (const system_error&) {
        co_return nullopt;
    }
    co_return body;
}

// Single-shot DoT exchange: open TCP, TLS handshake (cert + pin verified
// inside), write framed query, read framed response. Returns nullopt on
// any failure mode that should let the caller try the next upstream.
// On success, the returned UpstreamReply carries both the response bytes
// and the ECH state observed on the handshake (Greased / Success /
// FailedRetry / NotTried).
//
// `outbound` already has the upstream's transaction ID written at offset 0
// and any EDNS padding applied — same convention as the UDP path in
// upstream.cpp.
asio::awaitable<optional<UpstreamReply>>
dot_try_once(asio::io_context& ctx,
             tls::Context& tls_ctx,
             const asio::ip::tcp::endpoint& server,
             const string& servername,
             span<const byte> outbound,
             chrono::milliseconds timeout) {
    using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

    // RFC 9849 §6.1.6: if the server rejects ECH and supplies fresh
    // retry_configs, the client may re-attempt the handshake exactly
    // once with those bytes. The loop runs at most twice; the second
    // pass uses the swapped-in config from maybe_apply_ech_retry.
    shared_ptr<SslStream> stream;
    asio::steady_timer timer{ctx};
    bool handshake_ok = false;

    for (int attempt = 0; attempt < 2 && !handshake_ok; ++attempt) {
        stream = make_shared<SslStream>(ctx, tls_ctx.asio_context());

        timer.cancel();
        timer.expires_after(timeout);
        timer.async_wait([stream](const error_code& ec) {
            if (!ec) {
                error_code ignore;
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
            co_return nullopt;
        }

        try {
            co_await stream->lowest_layer().async_connect(server, asio::use_awaitable);
            co_await stream->async_handshake(
                asio::ssl::stream_base::client, asio::use_awaitable);
            handshake_ok = true;
        } catch (const system_error&) {
            if (attempt == 0 &&
                tls::maybe_apply_ech_retry(tls_ctx, stream->native_handle())) {
                std::cerr << "ech: retry_configs received from "
                          << servername << " — retrying DoT handshake"
                          << std::endl;
                // Loop continues with a new stream + the freshly-swapped
                // ECHConfigList.
                continue;
            }
            co_return nullopt;
        }
    }
    if (!handshake_ok) co_return nullopt;

    auto framed = dot_frame(outbound);
    try {
        co_await asio::async_write(*stream,
            asio::buffer(framed.data(), framed.size()), asio::use_awaitable);
    } catch (const system_error&) {
        co_return nullopt;
    }

    auto resp = co_await dot_read_framed(*stream, timer);
    timer.cancel();

    // ECH status snapshot taken before we tear the connection down.
    // Successful handshakes report Success (or NotTried on non-ECH
    // builds / non-ECH connections).
    const tls::EchStatus ech = tls::ech_status(stream->native_handle());

    // Best-effort shutdown; ignore close-notify alerts.
    error_code ignore;
    stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ignore);
    stream->lowest_layer().close(ignore);

    if (!resp) co_return nullopt;
    co_return UpstreamReply{.bytes = std::move(*resp), .ech_status = ech};
}

} // namespace cloak::detail
