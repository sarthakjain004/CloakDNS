// DNS-over-TLS Resolver Adapter (RFC 7858).
//
// Wire format: TCP + TLS, length-prefixed DNS messages (RFC 1035 §4.2.2).
// One query / one response per stream. Cert pinning (SPKI SHA-256) is
// enforced by tls.cpp's verify callback. ECH retry_configs (RFC 9849
// §6.1.6) handled by re-running the handshake exactly once with the
// fresh bytes.
//
// The Adapter does framing + handshake + one wire exchange. ID rewrite,
// EDNS0 padding, retry across attempts, and RFC 5452 question-echo all
// live on the Resolver (ADR 0002).

#include "cloakdns/resolver.hpp"

#include "cloakdns/aliases.hpp"
#include "cloakdns/tls.hpp"
#include "cloakdns/tls_adapter.hpp"
#include "cloakdns/wire_endian.hpp"

#include <asio/buffer.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include <openssl/ssl.h>

#include <algorithm>
#include <iostream>
#include <utility>

namespace cloak::resolver {

namespace {

// Encode a DNS message with the RFC 1035 §4.2.2 2-byte length prefix.
vector<byte> dot_frame(span<const byte> msg) {
    if (msg.size() > 0xffffu)
        throw runtime_error{"dot_frame: message > 65535 bytes"};
    vector<byte> out(msg.size() + 2);
    write_u16_be(span<byte>{out}, 0, static_cast<uint16_t>(msg.size()));
    std::copy(msg.begin(), msg.end(), out.begin() + 2);
    return out;
}

asio::awaitable<optional<vector<byte>>>
dot_read_framed(asio::ssl::stream<asio::ip::tcp::socket>& stream) {
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

class DotAdapter final : public Adapter {
public:
    DotAdapter(asio::io_context& ctx, DotAdapterConfig cfg)
        : ctx_{ctx}, cfg_{std::move(cfg)} {
        std::tie(tls_cfg_, tls_ctx_) = detail::make_tls_for_adapter(
            detail::TlsAdapterFields{
                .spki_pins            = cfg_.spki_pins,
                .servername           = cfg_.servername,
                .ca_file              = cfg_.ca_file,
                .ech_grease           = cfg_.ech_grease,
                .ech_outer_servername = cfg_.ech_outer_servername,
                .ech_config_list      = cfg_.ech_config_list,
            },
            tls::HttpAlpn::None);
    }

    asio::awaitable<optional<UpstreamReply>>
        try_once(span<const byte> outbound,
                 chrono::milliseconds timeout) override {
        using SslStream = asio::ssl::stream<asio::ip::tcp::socket>;

        // RFC 9849 §6.1.6: one ECH retry permitted with retry_configs.
        shared_ptr<SslStream> stream;
        asio::steady_timer    timer{ctx_};
        bool                  handshake_ok = false;

        for (int attempt = 0; attempt < 2 && !handshake_ok; ++attempt) {
            stream = make_shared<SslStream>(ctx_, tls_ctx_->asio_context());

            timer.cancel();
            timer.expires_after(timeout);
            timer.async_wait([stream](const error_code& ec) {
                if (!ec) {
                    error_code ignore;
                    stream->lowest_layer().cancel(ignore);
                }
            });

            if (!cfg_.servername.empty() &&
                !tls::configure_ssl_for_connection(
                    stream->native_handle(), tls_ctx_->config(),
                    cfg_.servername)) {
                co_return nullopt;
            }

            try {
                co_await stream->lowest_layer().async_connect(
                    cfg_.server, asio::use_awaitable);
                co_await stream->async_handshake(
                    asio::ssl::stream_base::client, asio::use_awaitable);
                handshake_ok = true;
            } catch (const system_error&) {
                if (attempt == 0 &&
                    tls::maybe_apply_ech_retry(*tls_ctx_, stream->native_handle())) {
                    std::cerr << "ech: retry_configs received from "
                              << cfg_.servername
                              << " — retrying DoT handshake" << std::endl;
                    continue;
                }
                co_return nullopt;
            }
        }
        if (!handshake_ok) co_return nullopt;

        auto framed = dot_frame(outbound);
        try {
            co_await asio::async_write(*stream,
                asio::buffer(framed.data(), framed.size()),
                asio::use_awaitable);
        } catch (const system_error&) {
            co_return nullopt;
        }

        auto resp = co_await dot_read_framed(*stream);
        timer.cancel();

        const tls::EchStatus ech = tls::ech_status(stream->native_handle());

        error_code ignore;
        stream->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ignore);
        stream->lowest_layer().close(ignore);

        if (!resp) co_return nullopt;
        co_return UpstreamReply{.bytes = std::move(*resp), .ech_status = ech};
    }

    string_view  label()        const noexcept override { return cfg_.label; }
    tls::Context* tls_context() noexcept override        { return tls_ctx_.get(); }

private:
    asio::io_context&            ctx_;
    DotAdapterConfig             cfg_;
    unique_ptr<tls::ContextConfig> tls_cfg_;
    unique_ptr<tls::Context>     tls_ctx_;
};

} // anonymous namespace

AdapterPtr make_dot_adapter(asio::io_context& ctx, DotAdapterConfig cfg) {
    if (cfg.servername.empty())
        throw invalid_argument{"DotAdapter: servername required"};
    return make_unique<DotAdapter>(ctx, std::move(cfg));
}

} // namespace cloak::resolver
