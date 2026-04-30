// DNS-over-HTTPS Resolver Adapter (RFC 8484).
//
// Wire format: HTTP/1.1 POST {path} with body type
// application/dns-message; response same content type, binary DNS
// message. RFC 8484 recommends HTTP/2 but Cloudflare/Quad9/Google all
// accept 1.1; revisit if multiplexing becomes a measurable win (not
// imminent — DoH RTT is dominated by network, not HoL blocking).

#include "cloakdns/resolver.hpp"

#include "cloakdns/aliases.hpp"
#include "cloakdns/http_client.hpp"
#include "cloakdns/tls.hpp"
#include "cloakdns/tls_adapter.hpp"

#include <tuple>
#include <utility>

namespace cloak::resolver {

namespace {

class DohAdapter final : public Adapter {
public:
    DohAdapter(asio::io_context& ctx, DohAdapterConfig cfg)
        : ctx_{ctx}, cfg_{std::move(cfg)} {
        // Http1Only ALPN is required by Cloudflare's DoH endpoint
        // since 2025-ish — without it the handshake fails with
        // "no application protocol".
        std::tie(tls_cfg_, tls_ctx_) = detail::make_tls_for_adapter(
            detail::TlsAdapterFields{
                .spki_pins            = cfg_.spki_pins,
                .servername           = cfg_.servername,
                .ca_file              = cfg_.ca_file,
                .ech_grease           = cfg_.ech_grease,
                .ech_outer_servername = cfg_.ech_outer_servername,
                .ech_config_list      = cfg_.ech_config_list,
            },
            tls::HttpAlpn::Http1Only);
    }

    asio::awaitable<optional<UpstreamReply>>
        try_once(span<const byte> outbound,
                 chrono::milliseconds timeout) override {
        auto resp = co_await http::post_https_oneshot(
            ctx_, *tls_ctx_, cfg_.server, cfg_.servername, cfg_.doh_path,
            "application/dns-message", outbound, timeout);
        if (!resp) co_return nullopt;
        if (resp->status != 200) co_return nullopt;

        // RFC 8484 §6: a compliant server returns Content-Type
        // application/dns-message. Anything else, fail rather than try
        // to parse it as DNS.
        if (!resp->content_type.empty() &&
            resp->content_type.find("application/dns-message") == string::npos) {
            co_return nullopt;
        }

        co_return UpstreamReply{
            .bytes      = std::move(resp->body),
            .ech_status = resp->ech_status,
        };
    }

    string_view  label()        const noexcept override { return cfg_.label; }
    tls::Context* tls_context() noexcept override        { return tls_ctx_.get(); }

private:
    asio::io_context&              ctx_;
    DohAdapterConfig               cfg_;
    unique_ptr<tls::ContextConfig> tls_cfg_;
    unique_ptr<tls::Context>       tls_ctx_;
};

} // anonymous namespace

AdapterPtr make_doh_adapter(asio::io_context& ctx, DohAdapterConfig cfg) {
    if (cfg.servername.empty())
        throw invalid_argument{"DohAdapter: servername (Host header) required"};
    return make_unique<DohAdapter>(ctx, std::move(cfg));
}

} // namespace cloak::resolver
