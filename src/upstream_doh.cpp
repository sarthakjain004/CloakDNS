// DNS-over-HTTPS forwarder (RFC 8484).
//
// Wire format: HTTP/1.1 POST /dns-query with body type
// application/dns-message and binary body == one DNS message. The
// response is the same content type and a binary DNS message. RFC 8484
// recommends HTTP/2; in practice Cloudflare, Quad9, and Google all
// accept HTTP/1.1, so we ship 1.1 here and revisit if multiplexing
// becomes a measurable win (it won't: DoH RTT is dominated by network,
// not head-of-line blocking on a 100-byte request).

#include "cloakdns/http_client.hpp"
#include "cloakdns/tls.hpp"
#include "cloakdns/upstream.hpp"
#include "cloakdns/aliases.hpp"

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace cloak::detail {

asio::awaitable<optional<UpstreamReply>>
doh_try_once(asio::io_context& ctx,
             tls::Context& tls_ctx,
             const asio::ip::tcp::endpoint& server,
             const string& host_header,
             const string& path,
             span<const byte> outbound,
             chrono::milliseconds timeout) {
    auto resp = co_await http::post_https_oneshot(
        ctx, tls_ctx, server, host_header, path,
        "application/dns-message", outbound, timeout);
    if (!resp) co_return nullopt;
    if (resp->status != 200) co_return nullopt;

    // RFC 8484 §6: a compliant server returns Content-Type
    // application/dns-message. Cloudflare and Quad9 both honor this; if
    // we ever see something else we should fail rather than try to parse
    // it as DNS.
    if (!resp->content_type.empty() &&
        resp->content_type.find("application/dns-message") == string::npos) {
        co_return nullopt;
    }

    co_return UpstreamReply{
        .bytes      = std::move(resp->body),
        .ech_status = resp->ech_status,
    };
}

} // namespace cloak::detail
