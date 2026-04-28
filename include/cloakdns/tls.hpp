#pragma once

#include <asio/ssl/context.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace cloak::tls {

// Compute the RFC 7469 SPKI pin for `cert`: base64(SHA-256(DER(SPKI))) with
// the "sha256/" prefix. The DER(SPKI) is the DER encoding of the cert's
// SubjectPublicKeyInfo field (per X.509 — the public key plus its alg id).
// Throws std::runtime_error on encode failure.
std::string compute_spki_pin(X509* cert);

struct ContextConfig {
    // Accept any pin in this set. Empty disables pinning (chain validation
    // only). Wire format: "sha256/<base64>", as produced by compute_spki_pin
    // and as written in cloakdns.toml. We never disable chain validation —
    // pinning is additive, not a replacement.
    std::vector<std::string> spki_pins;

    // SNI to send during TLS ClientHello. For DoT to "1.1.1.1:853" set this
    // to "cloudflare-dns.com" so the cert's SAN check succeeds. Required
    // when the upstream is reached by IP literal.
    std::string servername;

    // ECH ClientHello outer SNI (decoy). Empty when ECH is disabled. When
    // set, this is the hostname an on-path observer sees in the
    // ClientHello; the real SNI travels encrypted inside the ECH
    // extension. Typical: a CDN-managed alias like "cloudflare-ech.com".
    std::string ech_outer_servername;

    // Binary ECHConfigList (RFC 9849). Empty disables ECH. When non-empty
    // and the build was compiled with CLOAKDNS_HAVE_ECH (OpenSSL 4.0+),
    // configure_ssl_for_connection() turns on ECH for the handshake.
    // Unused on builds without ECH support, even if populated — silently
    // falls back to plain SNI rather than failing closed.
    std::vector<std::byte> ech_config_list;
};

// Wraps an asio::ssl::context (which owns the underlying SSL_CTX*) with
// our verify callback installed and the pin set stashed in SSL_CTX
// ex-data. Lifetime invariant: callers must keep the ContextConfig
// referenced by the Context alive for the Context's lifetime — we hold
// a pointer to it, not a copy, so reload semantics match the rest of
// the codebase (Blocklist hot reload).
class Context {
public:
    explicit Context(const ContextConfig& cfg);
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    asio::ssl::context&       asio_context() noexcept       { return ctx_; }
    const asio::ssl::context& asio_context() const noexcept { return ctx_; }

    SSL_CTX*             native() noexcept       { return ctx_.native_handle(); }
    const ContextConfig& config() const noexcept { return *cfg_; }

private:
    asio::ssl::context   ctx_;
    const ContextConfig* cfg_;
};

// Apply per-connection TLS settings on a fresh SSL*. Always sets the
// SNI hostname (`real_sni`) and the cert SAN-match host. When the
// ContextConfig carries an ECHConfigList AND the build has ECH support,
// also wires up the encrypted ClientHello (real_sni becomes the inner
// SNI; cfg.ech_outer_servername becomes the outer/decoy). Returns false
// if any OpenSSL call fails — the caller should abort the connection.
bool configure_ssl_for_connection(SSL* ssl,
                                  const ContextConfig& cfg,
                                  const std::string& real_sni);

// True if this build was compiled with ECH support (OpenSSL 4.0+ and
// CLOAKDNS_ECH=ON). Use to fail config validation early when the user
// asks for ECH but the binary can't deliver it.
bool ech_supported() noexcept;

// Decode a base64 string (with or without "=" padding; whitespace
// ignored). Returns nullopt on any invalid character or wrong length.
std::optional<std::vector<std::byte>> base64_decode(std::string_view input);

// Idempotent OpenSSL init. Called from Context's constructor; exposed so
// tests can pre-init without spinning up a full Context.
void init();

} // namespace cloak::tls
