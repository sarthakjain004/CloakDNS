#pragma once

#include <asio/ssl/context.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <memory>
#include <string>
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

// Idempotent OpenSSL init. Called from Context's constructor; exposed so
// tests can pre-init without spinning up a full Context.
void init();

} // namespace cloak::tls
