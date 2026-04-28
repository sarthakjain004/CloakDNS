#pragma once

#include <asio/ssl/context.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace cloak::tls {

// Compute the RFC 7469 SPKI pin for `cert`: base64(SHA-256(DER(SPKI))) with
// the "sha256/" prefix. The DER(SPKI) is the DER encoding of the cert's
// SubjectPublicKeyInfo field (per X.509 — the public key plus its alg id).
// Throws std::runtime_error on encode failure.
std::string compute_spki_pin(X509* cert);

// Live-mutable holder for the ECH parameters. Wraps the ECHConfigList
// bytes + outer SNI behind a shared_mutex so retry-config handling
// (Phase 1) and SIGHUP reload can swap the bytes in atomically without
// rebuilding the surrounding tls::Context. The mutex is `mutable` so a
// `const ContextConfig&` (which is what configure_ssl_for_connection
// takes, and what the verify_callback dereferences from ex_data) can
// still load the current snapshot.
//
// Pattern matches main.cpp's BlocklistPtr / g_blocklist_mu. Reads grab a
// shared_lock and copy the snapshot (cheap shared_ptr ref-bump);
// stores grab a unique_lock and swap.
class EchConfig {
public:
    struct Snapshot {
        // nullptr or empty vector → ECH disabled for this connection.
        // Held as shared_ptr so a swap doesn't invalidate snapshots
        // already loaded by in-flight handshakes.
        std::shared_ptr<const std::vector<std::byte>> bytes;
        // Cleartext outer SNI (decoy hostname). Empty → let OpenSSL
        // use the public_name embedded in the ECHConfigList.
        std::string outer_servername;
    };

    EchConfig() = default;
    EchConfig(const EchConfig&) = delete;
    EchConfig& operator=(const EchConfig&) = delete;
    EchConfig(EchConfig&&) = delete;
    EchConfig& operator=(EchConfig&&) = delete;

    Snapshot load() const {
        std::shared_lock lk{mu_};
        return state_;
    }

    void store(Snapshot s) {
        std::unique_lock lk{mu_};
        state_ = std::move(s);
    }

    bool enabled() const {
        std::shared_lock lk{mu_};
        return state_.bytes && !state_.bytes->empty();
    }

private:
    mutable std::shared_mutex mu_;
    Snapshot                  state_;
};

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

    // Encrypted Client Hello (RFC 9849). Empty / disabled when the build
    // doesn't have CLOAKDNS_HAVE_ECH or the user didn't configure
    // upstream.ech_enabled. Mutable at runtime via .store() so retry-
    // configs (RFC 9849 §6.1.6) and SIGHUP reload can swap fresh bytes.
    EchConfig ech;

    // Default-constructible so callers can populate field-by-field. Copy
    // and move are deleted because of the shared_mutex inside `ech` —
    // the codebase always builds ContextConfig in place inside a
    // unique_ptr (see upstream.cpp).
    ContextConfig() = default;
    ContextConfig(const ContextConfig&) = delete;
    ContextConfig& operator=(const ContextConfig&) = delete;
    ContextConfig(ContextConfig&&) = delete;
    ContextConfig& operator=(ContextConfig&&) = delete;
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

// Categorised result of a TLS handshake's ECH state, derived from
// SSL_ech_get1_status. Non-ECH builds always return NotTried.
enum class EchStatus {
    NotTried,    // ECH wasn't configured for this connection
    Greased,     // sent GREASE ECH (Phase 3) — observer can't tell from real
    Success,     // ECH ran end-to-end and the inner ClientHello was used
    FailedRetry, // server rejected ECH AND returned retry_configs (RFC 9849
                 //   §6.1.6) — caller should pull fresh bytes via
                 //   ech_retry_config and re-attempt the handshake
    Failed,      // some other ECH-related failure (no retry signal)
};

// Inspect ECH state on a handshaken (or failed-to-handshake) SSL*. Safe to
// call before async_handshake completes — returns NotTried in that case.
EchStatus ech_status(SSL* ssl) noexcept;

// Pull the server-supplied retry_configs (fresh ECHConfigList bytes) when
// ech_status() returned FailedRetry. Returns nullopt when no retry config
// is available, the build has no ECH support, or OpenSSL refused. The
// returned bytes are a copy — OpenSSL's heap allocation is freed inside.
std::optional<std::vector<std::byte>> ech_retry_config(SSL* ssl) noexcept;

// Decode a base64 string (with or without "=" padding; whitespace
// ignored). Returns nullopt on any invalid character or wrong length.
std::optional<std::vector<std::byte>> base64_decode(std::string_view input);

// Idempotent OpenSSL init. Called from Context's constructor; exposed so
// tests can pre-init without spinning up a full Context.
void init();

} // namespace cloak::tls
