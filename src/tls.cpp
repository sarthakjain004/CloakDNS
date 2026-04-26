#include "cloakdns/tls.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <string>

namespace cloak::tls {
namespace {

std::atomic<int> g_ex_data_idx{-1};
std::once_flag   g_init_flag;

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const unsigned char* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        const std::uint32_t b0 = data[i];
        const std::uint32_t b1 = (i + 1 < len) ? data[i + 1] : 0u;
        const std::uint32_t b2 = (i + 2 < len) ? data[i + 2] : 0u;
        const std::uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? kBase64Alphabet[(triple >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? kBase64Alphabet[triple & 0x3F] : '=');
    }
    return out;
}

// X509_STORE_CTX verify hook. Runs once per cert in the chain.
//   preverify_ok=1 means OpenSSL's chain validation accepts this cert.
//   We then layer SPKI pinning on top: pinning runs only at the leaf
//   (depth 0); intermediates pass through as-is.
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
    if (!preverify_ok) return 0;
    if (X509_STORE_CTX_get_error_depth(ctx) != 0) return 1;

    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) return 0;

    SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(
        ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    if (!ssl) return 0;
    SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);

    const int idx = g_ex_data_idx.load(std::memory_order_acquire);
    if (idx < 0) return 1;

    auto* cfg = static_cast<const ContextConfig*>(
        SSL_CTX_get_ex_data(ssl_ctx, idx));
    if (!cfg || cfg->spki_pins.empty()) return 1;  // pinning disabled

    std::string actual;
    try {
        actual = compute_spki_pin(cert);
    } catch (const std::exception&) {
        return 0;
    }

    if (std::find(cfg->spki_pins.begin(), cfg->spki_pins.end(), actual)
        != cfg->spki_pins.end()) {
        return 1;
    }

    X509_STORE_CTX_set_error(ctx, X509_V_ERR_APPLICATION_VERIFICATION);
    return 0;
}

} // namespace

void init() {
    std::call_once(g_init_flag, [] {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                         OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
        const int idx = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
        if (idx < 0)
            throw std::runtime_error{"tls: SSL_CTX_get_ex_new_index failed"};
        g_ex_data_idx.store(idx, std::memory_order_release);
    });
}

std::string compute_spki_pin(X509* cert) {
    if (!cert) throw std::runtime_error{"tls: compute_spki_pin: null cert"};

    X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
    if (!pubkey) throw std::runtime_error{"tls: X509_get_X509_PUBKEY failed"};

    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(pubkey, &der);
    if (len <= 0 || !der)
        throw std::runtime_error{"tls: i2d_X509_PUBKEY failed"};

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<std::size_t>(len), hash);
    OPENSSL_free(der);

    return std::string{"sha256/"} + base64_encode(hash, SHA256_DIGEST_LENGTH);
}

Context::Context(const ContextConfig& cfg) : cfg_(&cfg) {
    init();
    ctx_ = SSL_CTX_new(TLS_client_method());
    if (!ctx_) throw std::runtime_error{"tls: SSL_CTX_new failed"};

    SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
    if (!SSL_CTX_set_default_verify_paths(ctx_)) {
        SSL_CTX_free(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error{"tls: SSL_CTX_set_default_verify_paths failed"};
    }
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_ex_data(ctx_, g_ex_data_idx.load(std::memory_order_acquire),
                        const_cast<ContextConfig*>(cfg_));
}

Context::~Context() {
    if (ctx_) SSL_CTX_free(ctx_);
}

} // namespace cloak::tls
