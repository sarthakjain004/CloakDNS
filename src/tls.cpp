#include "cloakdns/tls.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#ifdef CLOAKDNS_HAVE_ECH
#include <openssl/ech.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
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

    auto* pubkey = X509_get_X509_PUBKEY(cert);
    if (!pubkey) throw std::runtime_error{"tls: X509_get_X509_PUBKEY failed"};

    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(pubkey, &der);
    if (len <= 0 || !der)
        throw std::runtime_error{"tls: i2d_X509_PUBKEY failed"};

    // EVP_Digest is the 3.0-clean SHA-256 API; the legacy SHA256() helper
    // is deprecated under -DOPENSSL_NO_DEPRECATED_3_0.
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;
    if (EVP_Digest(der, static_cast<std::size_t>(len),
                   hash, &hash_len, EVP_sha256(), nullptr) != 1) {
        OPENSSL_free(der);
        throw std::runtime_error{"tls: EVP_Digest(sha256) failed"};
    }
    OPENSSL_free(der);

    return std::string{"sha256/"} + base64_encode(hash, hash_len);
}

bool ech_supported() noexcept {
#ifdef CLOAKDNS_HAVE_ECH
    return true;
#else
    return false;
#endif
}

bool configure_ssl_for_connection(SSL* ssl,
                                  const ContextConfig& cfg,
                                  const std::string& real_sni) {
    if (!ssl || real_sni.empty()) return false;

#ifdef CLOAKDNS_HAVE_ECH
    // Snapshot once: the underlying state can be swapped by SIGHUP /
    // retry-config handling between the load() and the SSL_* calls
    // below. The snapshot's shared_ptr keeps the bytes alive even if a
    // concurrent store() replaces the holder.
    const auto ech = cfg.ech.load();
    if (ech.bytes && !ech.bytes->empty()) {
        // Inner SNI: real hostname; cert verification matches against this
        // post-handshake. Goes inside the ECH-encrypted ClientHello.
        if (SSL_set_tlsext_host_name(ssl, real_sni.c_str()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        if (SSL_set1_host(ssl, real_sni.c_str()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        // ECHConfigList must be set before the outer-name override so the
        // outer-name validator inside OpenSSL has a config to validate
        // against. Order matters in OpenSSL 4.0+.
        const auto* bytes = reinterpret_cast<const unsigned char*>(
            ech.bytes->data());
        if (SSL_set1_ech_config_list(ssl, bytes, ech.bytes->size()) != 1) {
            ERR_print_errors_fp(stderr);
            return false;
        }
        // Outer SNI (cleartext): the decoy. When unset, OpenSSL uses the
        // public_name embedded in the ECHConfigList. The third arg is the
        // 4.0-introduced no_outer flag — 0 to honor our explicit name.
        if (!ech.outer_servername.empty()) {
            if (SSL_ech_set1_outer_server_name(ssl,
                    ech.outer_servername.c_str(), 0) != 1) {
                ERR_print_errors_fp(stderr);
                return false;
            }
        }
        return true;
    }
#endif

    // ECH disabled or unavailable: standard SNI path.
    if (SSL_set_tlsext_host_name(ssl, real_sni.c_str()) != 1) return false;
    if (SSL_set1_host(ssl, real_sni.c_str()) != 1) return false;
    return true;
}

EchStatus ech_status(SSL* ssl) noexcept {
#ifdef CLOAKDNS_HAVE_ECH
    if (!ssl) return EchStatus::NotTried;
    char* inner = nullptr;
    char* outer = nullptr;
    const int rc = SSL_ech_get1_status(ssl, &inner, &outer);
    if (inner) OPENSSL_free(inner);
    if (outer) OPENSSL_free(outer);
    switch (rc) {
        case SSL_ECH_STATUS_SUCCESS:               return EchStatus::Success;
        case SSL_ECH_STATUS_GREASE:
        case SSL_ECH_STATUS_GREASE_ECH:            return EchStatus::Greased;
        case SSL_ECH_STATUS_FAILED_ECH:
        case SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:   return EchStatus::FailedRetry;
        case SSL_ECH_STATUS_NOT_TRIED:
        case SSL_ECH_STATUS_NOT_CONFIGURED:        return EchStatus::NotTried;
        default:                                   return EchStatus::Failed;
    }
#else
    (void)ssl;
    return EchStatus::NotTried;
#endif
}

std::optional<std::vector<std::byte>> ech_retry_config(SSL* ssl) noexcept {
#ifdef CLOAKDNS_HAVE_ECH
    if (!ssl) return std::nullopt;
    unsigned char* p = nullptr;
    std::size_t    len = 0;
    const int rc = SSL_ech_get1_retry_config(ssl, &p, &len);
    if (rc != 1 || !p || len == 0) {
        if (p) OPENSSL_free(p);
        return std::nullopt;
    }
    std::vector<std::byte> out(len);
    std::memcpy(out.data(), p, len);
    OPENSSL_free(p);
    return out;
#else
    (void)ssl;
    return std::nullopt;
#endif
}

std::optional<std::vector<std::byte>> base64_decode(std::string_view input) {
    static constexpr std::int8_t kInvalid = -1;
    static constexpr auto kLookup = [] {
        std::array<std::int8_t, 256> t{};
        for (auto& v : t) v = kInvalid;
        for (int i = 0; i < 26; ++i) t[std::size_t('A' + i)] = static_cast<std::int8_t>(i);
        for (int i = 0; i < 26; ++i) t[std::size_t('a' + i)] = static_cast<std::int8_t>(26 + i);
        for (int i = 0; i < 10; ++i) t[std::size_t('0' + i)] = static_cast<std::int8_t>(52 + i);
        t[std::size_t('+')] = 62;
        t[std::size_t('/')] = 63;
        return t;
    }();

    // Strip whitespace into a packed buffer.
    std::string packed;
    packed.reserve(input.size());
    for (char c : input) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        packed.push_back(c);
    }
    if (packed.empty()) return std::vector<std::byte>{};
    if (packed.size() % 4 != 0) return std::nullopt;

    // Count trailing '=' padding (0–2).
    std::size_t pad = 0;
    if (packed.size() >= 1 && packed[packed.size() - 1] == '=') {
        pad = 1;
        if (packed.size() >= 2 && packed[packed.size() - 2] == '=') pad = 2;
    }

    std::vector<std::byte> out;
    out.reserve(packed.size() / 4 * 3);
    for (std::size_t i = 0; i + 4 <= packed.size(); i += 4) {
        const auto a = kLookup[std::uint8_t(packed[i])];
        const auto b = kLookup[std::uint8_t(packed[i + 1])];
        const auto c_idx = (packed[i + 2] == '=') ? 0 : kLookup[std::uint8_t(packed[i + 2])];
        const auto d_idx = (packed[i + 3] == '=') ? 0 : kLookup[std::uint8_t(packed[i + 3])];
        if (a == kInvalid || b == kInvalid ||
            (packed[i + 2] != '=' && c_idx == kInvalid) ||
            (packed[i + 3] != '=' && d_idx == kInvalid)) {
            return std::nullopt;
        }
        const std::uint32_t triple =
            (std::uint32_t(a) << 18) | (std::uint32_t(b) << 12) |
            (std::uint32_t(c_idx) << 6) | std::uint32_t(d_idx);
        out.push_back(std::byte((triple >> 16) & 0xff));
        if (i + 4 != packed.size() || pad < 2)
            out.push_back(std::byte((triple >> 8) & 0xff));
        if (i + 4 != packed.size() || pad < 1)
            out.push_back(std::byte(triple & 0xff));
    }
    return out;
}

Context::Context(ContextConfig& cfg)
    : ctx_(asio::ssl::context::tls_client), cfg_(&cfg) {
    init();
    SSL_CTX* raw = ctx_.native_handle();
    SSL_CTX_set_min_proto_version(raw, TLS1_2_VERSION);
    if (!SSL_CTX_set_default_verify_paths(raw))
        throw std::runtime_error{"tls: SSL_CTX_set_default_verify_paths failed"};
    SSL_CTX_set_verify(raw, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_ex_data(raw, g_ex_data_idx.load(std::memory_order_acquire), cfg_);
}

bool maybe_apply_ech_retry(Context& ctx, SSL* ssl) {
    if (ech_status(ssl) != EchStatus::FailedRetry) return false;
    auto retry = ech_retry_config(ssl);
    if (!retry) return false;
    auto& ech = ctx.ech_config();
    auto current = ech.load();
    EchConfig::Snapshot fresh;
    fresh.bytes = std::make_shared<const std::vector<std::byte>>(std::move(*retry));
    fresh.outer_servername = current.outer_servername;
    ech.store(std::move(fresh));
    return true;
}

} // namespace cloak::tls
