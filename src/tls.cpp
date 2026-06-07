#include "cloakdns/tls.hpp"
#include "cloakdns/aliases.hpp"

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
#include <filesystem>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace cloak::tls {
namespace {

atomic<int> g_ex_data_idx{-1};
std::once_flag   g_init_flag;

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64_encode(const unsigned char* data, size_t len) {
    string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t b0 = data[i];
        const uint32_t b1 = (i + 1 < len) ? data[i + 1] : 0u;
        const uint32_t b2 = (i + 2 < len) ? data[i + 2] : 0u;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
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

    string actual;
    try {
        actual = compute_spki_pin(cert);
    } catch (const exception&) {
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
            throw runtime_error{"tls: SSL_CTX_get_ex_new_index failed"};
        g_ex_data_idx.store(idx, std::memory_order_release);
    });
}

string compute_spki_pin(X509* cert) {
    if (!cert) throw runtime_error{"tls: compute_spki_pin: null cert"};

    auto* pubkey = X509_get_X509_PUBKEY(cert);
    if (!pubkey) throw runtime_error{"tls: X509_get_X509_PUBKEY failed"};

    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(pubkey, &der);
    if (len <= 0 || !der)
        throw runtime_error{"tls: i2d_X509_PUBKEY failed"};

    // EVP_Digest is the 3.0-clean SHA-256 API; the legacy SHA256() helper
    // is deprecated under -DOPENSSL_NO_DEPRECATED_3_0.
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int  hash_len = 0;
    if (EVP_Digest(der, static_cast<size_t>(len),
                   hash, &hash_len, EVP_sha256(), nullptr) != 1) {
        OPENSSL_free(der);
        throw runtime_error{"tls: EVP_Digest(sha256) failed"};
    }
    OPENSSL_free(der);

    return string{"sha256/"} + base64_encode(hash, hash_len);
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
                                  const string& real_sni) {
    if (!ssl || real_sni.empty()) return false;

    // Start from a clean thread-local ERR queue. This runs per-connection
    // on shared Asio worker threads; a stale entry left here (or by a prior
    // OpenSSL call on this thread) would otherwise be misattributed by the
    // ERR_print_errors_fp diagnostics below or by validate_ech_config_list /
    // maybe_apply_ech_retry running later on the same thread.
    ERR_clear_error();

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
        // Set the ECHConfigList before the outer-name override. The order
        // is deliberate and safe (the outer name is a public_name override;
        // the config is what defines the valid public_name), but note it is
        // NOT a documented OpenSSL 4.0 requirement — it was lore from the
        // ECH draft feature branch. Keep it, but don't treat it as a
        // load-bearing API contract.
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
        ERR_clear_error();   // drain any non-fatal entries before success
        return true;
    }
#endif

    // ECH disabled or unavailable: standard SNI path.
    if (SSL_set_tlsext_host_name(ssl, real_sni.c_str()) != 1) return false;
    if (SSL_set1_host(ssl, real_sni.c_str()) != 1) return false;

#ifdef CLOAKDNS_HAVE_ECH
    // RFC 9849 §6.2: when ECH is supported by the build but no real
    // config is loaded, the client SHOULD emit a GREASE ECH extension
    // so an on-path observer can't tell us apart from a real-ECH
    // client. Opt-in via cfg.ech_grease (default off, so the wire
    // shape doesn't change unless the operator asks).
    if (cfg.ech_grease) {
        SSL_set_options(ssl, SSL_OP_ECH_GREASE);
    }
#endif
    ERR_clear_error();   // drain any non-fatal entries before success
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
    // The failure codes can leave diagnostics on the queue; drain them so a
    // later ech_retry_config / validate_ech_config_list on this worker
    // thread starts from a clean ERR queue.
    ERR_clear_error();
    switch (rc) {
        case SSL_ECH_STATUS_SUCCESS:               return EchStatus::Success;
        case SSL_ECH_STATUS_GREASE:
        case SSL_ECH_STATUS_GREASE_ECH:            return EchStatus::Greased;
        // FAILED_ECH: server rejected ECH but supplied retry_configs whose
        // public_name authenticated — safe to honour, so flag one retry.
        case SSL_ECH_STATUS_FAILED_ECH:            return EchStatus::FailedRetry;
        // FAILED_ECH_BAD_NAME: retry_configs arrived but the public_name
        // certificate did NOT verify. RFC 9849 §6.1.6 forbids trusting
        // retry_configs from an unauthenticated name, so do NOT retry —
        // report a plain failure. (Any other unhandled status — the
        // cert-verify BAD_NAME, the NULL-arg BAD_CALL, or the server-side
        // BACKEND code — also collapses to Failed via the default arm.)
        case SSL_ECH_STATUS_FAILED_ECH_BAD_NAME:   return EchStatus::Failed;
        case SSL_ECH_STATUS_NOT_TRIED:
        case SSL_ECH_STATUS_NOT_CONFIGURED:        return EchStatus::NotTried;
        default:                                   return EchStatus::Failed;
    }
#else
    (void)ssl;
    return EchStatus::NotTried;
#endif
}

string_view to_string(EchStatus s) noexcept {
    switch (s) {
      case EchStatus::Success:     return "success";
      case EchStatus::Greased:     return "greased";
      case EchStatus::FailedRetry: return "failed_retry_available";
      case EchStatus::Failed:      return "failed";
      case EchStatus::NotTried:    return "not_tried";
    }
    return "not_tried";
}

optional<vector<byte>> ech_retry_config(SSL* ssl) noexcept {
#ifdef CLOAKDNS_HAVE_ECH
    if (!ssl) return nullopt;
    unsigned char* p = nullptr;
    size_t    len = 0;
    const int rc = SSL_ech_get1_retry_config(ssl, &p, &len);
    if (rc != 1 || !p || len == 0) {
        if (p) OPENSSL_free(p);
        ERR_clear_error();
        return nullopt;
    }
    vector<byte> out(len);
    std::memcpy(out.data(), p, len);
    OPENSSL_free(p);
    return out;
#else
    (void)ssl;
    return nullopt;
#endif
}

optional<vector<byte>> base64_decode(string_view input) {
    static constexpr int8_t kInvalid = -1;
    static constexpr auto kLookup = [] {
        array<int8_t, 256> t{};
        for (auto& v : t) v = kInvalid;
        for (int i = 0; i < 26; ++i) t[size_t('A' + i)] = static_cast<int8_t>(i);
        for (int i = 0; i < 26; ++i) t[size_t('a' + i)] = static_cast<int8_t>(26 + i);
        for (int i = 0; i < 10; ++i) t[size_t('0' + i)] = static_cast<int8_t>(52 + i);
        t[size_t('+')] = 62;
        t[size_t('/')] = 63;
        return t;
    }();

    // Strip whitespace into a packed buffer.
    string packed;
    packed.reserve(input.size());
    for (char c : input) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
        packed.push_back(c);
    }
    if (packed.empty()) return vector<byte>{};
    if (packed.size() % 4 != 0) return nullopt;

    // Count trailing '=' padding (0–2).
    size_t pad = 0;
    if (packed.size() >= 1 && packed[packed.size() - 1] == '=') {
        pad = 1;
        if (packed.size() >= 2 && packed[packed.size() - 2] == '=') pad = 2;
    }

    vector<byte> out;
    out.reserve(packed.size() / 4 * 3);
    for (size_t i = 0; i + 4 <= packed.size(); i += 4) {
        const auto a = kLookup[uint8_t(packed[i])];
        const auto b = kLookup[uint8_t(packed[i + 1])];
        const auto c_idx = (packed[i + 2] == '=') ? 0 : kLookup[uint8_t(packed[i + 2])];
        const auto d_idx = (packed[i + 3] == '=') ? 0 : kLookup[uint8_t(packed[i + 3])];
        if (a == kInvalid || b == kInvalid ||
            (packed[i + 2] != '=' && c_idx == kInvalid) ||
            (packed[i + 3] != '=' && d_idx == kInvalid)) {
            return nullopt;
        }
        const uint32_t triple =
            (uint32_t(a) << 18) | (uint32_t(b) << 12) |
            (uint32_t(c_idx) << 6) | uint32_t(d_idx);
        out.push_back(byte((triple >> 16) & 0xff));
        if (i + 4 != packed.size() || pad < 2)
            out.push_back(byte((triple >> 8) & 0xff));
        if (i + 4 != packed.size() || pad < 1)
            out.push_back(byte(triple & 0xff));
    }
    return out;
}

namespace {

#ifdef _WIN32
// Locate `cacert.pem` next to the running executable so the operator
// can drop the Mozilla CA bundle alongside cloakdns.exe and have it
// picked up automatically. Returns empty when the file isn't there.
string discover_windows_ca_file() {
    array<wchar_t, MAX_PATH> buf{};
    const DWORD n = GetModuleFileNameW(nullptr, buf.data(),
                                       static_cast<DWORD>(buf.size()));
    if (n == 0 || n == buf.size()) return {};
    fs::path exe{std::wstring{buf.data(), n}};
    auto candidate = exe.parent_path() / "cacert.pem";
    error_code ec;
    if (fs::exists(candidate, ec))
        return candidate.string();
    candidate = fs::current_path(ec) / "cacert.pem";
    if (!ec && fs::exists(candidate, ec))
        return candidate.string();
    return {};
}
#endif

// Wire trust anchors onto `raw`. Explicit ca_file takes priority; on
// Windows we additionally auto-discover `cacert.pem` next to the
// executable because OpenSSL 4 distributions for Windows commonly
// ship without a default trust store and chain validation would
// otherwise always fail. System defaults (POSIX paths, SSL_CERT_FILE
// env) are layered on regardless so a configured ca_file augments
// rather than replaces them.
void load_trust_anchors(SSL_CTX* raw, const string& ca_file) {
    string effective = ca_file;
#ifdef _WIN32
    if (effective.empty()) effective = discover_windows_ca_file();
#endif
    if (!effective.empty()) {
        if (SSL_CTX_load_verify_locations(raw, effective.c_str(), nullptr) != 1) {
            throw runtime_error{
                "tls: SSL_CTX_load_verify_locations(" + effective + ") failed"};
        }
        std::cerr << "tls: trust anchors loaded from " << effective << std::endl;
    }
    // Always try platform defaults too (no-op on Windows when nothing
    // is compiled in; SSL_CERT_FILE env var is honoured here).
    (void)SSL_CTX_set_default_verify_paths(raw);
}

} // namespace

Context::Context(ContextConfig& cfg)
    : ctx_(asio::ssl::context::tls_client), cfg_(&cfg) {
    init();
    SSL_CTX* raw = ctx_.native_handle();
    SSL_CTX_set_min_proto_version(raw, TLS1_2_VERSION);
    load_trust_anchors(raw, cfg.ca_file);
    SSL_CTX_set_verify(raw, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_ex_data(raw, g_ex_data_idx.load(std::memory_order_acquire), cfg_);

    // ALPN: set on the SSL_CTX so every spawned SSL inherits it. The
    // wire encoding is length-prefixed protocol identifiers per RFC
    // 7301 — currently only "http/1.1" since DoH speaks HTTP/1.1.
    if (cfg_->alpn == HttpAlpn::Http1Only) {
        static const unsigned char kAlpnHttp1[] = {
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'
        };
        // SSL_CTX_set_alpn_protos returns 0 on SUCCESS (inverted).
        if (SSL_CTX_set_alpn_protos(raw, kAlpnHttp1, sizeof(kAlpnHttp1)) != 0)
            throw runtime_error{"tls: SSL_CTX_set_alpn_protos(http/1.1) failed"};
    }
}

optional<string>
validate_ech_config_list(span<const byte> bytes) noexcept {
#ifdef CLOAKDNS_HAVE_ECH
    if (bytes.empty()) return string{"ECHConfigList is empty"};
    SSL_CTX* tmp_ctx = SSL_CTX_new(TLS_client_method());
    if (!tmp_ctx) return string{"validate: SSL_CTX_new failed"};
    SSL* tmp_ssl = SSL_new(tmp_ctx);
    if (!tmp_ssl) {
        SSL_CTX_free(tmp_ctx);
        return string{"validate: SSL_new failed"};
    }
    const auto* p = reinterpret_cast<const unsigned char*>(bytes.data());
    // Clear first so the ERR_get_error() below reflects only THIS probe —
    // the resulting string is surfaced to the user by config.cpp, so a
    // leftover unrelated error would produce a misleading load failure.
    ERR_clear_error();
    const int rc = SSL_set1_ech_config_list(tmp_ssl, p, bytes.size());
    SSL_free(tmp_ssl);
    SSL_CTX_free(tmp_ctx);
    if (rc != 1) {
        // ERR_get_error / ERR_error_string_n give us the OpenSSL
        // diagnostic. Drain all errors and return the first.
        unsigned long err = ERR_get_error();
        char buf[256] = {0};
        ERR_error_string_n(err, buf, sizeof(buf));
        // Drain any remaining errors so they don't pollute later calls.
        while (ERR_get_error()) {}
        return string{"ECHConfigList rejected by OpenSSL: "} + buf;
    }
    return nullopt;
#else
    (void)bytes;
    return nullopt;
#endif
}

bool maybe_apply_ech_retry(Context& ctx, SSL* ssl) {
    if (ech_status(ssl) != EchStatus::FailedRetry) return false;
    auto retry = ech_retry_config(ssl);
    if (!retry) return false;
    // Atomic read-modify-write: swap in the fresh retry_config bytes while
    // preserving outer_servername, with no load()/store() gap that a
    // concurrent retry (a second in-flight handshake to the same upstream)
    // or a SIGHUP reload could interleave with and clobber. The server just
    // told us the previous config was stale, so stamp fetched_at = now() to
    // keep staleness tracking honest.
    ctx.ech_config().update([&](EchConfig::Snapshot& s) {
        s.bytes      = make_shared<const vector<byte>>(std::move(*retry));
        s.fetched_at = chrono::system_clock::now();
        // s.outer_servername left untouched — preserved atomically.
    });
    return true;
}

} // namespace cloak::tls
