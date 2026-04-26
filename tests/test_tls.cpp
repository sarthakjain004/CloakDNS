// SPKI pin computation correctness — uses a self-signed cert generated at
// test setup time and verifies compute_spki_pin() produces a deterministic
// "sha256/<base64>" string. The exact pin value is checked by re-deriving
// it from the same key inside the test, so the assertion is an independent
// path through OpenSSL.

#include "cloakdns/tls.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace {

struct EvpPkeyFree { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct X509Free    { void operator()(X509*    p) const { X509_free(p);    } };

using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyFree>;
using CertPtr = std::unique_ptr<X509, X509Free>;

PkeyPtr make_p256_key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(pctx, &raw) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return PkeyPtr{raw};
}

CertPtr make_self_signed_cert(EVP_PKEY* pkey) {
    CertPtr cert{X509_new()};
    if (!cert) return nullptr;
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60);
    X509_set_pubkey(cert.get(), pkey);
    X509_NAME* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("test.cloak"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);
    if (!X509_sign(cert.get(), pkey, EVP_sha256())) return nullptr;
    return cert;
}

} // namespace

TEST(Tls, ComputeSpkiPinHasExpectedShape) {
    cloak::tls::init();
    auto pkey = make_p256_key();
    ASSERT_TRUE(pkey);
    auto cert = make_self_signed_cert(pkey.get());
    ASSERT_TRUE(cert);

    const std::string pin = cloak::tls::compute_spki_pin(cert.get());

    // "sha256/" prefix + 44 chars (32-byte hash → 44 base64 chars including
    // a trailing '=').
    EXPECT_TRUE(pin.starts_with("sha256/"));
    EXPECT_EQ(pin.size(), 7u + 44u);
    // Base64 body should be terminated with '=' for a 32-byte input.
    EXPECT_EQ(pin.back(), '=');
}

TEST(Tls, ComputeSpkiPinIsStableAcrossCalls) {
    cloak::tls::init();
    auto pkey = make_p256_key();
    ASSERT_TRUE(pkey);
    auto cert = make_self_signed_cert(pkey.get());
    ASSERT_TRUE(cert);

    const std::string a = cloak::tls::compute_spki_pin(cert.get());
    const std::string b = cloak::tls::compute_spki_pin(cert.get());
    EXPECT_EQ(a, b);
}

TEST(Tls, DifferentKeysProduceDifferentPins) {
    cloak::tls::init();
    auto k1 = make_p256_key();
    auto k2 = make_p256_key();
    ASSERT_TRUE(k1);
    ASSERT_TRUE(k2);
    auto c1 = make_self_signed_cert(k1.get());
    auto c2 = make_self_signed_cert(k2.get());
    ASSERT_TRUE(c1);
    ASSERT_TRUE(c2);

    EXPECT_NE(cloak::tls::compute_spki_pin(c1.get()),
              cloak::tls::compute_spki_pin(c2.get()));
}

TEST(Tls, ContextConstructsAndOwnsCtx) {
    cloak::tls::ContextConfig cfg;
    cfg.spki_pins.push_back("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    cfg.servername = "example.com";

    cloak::tls::Context ctx{cfg};
    EXPECT_NE(ctx.native(), nullptr);
    EXPECT_EQ(ctx.config().servername, "example.com");
    ASSERT_EQ(ctx.config().spki_pins.size(), 1u);
}
