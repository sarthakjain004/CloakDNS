# SPKI cert pinning (RFC 7469)

In addition to standard certificate-chain validation, CloakDNS can
**pin** the upstream resolver's TLS certificate to a specific
public-key hash. If the upstream's cert chain validates fine but
its leaf cert's public-key hash doesn't match a configured pin, the
connection is refused — a backstop against a CA mis-issuance or
state-actor-style attacker forging a "valid" cert for your upstream.

The hash form is RFC 7469 SPKI pinning: SHA-256 of the
`SubjectPublicKeyInfo` (DER form), base64-encoded, prefixed with
`sha256/`.

---

## The problem

TLS certificate validation rests on the assumption that **only the
real owner of `cloudflare-dns.com` can get a public CA to issue a
cert for it**. Most of the time this works: a CA wouldn't issue
`cloudflare-dns.com` to anyone but Cloudflare. But:

- A CA can be **compromised** (the DigiNotar 2011 incident issued
  fraudulent certs for `*.google.com`, `addons.mozilla.org`, etc.).
- A CA can be **coerced** by a state actor (Symantec was caught
  issuing test certs for `google.com` without authorisation in
  2015).
- A CA can be **mis-configured** by an over-eager DV provider
  (numerous incidents of CAs issuing for domains they shouldn't).
- An on-path attacker who can briefly hijack the BGP path to a CA
  can complete a domain-validation challenge they shouldn't have.

In any of these cases, the chain-of-trust validation that DoT/DoH
relies on says "this cert is valid" — but it's a cert for the wrong
public key. An attacker holding the corresponding private key can
intercept your encrypted DNS, decrypt every query, and inject
modified responses.

**SPKI pinning** is the defence: instead of trusting "any cert
signed by any of the 200+ CAs in the trust store," CloakDNS can
trust **only certs whose public key hash matches your pin**. Even
if an attacker gets a perfectly valid cert from a real CA, it'll
have a different public key, fail the pin check, and CloakDNS
rejects the connection.

The flip side: pins can lock you out of legitimate cert rotations.
If Cloudflare rotates its DoT cert (which they do periodically) and
you've pinned the old SPKI, your CloakDNS suddenly stops working.
RFC 7469 recommends backup pins (multiple SPKI hashes, only one
needs to match) so a rotation event doesn't take you down. CloakDNS
supports a list of pins per upstream for exactly this reason.

### Concrete user-impact example

You're on a hostile network — a corporate proxy that does TLS
interception by issuing its own certs. Without pinning:

- Network operator's MITM box terminates the TLS connection from
  CloakDNS, presents a cert chained to a CA the network has rolled
  out to managed devices.
- Plain TLS validation passes (because the corporate root is
  trusted).
- All your DNS queries are decrypted at the MITM box, logged, then
  re-encrypted to the real upstream.

With SPKI pinning to Cloudflare's actual cert:

- Same scenario; corporate MITM presents its substitute cert.
- Plain TLS validation passes.
- CloakDNS computes the leaf's SPKI, compares to your pin, no match.
- Connection refused, no DNS goes through, you immediately notice
  something's wrong.

Pinning is also the only defence against the "perfect" CA
mis-issuance scenario — when even the cert *transparency* log
checks pass because the bogus cert was logged like any normal one.

---

## See it live

Run end-to-end on **2026-04-28**.

### Step 1: compute the upstream's real pin

```
$ echo | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com 2>/dev/null \
    | openssl x509 -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform der 2>/dev/null \
    | openssl dgst -sha256 -binary \
    | openssl enc -base64
ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew=
```

That base64 string IS the SHA-256 of Cloudflare's leaf-cert
SubjectPublicKeyInfo, on this run. Cloudflare rotates this cert
periodically; you'll get a different value if you re-run later
once a rotation has happened.

The pin form CloakDNS expects is:

```
sha256/ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew=
```

(literal prefix `sha256/`, then the base64).

### Step 2: config with the correct pin

```toml
# cloakdns-feat-pin-good.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "dot"
servers      = ["1.1.1.1:853"]
servername   = "cloudflare-dns.com"
spki_pins    = ["sha256/ltQ6aXy3tqpNZKJdnevMD7oR+IsI5rNWbOssFDrl+Ew="]
timeout_ms   = 5000

[blocklist]
sources = ["blocklists/tier1.txt"]
[cache]
max_entries = 100
[logging]
path  = "cloakdns-feat-pin-good.jsonl"
async = false
```

`spki_pins` accepts a list — RFC 7469 backup-pin model. You can
add a second value for the next rotation's expected pin if you
know it ahead of time.

Run it:

```
$ SSL_CERT_FILE="$(pwd)/cacert.pem" \
    ./build-msvc/Release/cloakdns.exe cloakdns-feat-pin-good.toml &
$ dig @127.0.0.1 -p 5354 example.com +noall +answer +stats

example.com.            223     IN      A       104.20.23.154
example.com.            223     IN      A       172.66.147.243
;; Query time: 75 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
```

Real A records returned. The pin matched, the leaf cert's
public-key hash equalled the configured pin, the verify callback
let the connection through.

### Step 3: same daemon, deliberately wrong pin

```toml
# cloakdns-feat-pin-bad.toml — same as above except:
spki_pins    = ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
```

(All-zero SHA-256, base64-encoded — vanishingly unlikely to be
anyone's real public-key hash.)

```
$ SSL_CERT_FILE="$(pwd)/cacert.pem" \
    ./build-msvc/Release/cloakdns.exe cloakdns-feat-pin-bad.toml &
$ dig @127.0.0.1 -p 5354 example.com +noall +answer +stats

;; Query time: 36 msec
;; SERVER: 127.0.0.1#5354(127.0.0.1) (UDP)
;; WHEN: Tue Apr 28 01:08:42 India Standard Time 2026
;; MSG SIZE  rcvd: 29
```

No answer section. SERVFAIL on the wire. The 36 ms is the time it
took Cloudflare's TLS handshake to complete + CloakDNS to compute
the leaf SPKI + reject + the sub-second-multiple retry attempts to
all fail similarly.

Daemon log:

```
... (startup banner)
servfail example.com  (upstream: all DoT servers exhausted)
```

`upstream: all DoT servers exhausted` is the human-readable summary
— every configured upstream had its TLS handshake aborted by the
verify callback (because no pin matched), there's nothing else to
try, query fails.

---

## How it works in code

Three pieces.

### 1. The pin computation (`src/tls.cpp:92`)

```cpp
// src/tls.cpp:92
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
```

Three steps:

1. `X509_get_X509_PUBKEY(cert)` — pull the SubjectPublicKeyInfo
   ASN.1 structure out of the cert.
2. `i2d_X509_PUBKEY(pubkey, &der)` — serialise it to DER bytes.
   This is the canonical "SubjectPublicKeyInfo" form RFC 7469
   specifies as the input to the hash.
3. `EVP_Digest(... EVP_sha256() ...)` — SHA-256 of the DER bytes.
   The result is base64-encoded and prefixed with `sha256/`.

The `auto*` on line 95 is the OpenSSL-4.0 const-correctness fix —
`X509_get_X509_PUBKEY` returns `const X509_PUBKEY*` in 4.0+;
`auto*` lets the same code compile against both 3.x (non-const)
and 4.0 (const).

### 2. The verify callback (`src/tls.cpp:44`)

OpenSSL invokes a verify callback once per cert in the chain
during handshake validation. CloakDNS's callback layers SPKI
pinning on top of the standard chain check:

```cpp
// src/tls.cpp:44
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
```

The flow:

- **`if (!preverify_ok) return 0;`** — if the standard chain
  validation already failed, reject without bothering with pins.
  Pinning is **defence in depth**, not a chain-bypass — a wrong
  signature is wrong regardless of pin state.
- **`if (X509_STORE_CTX_get_error_depth(ctx) != 0) return 1;`** —
  pinning runs only at the leaf cert (depth 0). Intermediates pass
  through; we don't care which intermediates the chain went through
  as long as the leaf has the right public key.
- **`if (!cfg || cfg->spki_pins.empty()) return 1;`** — when no
  pins are configured, accept any chain-validated cert (i.e., this
  whole feature is opt-in).
- **`compute_spki_pin(cert)` + `std::find` over `cfg->spki_pins`**
  — compute the leaf's pin, accept if it matches **any** of the
  configured pins (RFC 7469 backup-pin model).
- **`X509_STORE_CTX_set_error(ctx,
  X509_V_ERR_APPLICATION_VERIFICATION); return 0;`** — on
  mismatch, return 0 with an explicit error code so the upper
  layers see "verification failed: application verification" and
  abort the handshake.

### 3. Wiring the callback (`src/tls.cpp:226`)

In the `tls::Context` constructor:

```cpp
// src/tls.cpp ~line 226
if (!SSL_CTX_set_default_verify_paths(raw))
    throw std::runtime_error{"tls: SSL_CTX_set_default_verify_paths failed"};
SSL_CTX_set_verify(raw, SSL_VERIFY_PEER, verify_callback);
```

Two calls:

- `SSL_CTX_set_default_verify_paths` loads the system trust store
  (or the path in `SSL_CERT_FILE` env var on Windows; we use a
  Mozilla bundle in `cacert.pem`). This populates the chain that
  `preverify_ok` validates against.
- `SSL_CTX_set_verify` registers our verify callback to run after
  every cert validation. The `SSL_VERIFY_PEER` mode means clients
  always validate the server's cert.

The pins live in `tls::ContextConfig::spki_pins` (a
`std::vector<std::string>`) and are stashed on the `SSL_CTX`'s
ex-data slot via `SSL_CTX_set_ex_data` so the verify callback can
find them.

### What you can verify yourself

- Compute the pin yourself with the s_client pipeline above and
  compare to what other tools report. The
  `tests/test_tls.cpp::ComputeSpkiPinIsStableAcrossCalls` unit test
  checks pin determinism for the same cert.
- Set a wrong pin → SERVFAIL. Set the right pin → resolves.
- Configure two pins (correct + bogus) → still works because
  std::find matches the correct one.
- Configure two bogus pins → SERVFAIL.

---

## References

- **RFC 7469** — Public Key Pinning Extension for HTTP (the SPKI
  hash format CloakDNS reuses; the original HTTP-header use case
  is now deprecated for browser HSTS but the pin-format spec is
  still cited).
- **RFC 5280** — X.509 cert structure (where SubjectPublicKeyInfo
  comes from).
- **DigiNotar 2011 incident** — example of why CA-only trust isn't
  enough.
- **Source files:** [`src/tls.cpp`](../src/tls.cpp),
  [`src/upstream.cpp`](../src/upstream.cpp).
- **Unit tests:** [`tests/test_tls.cpp`](../tests/test_tls.cpp).
- **`docs/09-verification.md` §SPKI pinning** — verification
  procedure with concrete pin values from a real run.
- Related features: DoT upstream, DoH upstream, ECH.
