# ECH live verification (`verify_ech.py`)

Live integration check for CloakDNS Encrypted Client Hello (M20). This is
a manual / nightly tool, **not** part of the standard unit-test suite —
it requires network access, a current ECHConfigList from the upstream,
and capture privileges on a real interface.

## What it asserts

For an upstream like Cloudflare's `cloudflare-dns.com`:

1. The ClientHello on the upstream TLS handshake carries an
   `encrypted_client_hello` TLS extension (RFC 9849 §11, type
   `0xfe0d`).
2. The cleartext `server_name` extension does **not** carry the inner
   hostname (`cloudflare-dns.com`). It should carry the configured
   `ech_outer_servername` decoy.
3. As a defence-in-depth check, the literal bytes of the inner
   hostname don't appear anywhere inside any captured ClientHello
   frame.

If any of those fails the script exits non-zero with a diagnostic and
the pcap path so the user can pry it open in Wireshark.

## Prerequisites

- A CloakDNS binary built with `-DCLOAKDNS_ECH=ON` against OpenSSL
  4.0+. This is the gated path from M20 — a stock 3.x build won't have
  the ECH symbols and the test would always fail assertion 1.
- `tshark` (Wireshark CLI) on PATH. Capture privileges on the egress
  interface:
  - **Linux:** `sudo setcap cap_net_raw,cap_net_admin=eip $(which dumpcap)`
    once, after which tshark works without root.
  - **macOS:** install the `ChmodBPF` helper bundled with Wireshark.
  - **Windows:** Npcap installer + run as Administrator.
- `dig` on PATH (for fetching the upstream's HTTPS DNS RR and for
  probing the running CloakDNS).
- The upstream's literal IP (so CloakDNS doesn't need a bootstrap path
  it doesn't have yet — see M20.1).

## Usage

```bash
# Linux (egress on any interface)
./verify_ech.py \
    --cloakdns ../../build/cloakdns \
    --upstream cloudflare-dns.com \
    --upstream-ip 1.1.1.1 \
    --protocol doh

# macOS — capture on lo0 won't see the upstream traffic; pick the real
# egress interface (en0 typically) and run with the BPF helper installed.
./verify_ech.py \
    --cloakdns ../../build/cloakdns \
    --upstream cloudflare-dns.com \
    --upstream-ip 1.1.1.1 \
    --interface en0 \
    --protocol dot

# Windows — name the NIC by Wireshark's index. Run from an
# Administrator PowerShell.
python verify_ech.py `
    --cloakdns ..\..\build-msvc\Release\cloakdns.exe `
    --upstream cloudflare-dns.com `
    --upstream-ip 1.1.1.1 `
    --interface 1
```

Add `--keep-tmp` if you want the working directory (config, pcap, and
both subprocess logs) preserved for forensic inspection.

## Expected output

On success the last two lines are:

```
OK: 3 ClientHello captured, ECH ext present, inner SNI 'cloudflare-dns.com' never seen in cleartext.
observed outer SNIs: ['cloudflare-ech.com']
```

## Failure modes

| Diagnostic | What to check |
|---|---|
| `no ECH= SvcParam` from dig | Is `cloudflare-dns.com` HTTPS RR visible from your network? Some captive portals strip HTTPS RRs. Try `dig +trace`. |
| `cloakdns never opened <port>` | Inspect `cloakdns.log` in the printed workdir — most often a config validation failure. |
| `no TLS handshakes captured` | Wrong `--interface` (loopback won't see egress) or capture privileges aren't set up. |
| `inner hostname appears in cleartext` | ECH didn't activate. Either the binary lacks `CLOAKDNS_HAVE_ECH`, the ECHConfigList is stale (rotated by Cloudflare), or the upstream rejected the ECHClientHello and forced retry without ECH. |
| `no ClientHello carried the ECH extension` | Same as above. Cross-check with `dig +https` that the SvcParam still parses; rerun with `--keep-tmp` and inspect the pcap directly. |

## Why this isn't in CI yet

CI runners don't currently provision OpenSSL 4.0 nor a privileged
`tshark`. Adding either is a separate piece of infra work; the script
is structured so a CI job that does provision them just runs it. See
`learnings/encrypted-upstream-plan.md` §"M20.1 follow-up" for the next
piece of the puzzle (auto-fetching the ECHConfigList from the upstream's
HTTPS RR so the bootstrap step here happens inside CloakDNS itself).
