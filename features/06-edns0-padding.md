# EDNS0 query padding (RFC 8467)

CloakDNS pads every outgoing DNS query with random zero bytes inside
an EDNS0 OPT-record `Padding` option (RFC 7830) so that the
**packet's wire length is rounded up to a fixed block size**
(default 128 bytes). All your queries leave the box at the same size,
regardless of how short or long the actual hostname is.

This defends against an upstream-side observer who'd otherwise be
able to guess what you queried purely from packet length —
particularly relevant on encrypted-DNS transports (DoT, DoH) where
the hostname text is hidden but the packet *size* still leaks.

---

## The problem

The DNS wire format is short. An A query for `example.com` is about
40 bytes; an A query for
`a-much-longer-subdomain-name-for-padding-test.example.com` is about
85 bytes. The hostname text dominates the variable-size portion.

Without padding, an observer who can see your DNS packets — your ISP
on plain UDP/53, an attacker on the network path, even a recipient
of a DoT/DoH stream's encrypted-but-length-visible records — can
make educated guesses about what you queried just from the packet
length pattern. Siby et al. (NDSS 2020) demonstrated this on
encrypted DNS:

> "DoH traffic analysis identifies websites with 90%+ accuracy from
> packet sizes alone, using 124× less data than HTTPS fingerprinting."

The encryption protected the contents (the hostname text), but the
*sequence of packet sizes* across a single page-load was still a
distinct fingerprint. Adding random padding so every query is the
same size collapses that fingerprint.

RFC 8467 ("Padding Policies for Extension Mechanisms for DNS")
recommends padding to either 128-byte blocks (clients) or 468-byte
blocks (recursive resolvers). RFC 7830 specifies the actual EDNS0
Padding option (option code 12). CloakDNS implements both: pads
client→upstream queries to 128-byte blocks by default; the value
is configurable via `padding_block_size`.

### Concrete user-impact example

You're on a public Wi-Fi network. Your DNS is set to a public DoT
resolver (`1.1.1.1:853`). The TLS encrypts the *content* of every
query, but the network operator can still see:

```
[client → 1.1.1.1]   length 47   ← short hostname
[client → 1.1.1.1]   length 92   ← long hostname
[client → 1.1.1.1]   length 51   ← medium hostname
... (a fingerprint shape per page-load)
```

Match that shape against a known catalogue of "what `cnn.com`
looks like on a fresh tab" or "what `youtube.com` looks like" and
you can guess the site with 90%+ accuracy without ever decrypting a
single byte.

With padding turned on:

```
[client → 1.1.1.1]   length 136   ← short hostname (padded)
[client → 1.1.1.1]   length 136   ← long hostname  (padded)
[client → 1.1.1.1]   length 136   ← medium hostname (padded)
... (every query the same length)
```

The shape is gone. Sites that used to look distinct now look
identical at the packet-length layer.

The honest caveat from Siby 2020: *padding alone is not enough.*
With standard 128-byte padding, F1 score for site identification
dropped from 0.91 to 0.43–0.69 — better, but not zero. Layering
padding with cache (so fewer queries leave at all), CNAME
randomization, and ECH (so even the SNI is hidden) closes the
remainder. CloakDNS ships padding as a layer in that stack, not as
a complete solution.

---

## See it live

Run end-to-end on **2026-04-28**. Plain UDP upstream so we can read
the wire bytes directly.

### Config

```toml
# cloakdns-feat-pad.toml
[server]
listen_addr = "127.0.0.1"
listen_port = 5354

[upstream]
protocol     = "udp"
servers      = ["1.1.1.1:53"]
timeout_ms   = 3000
padding_block_size = 128

[blocklist]
sources = ["blocklists/tier1.txt"]

[cache]
max_entries = 100

[logging]
path  = "cloakdns-feat-pad.jsonl"
async = false
```

### Capture two queries with very different qname lengths

In one terminal, start a 12-second tshark capture on the egress
interface (`-i 5` is Wi-Fi on this box; check yours with `tshark -D`):

```
$ "/c/Program Files/Wireshark/tshark.exe" -i 5 -w pad-test.pcap \
    -a duration:12 -f "udp port 53 and host 1.1.1.1"
```

In another, start CloakDNS and send two queries — one with an
11-byte qname, one with a 57-byte qname:

```
$ ./build-msvc/Release/cloakdns.exe cloakdns-feat-pad.toml &
$ dig @127.0.0.1 -p 5354 example.com +short
172.66.147.243
104.20.23.154

$ dig @127.0.0.1 -p 5354 a-much-longer-subdomain-name-for-padding-test.example.com +short
(returns NXDOMAIN; doesn't matter for this test — what we care about
is the outgoing query bytes, not the upstream's answer)
```

### What tshark captured

Outgoing UDP query frames to `1.1.1.1:53`:

```
$ tshark -r pad-test.pcap -Y "ip.dst == 1.1.1.1 and udp.dstport == 53" \
    -T fields -e frame.number -e udp.length -e dns.qry.name

1   136   example.com
3   136   a-much-longer-subdomain-name-for-padding-test.example.com
```

**Both queries left the box as 136-byte UDP payloads** even though
one qname is 11 bytes and the other is 57. Same `udp.length` despite
the radically different content — that's the whole feature, observable.

UDP payload of 136 bytes = 8 (UDP header) + **128 (DNS message)**.
Exactly the configured `padding_block_size`.

### Quick uniformity check via full frame length

A more honest "what an on-path observer sees" view is the full
Ethernet frame length — that's literally the bytes-on-the-wire size.
Pulling just `frame.len` for the outbound DNS frames is a one-line
sanity check that the padding actually flattens what an attacker
could measure:

```
$ "/c/Program Files/Wireshark/tshark.exe" -r pad-test.pcap \
    -Y "dns and ip.dst == 1.1.1.1" \
    -T fields -e frame.len

170
170
```

Two outbound DNS frames, identical 170-byte length on the wire
(= 14 Ethernet + 20 IPv4 + 8 UDP + 128 padded DNS message). Without
padding the same two queries would be 14 + 20 + 8 + 41 = **83**
bytes for `example.com` and 14 + 20 + 8 + 87 = **129** bytes for the
long subdomain — trivially distinguishable. With padding they're
indistinguishable in size.

### Detailed dissection

```
$ tshark -r pad-test.pcap -Y "ip.dst == 1.1.1.1 and udp.dstport == 53" -V

Frame 1: 170 bytes (1360 bits)
  Total Length: 156          ← IP layer
  Length: 136                ← UDP payload
  ...
  Additional records
    OPT
      Option Code: COOKIE (10)
      Option Length: 8
      Option Code: PADDING (12)    ← RFC 7830 EDNS0 Padding
      Option Length: 72            ← bytes of padding
      Padding: 000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Frame 3: 170 bytes
  Length: 136                ← same UDP payload size
  ...
      Option Code: PADDING (12)
      Option Length: 26            ← less padding (qname was longer)
      Padding: 0000000000000000000000000000000000000000000000000000
```

Read structure:

- **Option Code: PADDING (12)** — that's the RFC 7830 EDNS0 option
  code in the OPT pseudo-record's RDATA.
- **Option Length** is **72** for the short query and **26** for
  the long query. The longer the qname, the less padding needed
  to reach 128 bytes. Both arrive at exactly the same total.
- The padding bytes are all zeros. RFC 7830 §3 explicitly says
  "implementations MUST set the padding octets to zero" — random
  bytes would themselves be a covert channel.
- `Option Code: COOKIE (10)` is also present — that's an unrelated
  EDNS0 cookie option dig adds; CloakDNS preserved it and added
  its Padding option alongside.

### Daemon side

The daemon's startup line confirms padding is enabled:

```
padding: 128-byte blocks
```

(Set `padding_block_size = 0` to disable; the daemon prints
`padding: disabled`.)

---

## How it works in code

Two pieces.

### 1. Where padding is applied (`src/resolver.cpp:75`)

Before handing the outbound bytes to any Adapter, `Resolver::Impl::forward`
calls `pad_query`:

```cpp
// src/resolver.cpp:75
vector<byte> outbound = (cfg.padding_block_size == 0)
    ? vector<byte>(client_query.begin(), client_query.end())
    : pad_query(client_query, cfg.padding_block_size);
write_u16_be(span<byte>{outbound}, 0, our_id);
```

The padding happens once, in the Resolver, before any Adapter is
called — so UDP, DoT, and DoH all see the same padded buffer. The
per-protocol single-shot code in `src/udp_adapter.cpp` /
`src/dot_adapter.cpp` / `src/doh_adapter.cpp` never knows padding
exists.

### 2. The padding builder (`src/edns_padding.cpp:60`)

`pad_query` has two cases depending on whether the client's query
already has an EDNS0 OPT record (most modern clients do — dig adds
one for COOKIE; browsers add one for AD/CD bits):

#### Case A — query already has an OPT record at the end

```cpp
// src/edns_padding.cpp:75
if (opt.state == OptState::Last) {
    const size_t min_new = query.size() + kPaddingOptionHead;
    const size_t target  = round_up(min_new, block_size);
    const size_t pad_len = target - min_new;

    // RFC 6891 limits RDLEN to uint16_t; bail if extending would overflow.
    const size_t new_rdlen_full =
        opt.rr->rdata.size() + kPaddingOptionHead + pad_len;
    if (new_rdlen_full > std::numeric_limits<uint16_t>::max()) return out;

    // RDLEN sits 2 bytes before RDATA begins.
    const size_t rdlen_off = static_cast<size_t>(
        opt.rr->rdata.data() - query.data() - 2);
    write_u16_be(out, rdlen_off, static_cast<uint16_t>(new_rdlen_full));

    out.reserve(target);
    append_padding_option(out, pad_len);
    return out;
}
```

The math: round up the desired total length to the next multiple of
`block_size`, subtract the bytes we're about to add for the padding
option header (4 bytes — option-code + option-length), pad with the
remainder. Update the OPT record's RDLEN field to account for the
new bytes.

The `OptState::NotLast` case (an OPT record exists but isn't the
last RR) is treated as malformed and the query is forwarded
unmodified — the padding option has to live inside an OPT record,
and rebuilding the message structure to insert a new OPT in the
middle isn't worth it.

#### Case B — query has no OPT record at all

```cpp
// src/edns_padding.cpp:103 (synthesise a fresh OPT record)
const size_t min_new = query.size() + kOptRrSkeleton + kPaddingOptionHead;
const size_t target  = round_up(min_new, block_size);
const size_t pad_len = target - min_new;

out.reserve(target);
out.push_back(std::byte{0});                     // NAME = root label
append_u16_be(out, dns_type::OPT);               // TYPE
append_u16_be(out, kDefaultUdpPayload);          // CLASS = UDP payload size
append_u16_be(out, 0);                           // TTL hi: extended rcode + version
append_u16_be(out, 0);                           // TTL lo: DO + Z
append_u16_be(out, static_cast<uint16_t>(kPaddingOptionHead + pad_len));
append_padding_option(out, pad_len);

write_u16_be(out, 10, static_cast<uint16_t>(old_arcount + 1));
return out;
```

11 bytes for the OPT skeleton (`NAME(1) + TYPE(2) + CLASS(2) +
TTL(4) + RDLEN(2)`) + 4 bytes for the padding option header + the
padding zero bytes. Then bump ARCOUNT in the message header so the
upstream knows there's now one more additional record to parse.

### Why we don't pad responses

Padding is on the *outgoing* path only — what your machine sends
to the upstream. The upstream's reply already has the correct length
to reach `1.1.1.1`'s edge; padding it on the way back to the client
would just add latency without privacy benefit (the client side of
the tunnel is your own machine).

Some research considers padding both directions (e.g. to defend
against an observer that watches your local network), but the
classic Siby threat model is the upstream-side adversary — that's
what this implementation targets.

### What you can verify yourself

- Configure two queries with hugely different qname lengths and
  capture them on the wire — same `udp.length` value.
- Set `padding_block_size = 256` and re-capture — every query is
  now 256 (well, 264 — 8 UDP header + 256 DNS). The block size is
  fully configurable.
- Set `padding_block_size = 0` to disable — capture again, this
  time queries leave at their natural length, and you'll see the
  qname-length signal back in the wire.
- The `tests/test_edns_padding.cpp` file has unit tests for the
  byte-level invariants.

---

## References

- **RFC 7830** — the EDNS0 Padding option specification (option
  code 12).
- **RFC 8467** — recommended padding policies (128-byte blocks for
  clients).
- **RFC 6891** — EDNS0 mechanism (the OPT record this rides on).
- **Siby et al., Encrypted DNS → Privacy?** (NDSS 2020) — the
  traffic-analysis attack that motivates padding (and the honest
  measurement that padding alone is partial mitigation).
- **`docs/09-verification.md` §EDNS0 padding** — verification
  procedure with captured tshark output.
- **Source files:** [`src/edns_padding.cpp`](../src/edns_padding.cpp),
  [`src/resolver.cpp`](../src/resolver.cpp).
- **Unit tests:** [`tests/test_edns_padding.cpp`](../tests/test_edns_padding.cpp).
- Related features: UDP forwarding, DoT upstream, DoH upstream, ECH.
