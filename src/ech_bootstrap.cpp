// HTTPS-RR (RFC 9460) auto-bootstrap for the upstream's ECHConfigList.
//
// On startup, when the user sets `upstream.ech_autobootstrap = true`,
// we query a plain-UDP resolver for the upstream's HTTPS record, pull
// the rdata, and extract SvcParamKey 5 (ech). The bytes go into
// tls::Context::ech_config() before any DoT/DoH handshake — so the
// first connection already has a fresh config without the user
// hand-pasting `ech_config_list_b64` into the TOML.
//
// The plain-UDP query is a deliberate, documented one-time cleartext
// leak: it reveals "this client is about to talk to <upstream
// hostname>", which is information already encoded in the user's
// config file. It does not reveal any subsequent DNS query.

#include "cloakdns/ech_bootstrap.hpp"
#include "cloakdns/dns_message.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/aliases.hpp"

#include <asio/buffer.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <iostream>
#include <random>
#include <span>
#include <stdexcept>
#include <system_error>

namespace cloak {

namespace {

constexpr uint16_t kQTypeHttps = 65;
constexpr size_t   kMaxResponse = 4096;

// SvcParamKey 5 (ech) per RFC 9460 §14.3.
constexpr uint16_t kSvcParamKeyEch = 5;

void write_u16_be(span<byte> b, size_t off, uint16_t v) {
    b[off]     = byte{static_cast<uint8_t>((v >> 8) & 0xff)};
    b[off + 1] = byte{static_cast<uint8_t>(v & 0xff)};
}

uint16_t read_u16_be(span<const byte> b, size_t off) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(to_integer<uint8_t>(b[off])) << 8) |
         static_cast<uint16_t>(to_integer<uint8_t>(b[off + 1])));
}

// Build a wire-format DNS query for `<qname>. IN TYPE65`. RD bit set.
vector<byte> build_https_query(string_view qname, uint16_t id) {
    // Header (12 bytes) + qname-encoded + 2 (qtype) + 2 (qclass).
    vector<byte> out;
    out.reserve(12 + qname.size() + 6);
    out.resize(12);
    write_u16_be(span<byte>{out}, 0, id);
    // RD = 1, opcode 0, QR 0; flags second byte zero.
    out[2] = byte{0x01};
    out[3] = byte{0x00};
    write_u16_be(span<byte>{out}, 4, 1);  // qdcount
    // ancount/nscount/arcount left zero.

    // QNAME: each label prefixed by its length, terminated by 0x00.
    size_t label_start = 0;
    for (size_t i = 0; i <= qname.size(); ++i) {
        if (i == qname.size() || qname[i] == '.') {
            const size_t len = i - label_start;
            if (len == 0) break;     // trailing dot or empty name — emit root early
            if (len > 63) throw runtime_error{"ech_bootstrap: label > 63 bytes"};
            out.push_back(byte{static_cast<uint8_t>(len)});
            for (size_t j = label_start; j < i; ++j) {
                out.push_back(byte{static_cast<uint8_t>(qname[j])});
            }
            label_start = i + 1;
        }
    }
    out.push_back(byte{0});      // root label terminator

    // QTYPE (HTTPS = 65), QCLASS (IN = 1).
    out.push_back(byte{0});
    out.push_back(byte{static_cast<uint8_t>(kQTypeHttps)});
    out.push_back(byte{0});
    out.push_back(byte{1});
    return out;
}

// Skip a DNS name in `rdata`, returning the offset just past the
// terminating zero / pointer. Refuses compressed names (pointer bit set)
// because RFC 9460 §2.2 says SVCB TargetName is a compressed name in the
// rdata, but for our use case (auto-bootstrap of an upstream) the target
// is almost always "." (root, single 0x00 byte) meaning "use the
// queried name." If we see a pointer, bail out — caller treats it as
// "unable to parse, ignore record."
optional<size_t> skip_uncompressed_name(
        span<const byte> rdata, size_t off) {
    while (off < rdata.size()) {
        const auto b = to_integer<uint8_t>(rdata[off]);
        if (b == 0) return off + 1;          // root label, done
        if ((b & 0xc0) != 0) return nullopt;   // pointer or reserved bits
        const size_t label_len = b;
        if (off + 1 + label_len > rdata.size()) return nullopt;
        off += 1 + label_len;
    }
    return nullopt;
}

} // namespace

optional<vector<byte>>
svcb_extract_ech(span<const byte> rdata) noexcept {
    try {
        // RFC 9460 §2.2: SVCB rdata = SvcPriority (2) + TargetName + SvcParams*
        if (rdata.size() < 3) return nullopt;
        const auto priority = read_u16_be(rdata, 0);
        if (priority == 0) return nullopt;       // AliasMode — out of scope

        size_t cursor = 2;
        const auto after_name = skip_uncompressed_name(rdata, cursor);
        if (!after_name) return nullopt;
        cursor = *after_name;

        // Walk the SvcParam list. Keys must appear in strictly ascending
        // order per §2.2. We don't enforce ordering — just look for key 5.
        while (cursor + 4 <= rdata.size()) {
            const auto key  = read_u16_be(rdata, cursor);
            const auto vlen = read_u16_be(rdata, cursor + 2);
            cursor += 4;
            if (cursor + vlen > rdata.size()) return nullopt;
            if (key == kSvcParamKeyEch) {
                vector<byte> out(vlen);
                std::memcpy(out.data(), rdata.data() + cursor, vlen);
                return out;
            }
            cursor += vlen;
        }
        return nullopt;
    } catch (...) {
        return nullopt;
    }
}

asio::awaitable<optional<vector<byte>>>
fetch_https_rr_rdata(asio::io_context& ctx,
                     const asio::ip::udp::endpoint& bootstrap,
                     string_view qname,
                     chrono::milliseconds timeout) {
    std::random_device rd;
    std::uniform_int_distribution<uint32_t> dist{0, 0xffff};
    std::mt19937 rng{rd()};
    const auto our_id = static_cast<uint16_t>(dist(rng));

    vector<byte> query;
    try {
        query = build_https_query(qname, our_id);
    } catch (const exception&) {
        co_return nullopt;
    }

    auto sock = make_shared<asio::ip::udp::socket>(ctx);
    try {
        sock->open(asio::ip::udp::v4());
        sock->bind(asio::ip::udp::endpoint{asio::ip::udp::v4(), 0});
    } catch (const system_error&) {
        co_return nullopt;
    }

    asio::steady_timer timer{ctx};
    timer.expires_after(timeout);
    timer.async_wait([sock](const error_code& ec) {
        if (!ec) {
            error_code ignore;
            sock->cancel(ignore);
        }
    });

    try {
        co_await sock->async_send_to(
            asio::buffer(query.data(), query.size()), bootstrap,
            asio::use_awaitable);
    } catch (const system_error&) {
        co_return nullopt;
    }

    vector<byte> buf(kMaxResponse);
    asio::ip::udp::endpoint from;
    size_t n = 0;
    try {
        n = co_await sock->async_receive_from(
            asio::buffer(buf.data(), buf.size()), from,
            asio::use_awaitable);
    } catch (const system_error&) {
        co_return nullopt;
    }
    timer.cancel();
    if (from != bootstrap) co_return nullopt;
    if (n < 12)            co_return nullopt;

    DnsMessage msg;
    try {
        msg = parse(span<const byte>{buf.data(), n});
    } catch (const ParseError&) {
        co_return nullopt;
    }
    if (msg.header.id != our_id) co_return nullopt;
    if (msg.header.rcode != 0)   co_return nullopt;

    // Find the first HTTPS-typed answer. The owner name should match
    // qname (lowercased) but we don't double-check — we trust the
    // resolver and the ID match.
    for (const auto& rr : msg.answers) {
        if (rr.type == kQTypeHttps) {
            vector<byte> rdata(rr.rdata.size());
            std::memcpy(rdata.data(), rr.rdata.data(), rr.rdata.size());
            co_return rdata;
        }
    }
    co_return nullopt;
}

asio::awaitable<optional<vector<byte>>>
bootstrap_ech_config(asio::io_context& ctx,
                     span<const asio::ip::udp::endpoint> bootstrap_servers,
                     string_view hostname,
                     chrono::milliseconds timeout) {
    for (const auto& ep : bootstrap_servers) {
        auto rdata = co_await fetch_https_rr_rdata(ctx, ep, hostname, timeout);
        if (!rdata) {
            std::cerr << "ech bootstrap: no HTTPS RR from "
                      << ep.address().to_string() << ":" << ep.port()
                      << " for " << hostname << std::endl;
            continue;
        }
        auto ech = svcb_extract_ech(*rdata);
        if (!ech) {
            std::cerr << "ech bootstrap: HTTPS RR from "
                      << ep.address().to_string() << ":" << ep.port()
                      << " carried no ech= SvcParam" << std::endl;
            continue;
        }
        std::cerr << "ech bootstrap: fetched " << ech->size()
                  << " ECHConfigList bytes for " << hostname
                  << " via " << ep.address().to_string() << ":" << ep.port()
                  << std::endl;
        co_return ech;
    }
    co_return nullopt;
}

} // namespace cloak
