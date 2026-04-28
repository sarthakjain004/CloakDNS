#pragma once

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/udp.hpp>

#include <chrono>
#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cloak {

// Pull the ECHConfigList bytes out of the rdata of a single ServiceMode
// HTTPS RR (RFC 9460). Returns nullopt when the rdata is malformed,
// when the record is in AliasMode, or when no ech= SvcParam (key 5)
// is present.
//
// Scope is intentionally narrow: the parser is only used to extract the
// ECHConfigList from a record fetched at startup. It does NOT walk
// AliasMode redirections, doesn't honour ipv4hint/ipv6hint/alpn, doesn't
// follow target-name pointers, and rejects any compressed name in the
// TargetName slot. Use a real DNS library if you need more.
std::optional<std::vector<std::byte>>
svcb_extract_ech(std::span<const std::byte> rdata) noexcept;

// One-shot blocking-but-async UDP DNS query for an HTTPS (TYPE65) record
// at `qname`. Returns the raw rdata of the first ServiceMode HTTPS
// answer, or nullopt on timeout / NXDOMAIN / RCODE != NOERROR / no
// ServiceMode answer in the response.
//
// `bootstrap` is the resolver to ask. This is plain UDP — the caller
// should treat the lookup as a one-time cleartext leak that reveals
// "I am about to ECH-talk to <qname>", which is the same hostname
// already in their config.
asio::awaitable<std::optional<std::vector<std::byte>>>
fetch_https_rr_rdata(asio::io_context& ctx,
                     const asio::ip::udp::endpoint& bootstrap,
                     std::string_view qname,
                     std::chrono::milliseconds timeout);

// Composite helper: try each bootstrap server in order, parse its
// response, extract ECHConfigList. Returns the first non-empty result,
// or nullopt if every server fails. The hostname is the upstream DoT/DoH
// servername the daemon will connect to.
asio::awaitable<std::optional<std::vector<std::byte>>>
bootstrap_ech_config(asio::io_context& ctx,
                     std::span<const asio::ip::udp::endpoint> bootstrap_servers,
                     std::string_view hostname,
                     std::chrono::milliseconds timeout);

} // namespace cloak
