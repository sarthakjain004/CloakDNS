#pragma once

#include "cloakdns/blocklist.hpp"
#include "cloakdns/upstream.hpp"

#include <asio/awaitable.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace cloak {

enum class UncloakStatus {
    Clean,    // chain terminated with A/AAAA (or no CNAME present); no hop hit the blocklist
    Blocked,  // a hop matched the blocklist
    Aborted,  // loop, depth limit, or re-query failure
};

struct UncloakResult {
    UncloakStatus status{UncloakStatus::Clean};
    std::vector<std::string> chain;   // [original_qname, hop1, hop2, ...]
    MatchResult hit{};                // populated iff status == Blocked
    std::string abort_reason;         // populated iff status == Aborted

    // Suspicious-cross signal: set when the chain hops to a different
    // eTLD+1 than the original qname's. Recorded regardless of `status`
    // — Safari ITP-style soft signal that the caller may surface in the
    // query log without changing the resolved response. See
    // learnings/safari-cname-defense-and-our-adaptation.md §6.
    bool        crossed_etldp1{false};
    std::string crossed_to;           // eTLD+1 of the first hop that crossed
};

class CnameUncloaker {
public:
    struct Config {
        int max_depth{8};             // RFC 1034 recommends 8 levels of indirection
    };

    // Two overloads instead of `Config cfg = {}` — Clang 18 rejects a
    // default arg whose value is `Config{}` when Config is a nested
    // struct of the same class with default member initializers,
    // because the inline initializers aren't fully visible until the
    // class definition closes (CWG 2335 / known Clang regression).
    // GCC and MSVC accept it; the overload split builds everywhere.
    CnameUncloaker(UpstreamForwarder& forwarder,
                   const Blocklist& blocklist);
    CnameUncloaker(UpstreamForwarder& forwarder,
                   const Blocklist& blocklist,
                   Config cfg);

    CnameUncloaker(const CnameUncloaker&) = delete;
    CnameUncloaker& operator=(const CnameUncloaker&) = delete;

    // Walk the CNAME chain starting at `original_qname`, using
    // `first_response` as the initial upstream answer. If the answer
    // section ends without an A/AAAA terminator, re-query the last
    // CNAME target via the forwarder. Each new hop is checked against
    // the blocklist; the first hit terminates the walk.
    asio::awaitable<UncloakResult>
    uncloak(std::string_view original_qname,
            std::span<const std::byte> first_response);

private:
    UpstreamForwarder& forwarder_;
    const Blocklist& blocklist_;
    Config cfg_;
};

} // namespace cloak
