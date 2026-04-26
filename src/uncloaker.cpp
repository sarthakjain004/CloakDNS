#include "cloakdns/uncloaker.hpp"

#include "cloakdns/dns_message.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/dns_writer.hpp"
#include "cloakdns/etld.hpp"

#include <unordered_set>
#include <utility>

namespace cloak {
namespace {

struct WalkOutput {
    std::vector<std::string> new_hops;
    bool terminated{false};
};

// Follow the CNAME chain inside a single parsed response. `current` is
// the name we want an answer for. Each matching CNAME advances `current`
// to its target; an A or AAAA record for `current` terminates the walk.
// Re-scanning handles out-of-order answer sections. Iterations are capped
// by answer count so a cyclic response produces a bounded output that
// the caller's cross-response `seen` set then detects as a loop.
WalkOutput walk_answers(const DnsMessage& msg,
                        std::span<const std::byte> packet,
                        std::string_view start) {
    WalkOutput w;
    std::string current{start};
    const size_t cap = msg.answers.size() + 1;

    for (size_t iter = 0; iter < cap; ++iter) {
        bool advanced = false;
        for (const auto& rr : msg.answers) {
            if (rr.name != current) continue;

            if (rr.type == dns_type::A || rr.type == dns_type::AAAA) {
                w.terminated = true;
                return w;
            }
            if (rr.type != dns_type::CNAME) continue;

            const auto rdata_offset = static_cast<size_t>(
                rr.rdata.data() - packet.data());
            std::string target = decode_name_at(packet, rdata_offset);

            w.new_hops.push_back(target);
            current = std::move(target);
            advanced = true;
            break;
        }
        if (!advanced) return w;
    }
    return w;
}

} // namespace

CnameUncloaker::CnameUncloaker(UpstreamForwarder& forwarder,
                               const Blocklist& blocklist,
                               Config cfg)
    : forwarder_(forwarder), blocklist_(blocklist), cfg_(cfg) {}

asio::awaitable<UncloakResult>
CnameUncloaker::uncloak(std::string_view original_qname,
                        std::span<const std::byte> first_response) {
    UncloakResult result;
    result.chain.emplace_back(original_qname);
    std::unordered_set<std::string> seen{result.chain.front()};

    // Original eTLD+1 — used to flag cross-registrable-domain hops.
    // Empty when original_qname is empty / a degenerate single label.
    const std::string original_etldp1 = etld_plus_one(original_qname);

    // First iteration walks `first_response` without copying. Re-query
    // responses are owned by `owned_packet` and aliased by `current`.
    std::span<const std::byte> current = first_response;
    std::vector<std::byte> owned_packet;

    while (true) {
        DnsMessage msg;
        try {
            msg = parse(current);
        } catch (const ParseError&) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "parse error in upstream response";
            co_return result;
        }

        WalkOutput walk;
        try {
            walk = walk_answers(msg, current, result.chain.back());
        } catch (const ParseError&) {
            // A CNAME target's RDATA contained a malformed compressed name.
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "malformed CNAME target";
            co_return result;
        }

        for (auto& hop : walk.new_hops) {
            if (!seen.insert(hop).second) {
                result.status = UncloakStatus::Aborted;
                result.abort_reason = "CNAME loop";
                co_return result;
            }
            if (static_cast<int>(result.chain.size()) >= cfg_.max_depth) {
                result.status = UncloakStatus::Aborted;
                result.abort_reason = "depth limit reached";
                co_return result;
            }
            result.chain.push_back(hop);

            // Soft eTLD+1 cross signal — does NOT change status. Captured
            // on the FIRST crossing hop only; subsequent hops don't
            // overwrite. Skipped silently when original eTLD+1 was empty
            // (degenerate input — nothing meaningful to compare against).
            if (!result.crossed_etldp1 && !original_etldp1.empty()) {
                std::string hop_etldp1 = etld_plus_one(hop);
                if (!hop_etldp1.empty() && hop_etldp1 != original_etldp1) {
                    result.crossed_etldp1 = true;
                    result.crossed_to = std::move(hop_etldp1);
                }
            }

            auto m = blocklist_.match(hop);
            if (m.blocked) {
                result.status = UncloakStatus::Blocked;
                result.hit = std::move(m);
                co_return result;
            }
        }

        // Clean exit: upstream gave us a terminator, or it returned no
        // CNAME for the current name (NODATA / NXDOMAIN / unrelated
        // records). Absence of A isn't a failure for the uncloaker.
        if (walk.terminated || walk.new_hops.empty()) {
            result.status = UncloakStatus::Clean;
            co_return result;
        }

        // Skip the re-query round-trip if we already have no headroom
        // to record another hop.
        if (static_cast<int>(result.chain.size()) >= cfg_.max_depth) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "depth limit reached";
            co_return result;
        }

        std::vector<std::byte> req;
        try {
            // Placeholder id; the forwarder rewrites it to a fresh
            // random value on the wire per M4's Kaminsky defense.
            req = build_a_query(result.chain.back(), /*id=*/0);
        } catch (const std::exception&) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "cannot encode re-query name";
            co_return result;
        }
        try {
            owned_packet = co_await forwarder_.forward(req);
        } catch (const std::exception&) {
            result.status = UncloakStatus::Aborted;
            result.abort_reason = "re-query failed";
            co_return result;
        }
        current = std::span<const std::byte>{owned_packet};
    }
}

} // namespace cloak
