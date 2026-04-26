#include "cloakdns/etld.hpp"

#include <string>
#include <string_view>

namespace cloak {
namespace {

// Hardcoded list of common multi-label public suffixes. Covers the
// most-trafficked ccTLD patterns plus the reverse-DNS pseudo-TLDs.
// Order doesn't matter at lookup time — we pick the longest match.
//
// Selection: top ~30 ccTLDs by web traffic + special cases that surface
// in our own DNS captures. Upgrade path is full Mozilla PSL when the
// ad-hoc list shows its limits; see
// learnings/safari-cname-defense-and-our-adaptation.md §8.
constexpr std::string_view kMultiLabelSuffixes[] = {
    // Reverse DNS — for completeness, though qtype=PTR is filtered out
    // before uncloak runs in our hot path.
    "in-addr.arpa",
    "ip6.arpa",
    // United Kingdom
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "plc.uk",
    // India
    "co.in", "ac.in", "gov.in", "edu.in", "net.in", "org.in", "res.in",
    // Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    // Brazil
    "com.br", "net.br", "gov.br", "edu.br", "org.br",
    // Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "lg.jp",
    // South Korea
    "co.kr", "ne.kr", "or.kr",
    // China
    "com.cn", "net.cn", "gov.cn", "edu.cn", "org.cn", "ac.cn",
    // Hong Kong
    "com.hk", "edu.hk", "gov.hk", "org.hk",
    // Taiwan
    "com.tw", "net.tw", "org.tw", "edu.tw", "gov.tw",
    // Singapore
    "com.sg", "edu.sg", "gov.sg",
    // Mexico
    "com.mx", "gob.mx", "edu.mx",
    // Turkey
    "com.tr", "net.tr", "edu.tr", "gov.tr", "org.tr",
    // South Africa
    "co.za", "org.za", "ac.za",
};

bool ends_with_dot_suffix(std::string_view host, std::string_view suffix) {
    // host must end with "." + suffix and have at least one byte before.
    if (host.size() <= suffix.size()) return false;
    const size_t off = host.size() - suffix.size();
    if (off == 0) return false;             // host == suffix exactly
    if (host[off - 1] != '.') return false; // boundary must be a label dot
    return host.substr(off) == suffix;
}

}  // namespace

std::string etld_plus_one(std::string_view hostname) {
    // Canonical form: strip trailing dots.
    while (!hostname.empty() && hostname.back() == '.') {
        hostname.remove_suffix(1);
    }
    if (hostname.empty()) return {};

    // Find the longest multi-label suffix that hostname ends with.
    std::string_view best;
    for (const auto& sfx : kMultiLabelSuffixes) {
        if (ends_with_dot_suffix(hostname, sfx) && sfx.size() > best.size()) {
            best = sfx;
        }
    }

    if (!best.empty()) {
        // hostname ends with ".<best>" — find one label further left.
        // suffix_dot_index is the position of the '.' between the
        // label-before and the multi-label suffix.
        const size_t suffix_dot_index = hostname.size() - best.size() - 1;
        if (suffix_dot_index == 0) {
            // No label before the suffix — return whole hostname as best
            // available answer (degenerate input like ".co.uk").
            return std::string{hostname};
        }
        const size_t prev_dot = hostname.rfind('.', suffix_dot_index - 1);
        if (prev_dot == std::string_view::npos) {
            // hostname is exactly "label.<best>" — return as-is.
            return std::string{hostname};
        }
        return std::string{hostname.substr(prev_dot + 1)};
    }

    // No multi-label suffix matched — default to "last two labels".
    const size_t last_dot = hostname.rfind('.');
    if (last_dot == std::string_view::npos) {
        // Single label (e.g. "localhost").
        return std::string{hostname};
    }
    if (last_dot == 0) {
        // Pathological: ".tld" form.
        return std::string{hostname};
    }
    const size_t prev_dot = hostname.rfind('.', last_dot - 1);
    if (prev_dot == std::string_view::npos) {
        // Exactly two labels (e.g. "example.com").
        return std::string{hostname};
    }
    return std::string{hostname.substr(prev_dot + 1)};
}

}  // namespace cloak
