#pragma once

#include <cstddef>
#include <filesystem>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace cloak {

enum class MatchKind { None, Exact, Suffix, Regex };

struct MatchResult {
    bool blocked{};
    std::string rule;
    MatchKind kind{MatchKind::None};
    // The research tier that caught this rule (e.g. "syncing-hub",
    // "server-side-endpoint"). Empty for the uncategorized core list
    // and for regex/allow paths. Set only on a block hit.
    std::string category;
};

class Blocklist {
public:
    void add_exact(std::string_view qname);
    void add_suffix(std::string_view domain);
    void add_regex(std::string pattern);

    // Allowlist counterparts: a hit on any of these wins over a block
    // rule and the query is forwarded as if the blocklist had no entry.
    void add_allow_exact(std::string_view qname);
    void add_allow_suffix(std::string_view domain);

    // Load a StevenBlack-style hosts file. Lines matching `IP domain...`
    // contribute each domain as a suffix rule. Comments (`#`) and blank
    // lines are ignored. Malformed domains are silently skipped.
    // Returns the number of rules added.
    size_t load_hosts_file(const std::filesystem::path& path);

    // Same as above, but every domain loaded is also tagged with
    // `category` (a research-tier name). A later block on one of these
    // domains carries the tag in MatchResult::category, so the query log
    // can record *why* a domain was blocked, not just that it was. An
    // empty category behaves exactly like the untagged overload.
    size_t load_hosts_file(const std::filesystem::path& path,
                           std::string_view category);

    // Same format as load_hosts_file, but rules go into the allowlist
    // (passthrough). Use for legitimate sites that share infra with
    // trackers (googleapis.com, cloudfront.net subdomains, etc.).
    size_t load_allowlist_file(const std::filesystem::path& path);

    // qname is expected to be ASCII, lowercase, dot-separated, no
    // trailing dot. Allowlist is checked first; on hit, returns
    // {blocked=false}. Otherwise match order is Exact → Suffix → Regex.
    MatchResult match(std::string_view qname) const;

    // True iff the qname matches an allowlist rule (exact or suffix).
    bool allowed(std::string_view qname) const;

    size_t size_exact()  const { return exact_.size(); }
    size_t size_suffix() const { return suffix_.size(); }
    size_t size_regex()  const { return regex_.size(); }
    size_t size_allow_exact()  const { return allow_exact_.size(); }
    size_t size_allow_suffix() const { return allow_suffix_.size(); }

private:
    std::unordered_set<std::string> exact_;
    std::unordered_set<std::string> suffix_;
    std::vector<std::pair<std::string, std::regex>> regex_;
    std::unordered_set<std::string> allow_exact_;
    std::unordered_set<std::string> allow_suffix_;
    // rule-domain -> research tier name. Populated only by the
    // categorized load_hosts_file overload; consulted only on a block
    // hit, so the fast path is untouched.
    std::unordered_map<std::string, std::string> category_;
};

} // namespace cloak
