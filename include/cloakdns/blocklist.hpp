#pragma once

#include <cstddef>
#include <filesystem>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace cloak {

enum class MatchKind { None, Exact, Suffix, Regex };

struct MatchResult {
    bool blocked{};
    std::string rule;
    MatchKind kind{MatchKind::None};
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
};

} // namespace cloak
