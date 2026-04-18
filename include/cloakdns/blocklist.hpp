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

    // Load a StevenBlack-style hosts file. Lines matching `IP domain...`
    // contribute each domain as a suffix rule. Comments (`#`) and blank
    // lines are ignored. Malformed domains are silently skipped.
    // Returns the number of rules added.
    size_t load_hosts_file(const std::filesystem::path& path);

    // qname is expected to be ASCII, lowercase, dot-separated, no
    // trailing dot. Match order is Exact → Suffix → Regex.
    MatchResult match(std::string_view qname) const;

    size_t size_exact()  const { return exact_.size(); }
    size_t size_suffix() const { return suffix_.size(); }
    size_t size_regex()  const { return regex_.size(); }

private:
    std::unordered_set<std::string> exact_;
    std::unordered_set<std::string> suffix_;
    std::vector<std::pair<std::string, std::regex>> regex_;
};

} // namespace cloak
