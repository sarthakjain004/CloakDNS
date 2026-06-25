#include "cloakdns/blocklist.hpp"
#include "cloakdns/aliases.hpp"

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace cloak {
namespace {

string to_lower_ascii(string_view s) {
    string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        out.push_back(c);
    }
    return out;
}

bool is_valid_domain_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '.' || c == '_';
}

bool is_valid_domain(string_view s) {
    if (s.empty() || s.size() > 255) return false;
    if (s.front() == '.' || s.back() == '.') return false;
    bool has_letter_or_digit = false;
    for (char c : s) {
        if (!is_valid_domain_char(c)) return false;
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
            has_letter_or_digit = true;
    }
    return has_letter_or_digit;
}

} // namespace

void Blocklist::add_exact(string_view qname) {
    auto s = to_lower_ascii(qname);
    if (!is_valid_domain(s)) return;
    exact_.insert(std::move(s));
}

void Blocklist::add_suffix(string_view domain) {
    auto s = to_lower_ascii(domain);
    if (!is_valid_domain(s)) return;
    suffix_.insert(std::move(s));
}

void Blocklist::add_regex(string pattern) {
    std::regex rx{pattern, std::regex::ECMAScript | std::regex::optimize};
    regex_.emplace_back(std::move(pattern), std::move(rx));
}

void Blocklist::add_allow_exact(string_view qname) {
    auto s = to_lower_ascii(qname);
    if (!is_valid_domain(s)) return;
    allow_exact_.insert(std::move(s));
}

void Blocklist::add_allow_suffix(string_view domain) {
    auto s = to_lower_ascii(domain);
    if (!is_valid_domain(s)) return;
    allow_suffix_.insert(std::move(s));
}

namespace {

// Generic hosts-file loader. `add_one` returns true when the token was
// added (new entry); used by both the blocklist and allowlist paths.
template <class Add>
size_t load_hosts_into(const fs::path& path, Add add_one) {
    std::ifstream in{path};
    if (!in) {
        throw runtime_error{"cannot open list file: " + path.string()};
    }
    size_t added = 0;
    string line;
    while (std::getline(in, line)) {
        if (const auto hash = line.find('#'); hash != string::npos)
            line.resize(hash);
        std::istringstream iss{line};
        string token;
        bool first = true;
        while (iss >> token) {
            if (first) { first = false; continue; }  // skip IP
            if (add_one(token)) ++added;
        }
    }
    return added;
}

} // namespace

size_t Blocklist::load_hosts_file(const fs::path& path) {
    return load_hosts_into(path, [&](const string& tok) {
        const auto before = suffix_.size();
        add_suffix(tok);
        return suffix_.size() != before;
    });
}

size_t Blocklist::load_hosts_file(const fs::path& path, string_view category) {
    if (category.empty()) return load_hosts_file(path);
    return load_hosts_into(path, [&](const string& tok) {
        auto s = to_lower_ascii(tok);
        if (!is_valid_domain(s)) return false;
        const auto before = suffix_.size();
        // Tag the category even when the suffix already exists — a
        // high-value domain can sit in both the uncategorized core list
        // (loaded first) and a tier; we still want the attribution.
        // emplace keeps the first tier to claim a domain. The key is the
        // normalized form, identical to what match() returns as the rule.
        category_.emplace(s, string{category});
        suffix_.insert(std::move(s));
        return suffix_.size() != before;   // count only newly-added rules
    });
}

size_t Blocklist::load_allowlist_file(const fs::path& path) {
    return load_hosts_into(path, [&](const string& tok) {
        const auto before = allow_suffix_.size();
        add_allow_suffix(tok);
        return allow_suffix_.size() != before;
    });
}

namespace {

// Walk qname's suffixes (qname, then each label-aligned tail) and return
// an iterator into `set` if any suffix matches; otherwise set.end(). The
// returned iterator points at the *longest* matching suffix — checking
// from pos=0 (full qname) outward guarantees we hit the longest one
// first.
template <class Set>
auto find_suffix_match(const Set& set, string_view qname) {
    size_t pos = 0;
    while (pos <= qname.size()) {
        if (auto it = set.find(string{qname.substr(pos)}); it != set.end())
            return it;
        const auto dot = qname.find('.', pos);
        if (dot == string_view::npos) break;
        pos = dot + 1;
    }
    return set.end();
}

} // namespace

bool Blocklist::allowed(string_view qname) const {
    if (qname.empty()) return false;
    if (allow_exact_.find(string{qname}) != allow_exact_.end())
        return true;
    return find_suffix_match(allow_suffix_, qname) != allow_suffix_.end();
}

MatchResult Blocklist::match(string_view qname) const {
    if (qname.empty()) return {};

    // Longest-match-wins between allow and block rules. Without this,
    // an apex allowlist entry like `google.com` defeats every more-
    // specific deny rule beneath it (e.g. `analytics.google.com`),
    // letting trackers through whenever the user allowlists the
    // user-facing apex.
    //
    // Specificity is the rule's hostname length: an exact match for
    // `analytics.google.com` (20 chars) beats a suffix match for
    // `google.com` (10 chars). Exact rules are also preferred over
    // suffix rules of the same length to break ties deterministically.

    // Compute the strongest-matching allow rule (longest hit).
    size_t allow_len = 0;
    bool allow_exact_hit = false;
    if (auto it = allow_exact_.find(string{qname}); it != allow_exact_.end()) {
        allow_len = it->size();
        allow_exact_hit = true;
    }
    if (auto it = find_suffix_match(allow_suffix_, qname); it != allow_suffix_.end()) {
        if (it->size() > allow_len) { allow_len = it->size(); allow_exact_hit = false; }
    }

    // Compute the strongest-matching deny rule (longest hit).
    MatchResult deny{};
    size_t deny_len = 0;
    if (auto it = exact_.find(string{qname}); it != exact_.end()) {
        deny_len = it->size();
        deny = {true, *it, MatchKind::Exact, ""};
    }
    if (auto it = find_suffix_match(suffix_, qname); it != suffix_.end()) {
        if (it->size() > deny_len ||
            (it->size() == deny_len && deny.kind != MatchKind::Exact)) {
            deny_len = it->size();
            deny = {true, *it, MatchKind::Suffix, ""};
        }
    }
    if (deny_len == 0) {
        for (const auto& [pattern, rx] : regex_) {
            if (std::regex_search(string{qname}, rx)) {
                deny_len = pattern.size();
                deny = {true, pattern, MatchKind::Regex, ""};
                break;
            }
        }
    }

    if (allow_len == 0 && deny_len == 0) return {};
    // Allow wins on tie (an apex listed in both is ambiguous; prefer
    // permissive). Otherwise the longer hostname pattern wins.
    if (allow_len > 0 && allow_len >= deny_len) {
        (void)allow_exact_hit;
        return {};
    }
    // Block confirmed: attribute it to its research tier if known. One
    // hash lookup, only on the block path. Keyed by deny.rule, which is
    // the normalized suffix/exact string also used as the category_ key.
    if (auto it = category_.find(deny.rule); it != category_.end())
        deny.category = it->second;
    return deny;
}

} // namespace cloak
