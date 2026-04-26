#include "cloakdns/blocklist.hpp"

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace cloak {
namespace {

std::string to_lower_ascii(std::string_view s) {
    std::string out;
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

bool is_valid_domain(std::string_view s) {
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

void Blocklist::add_exact(std::string_view qname) {
    auto s = to_lower_ascii(qname);
    if (!is_valid_domain(s)) return;
    exact_.insert(std::move(s));
}

void Blocklist::add_suffix(std::string_view domain) {
    auto s = to_lower_ascii(domain);
    if (!is_valid_domain(s)) return;
    suffix_.insert(std::move(s));
}

void Blocklist::add_regex(std::string pattern) {
    std::regex rx{pattern, std::regex::ECMAScript | std::regex::optimize};
    regex_.emplace_back(std::move(pattern), std::move(rx));
}

void Blocklist::add_allow_exact(std::string_view qname) {
    auto s = to_lower_ascii(qname);
    if (!is_valid_domain(s)) return;
    allow_exact_.insert(std::move(s));
}

void Blocklist::add_allow_suffix(std::string_view domain) {
    auto s = to_lower_ascii(domain);
    if (!is_valid_domain(s)) return;
    allow_suffix_.insert(std::move(s));
}

namespace {

// Generic hosts-file loader. `add_one` returns true when the token was
// added (new entry); used by both the blocklist and allowlist paths.
template <class Add>
size_t load_hosts_into(const std::filesystem::path& path, Add add_one) {
    std::ifstream in{path};
    if (!in) {
        throw std::runtime_error{"cannot open list file: " + path.string()};
    }
    size_t added = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (const auto hash = line.find('#'); hash != std::string::npos)
            line.resize(hash);
        std::istringstream iss{line};
        std::string token;
        bool first = true;
        while (iss >> token) {
            if (first) { first = false; continue; }  // skip IP
            if (add_one(token)) ++added;
        }
    }
    return added;
}

} // namespace

size_t Blocklist::load_hosts_file(const std::filesystem::path& path) {
    return load_hosts_into(path, [&](const std::string& tok) {
        const auto before = suffix_.size();
        add_suffix(tok);
        return suffix_.size() != before;
    });
}

size_t Blocklist::load_allowlist_file(const std::filesystem::path& path) {
    return load_hosts_into(path, [&](const std::string& tok) {
        const auto before = allow_suffix_.size();
        add_allow_suffix(tok);
        return allow_suffix_.size() != before;
    });
}

namespace {

// Walk qname's suffixes (qname, then each label-aligned tail) and return
// an iterator into `set` if any suffix matches; otherwise set.end().
template <class Set>
auto find_suffix_match(const Set& set, std::string_view qname) {
    size_t pos = 0;
    while (pos <= qname.size()) {
        if (auto it = set.find(std::string{qname.substr(pos)}); it != set.end())
            return it;
        const auto dot = qname.find('.', pos);
        if (dot == std::string_view::npos) break;
        pos = dot + 1;
    }
    return set.end();
}

} // namespace

bool Blocklist::allowed(std::string_view qname) const {
    if (qname.empty()) return false;
    if (allow_exact_.find(std::string{qname}) != allow_exact_.end())
        return true;
    return find_suffix_match(allow_suffix_, qname) != allow_suffix_.end();
}

MatchResult Blocklist::match(std::string_view qname) const {
    if (qname.empty()) return {};

    // Allowlist wins over any block rule.
    if (allowed(qname)) return {};

    if (auto it = exact_.find(std::string{qname}); it != exact_.end()) {
        return {true, *it, MatchKind::Exact};
    }

    if (auto it = find_suffix_match(suffix_, qname); it != suffix_.end()) {
        return {true, *it, MatchKind::Suffix};
    }

    for (const auto& [pattern, rx] : regex_) {
        if (std::regex_search(std::string{qname}, rx)) {
            return {true, pattern, MatchKind::Regex};
        }
    }

    return {};
}

} // namespace cloak
