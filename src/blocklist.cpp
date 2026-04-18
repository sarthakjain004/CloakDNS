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

size_t Blocklist::load_hosts_file(const std::filesystem::path& path) {
    std::ifstream in{path};
    if (!in) {
        throw std::runtime_error{"cannot open blocklist: " + path.string()};
    }

    size_t added = 0;
    std::string line;
    while (std::getline(in, line)) {
        // Strip comment.
        if (const auto hash = line.find('#'); hash != std::string::npos) {
            line.resize(hash);
        }

        std::istringstream iss{line};
        std::string token;
        bool first = true;
        while (iss >> token) {
            if (first) { first = false; continue; }  // skip IP
            const auto before = suffix_.size();
            add_suffix(token);
            if (suffix_.size() != before) ++added;
        }
    }
    return added;
}

MatchResult Blocklist::match(std::string_view qname) const {
    if (qname.empty()) return {};

    if (auto it = exact_.find(std::string{qname}); it != exact_.end()) {
        return {true, *it, MatchKind::Exact};
    }

    size_t pos = 0;
    while (pos <= qname.size()) {
        std::string_view suffix = qname.substr(pos);
        if (auto it = suffix_.find(std::string{suffix}); it != suffix_.end()) {
            return {true, *it, MatchKind::Suffix};
        }
        const auto dot = qname.find('.', pos);
        if (dot == std::string_view::npos) break;
        pos = dot + 1;
    }

    for (const auto& [pattern, rx] : regex_) {
        if (std::regex_search(std::string{qname}, rx)) {
            return {true, pattern, MatchKind::Regex};
        }
    }

    return {};
}

} // namespace cloak
