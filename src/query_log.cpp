#include "cloakdns/query_log.hpp"

#include "cloakdns/dns_message.hpp"
#include "cloakdns/aliases.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

namespace cloak {

string_view to_string(LogAction a) noexcept {
    switch (a) {
    case LogAction::Allow:      return "allow";
    case LogAction::Block:      return "block";
    case LogAction::Uncloak:    return "uncloak";
    case LogAction::Cached:     return "cached";
    case LogAction::ServFail:   return "servfail";
    case LogAction::Refuse:     return "refuse";
    case LogAction::Suspicious: return "suspicious";
    }
    return "unknown";
}

namespace {

string_view qtype_name(uint16_t qt) noexcept {
    if (qt == dns_type::A)     return "A";
    if (qt == dns_type::CNAME) return "CNAME";
    if (qt == dns_type::AAAA)  return "AAAA";
    if (qt == dns_type::OPT)   return "OPT";
    switch (qt) {
    case 2:   return "NS";
    case 6:   return "SOA";
    case 12:  return "PTR";
    case 15:  return "MX";
    case 16:  return "TXT";
    case 33:  return "SRV";
    case 257: return "CAA";
    default:  return "";
    }
}

void append_json_escaped(string& out, string_view s) {
    out.reserve(out.size() + s.size() + 2);
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b";  break;
        case '\f': out += "\\f";  break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (u < 0x20) {
                array<char, 8> buf{};
                std::snprintf(buf.data(), buf.size(), "\\u%04x", u);
                out += buf.data();
            } else {
                out += c;
            }
        }
    }
}

void append_json_string(string& out, string_view s) {
    out += '"';
    append_json_escaped(out, s);
    out += '"';
}

void append_timestamp(string& out,
                      chrono::system_clock::time_point ts) {
    const auto time_s = chrono::system_clock::to_time_t(ts);
    const auto ms =
        chrono::duration_cast<chrono::milliseconds>(ts.time_since_epoch()).count() % 1000;
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &time_s);
#else
    gmtime_r(&time_s, &tmv);
#endif
    array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(),
                  "%04d-%02d-%02dT%02d:%02d:%02d.%03lldZ",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
                  static_cast<long long>(ms));
    out += buf.data();
}

void append_latency(string& out, double ms) {
    array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(), "%.3f", ms);
    out += buf.data();
}

// FNV-1a 64-bit. Stable across processes and platforms (constants are
// in the spec), reasonable distribution for short strings, no
// dependencies. Used only for redaction display, not security; an 8-hex
// prefix is sufficient to disambiguate within an analytics session.
uint64_t fnv1a64(string_view s) noexcept {
    constexpr uint64_t kOffset = 0xcbf29ce484222325ULL;
    constexpr uint64_t kPrime  = 0x100000001b3ULL;
    uint64_t h = kOffset;
    for (char c : s) {
        h ^= static_cast<uint8_t>(c);
        h *= kPrime;
    }
    return h;
}

} // namespace

string redact_client_id(string_view client) {
    const uint64_t h = fnv1a64(client);
    array<char, 16> buf{};
    std::snprintf(buf.data(), buf.size(), "%08x",
                  static_cast<uint32_t>(h >> 32));
    return string{"hash:"} + buf.data();
}

string to_json_line(const QueryLog& r) {
    string out;
    out.reserve(256);
    out += R"({"v":)";
    out += std::to_string(kQueryLogSchemaVersion);
    out += R"(,"ts":")";
    append_timestamp(out, r.ts);
    out += R"(","qname":)";
    append_json_string(out, r.qname);
    out += R"(,"qtype":)";
    if (const auto name = qtype_name(r.qtype); !name.empty()) {
        append_json_string(out, name);
    } else {
        out += std::to_string(r.qtype);
    }
    out += R"(,"action":")";
    out += to_string(r.action);
    out += R"(","rule":)";
    if (r.rule.empty()) out += "null";
    else                append_json_string(out, r.rule);
    if (!r.category.empty()) {
        out += R"(,"category":)";
        append_json_string(out, r.category);
    }
    out += R"(,"cname_chain":[)";
    for (size_t i = 0; i < r.cname_chain.size(); ++i) {
        if (i) out += ',';
        append_json_string(out, r.cname_chain[i]);
    }
    out += R"(],"upstream":)";
    if (r.upstream) append_json_string(out, *r.upstream);
    else            out += "null";
    out += R"(,"latency_ms":)";
    append_latency(out, r.latency_ms);
    out += R"(,"client":)";
    append_json_string(out, r.client);
    if (r.tls_ech_status) {
        out += R"(,"tls_ech_status":)";
        append_json_string(out, *r.tls_ech_status);
    }
    out += '}';
    return out;
}

// ---------- QueryLogger ----------

QueryLogger::QueryLogger() : QueryLogger(Config{}) {}

QueryLogger::QueryLogger(Config cfg) : cfg_(std::move(cfg)) {
    if (cfg_.path.empty()) return;   // disabled
    stream_.open(cfg_.path, std::ios::app);
    if (!stream_) {
        // Fail loud but non-fatal: logger stays "disabled" for the
        // process lifetime. Without this, a misconfigured path would
        // silently drop every query log.
        std::cerr << "query_log: cannot open " << cfg_.path
                  << " for append — logging disabled" << std::endl;
        return;
    }
    // Seed bytes_written_ from the existing file size (we open in append
    // mode), so a restart doesn't forget how big the file already is.
    error_code ec;
    const auto sz = fs::file_size(cfg_.path, ec);
    if (!ec) bytes_written_ = static_cast<size_t>(sz);

    if (cfg_.async) {
        writer_ = std::thread{[this] { writer_loop(); }};
    }
}

QueryLogger::~QueryLogger() {
    // Cooperative shutdown — set the flag, wake the writer, join.
    if (writer_.joinable()) {
        {
            scoped_lock lk{mu_};
            stopping_.store(true);
        }
        cv_.notify_all();
        writer_.join();
    }
    // Drain any remaining queued records synchronously.
    while (!queue_.empty()) {
        write_one(queue_.front());
        queue_.pop_front();
    }
}

void QueryLogger::log(QueryLog record) {
    if (cfg_.path.empty()) return;
    if (cfg_.redact_client && !record.client.empty()) {
        record.client = redact_client_id(record.client);
    }
    auto line = to_json_line(record);

    if (!cfg_.async) {
        scoped_lock lk{mu_};
        write_one(line);
        return;
    }

    {
        scoped_lock lk{mu_};
        if (queue_.size() >= cfg_.queue_size) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(line));
    }
    cv_.notify_one();
}

void QueryLogger::flush() {
    unique_lock lk{mu_};
    cv_.wait(lk, [this] { return queue_.empty(); });
    stream_.flush();
}

size_t QueryLogger::dropped_count() const noexcept {
    scoped_lock lk{mu_};
    return dropped_;
}

size_t QueryLogger::rotated_count() const noexcept {
    scoped_lock lk{mu_};
    return rotations_;
}

void QueryLogger::maybe_rotate() {
    if (cfg_.max_size_bytes == 0) return;
    if (bytes_written_ < cfg_.max_size_bytes) return;
    if (!stream_) return;

    stream_.flush();
    stream_.close();

    // Build a timestamped sibling path:  cloakdns-queries.jsonl
    //                                 → cloakdns-queries.jsonl.20260426T123045Z
    const auto now = chrono::system_clock::now();
    const auto t = chrono::system_clock::to_time_t(now);
    std::tm tmv{};
#ifdef _WIN32
    gmtime_s(&tmv, &t);
#else
    gmtime_r(&t, &tmv);
#endif
    array<char, 32> stamp{};
    std::snprintf(stamp.data(), stamp.size(),
                  "%04d%02d%02dT%02d%02d%02dZ",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
                  tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

    auto rotated = cfg_.path;
    rotated += '.';
    rotated += stamp.data();
    error_code ec;
    fs::rename(cfg_.path, rotated, ec);
    if (ec) {
        std::cerr << "query_log: rotate rename failed (" << ec.message()
                  << ") — staying with existing file" << std::endl;
    }

    stream_.clear();
    stream_.open(cfg_.path, std::ios::app);
    if (!stream_) {
        std::cerr << "query_log: failed to reopen " << cfg_.path
                  << " after rotation — logging disabled" << std::endl;
        bytes_written_ = 0;
        return;
    }
    bytes_written_ = 0;
    ++rotations_;
}

void QueryLogger::writer_loop() {
    unique_lock lk{mu_};
    while (!stopping_.load() || !queue_.empty()) {
        cv_.wait(lk, [this] {
            return stopping_.load() || !queue_.empty();
        });
        // Drain the queue while holding the lock. write_one mutates
        // stream_, bytes_written_, and rotations_, all of which are
        // also read under mu_ by rotated_count() / dropped_count().
        // Holding the lock through the burst keeps those reads
        // race-free; the queue grows in producer threads only when
        // log() acquires mu_ briefly, so backpressure is bounded.
        while (!queue_.empty()) {
            auto line = std::move(queue_.front());
            queue_.pop_front();
            write_one(line);
        }
        // Flush after each drain burst so records reach disk even if
        // the process dies via SIGKILL / taskkill /F before shutdown.
        if (stream_) stream_.flush();
        cv_.notify_all();
    }
}

void QueryLogger::write_one(const string& line) {
    if (!stream_) return;
    maybe_rotate();
    if (!stream_) return;
    stream_ << line << '\n';
    bytes_written_ += line.size() + 1;
}

} // namespace cloak
