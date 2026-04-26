#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace cloak {

// Terminal actions for a DNS query. Stable across versions — the
// analytics dashboard (Sub-Project 6) depends on these string values.
enum class LogAction {
    Allow,       // forwarded upstream, no CNAME chain or chain was clean
    Block,       // direct blocklist match on the qname
    Uncloak,     // blocked after walking the CNAME chain
    Cached,      // served from the in-memory cache
    ServFail,    // upstream failure, loop, or other aborted path
    Refuse,      // unsupported qtype or malformed question
    Suspicious,  // forwarded, but CNAME chain crossed eTLD+1 boundary —
                 // soft signal for the review queue. Schema v2.
};

std::string_view to_string(LogAction a) noexcept;

struct QueryLog {
    std::chrono::system_clock::time_point ts{};
    std::string               qname;
    uint16_t                  qtype{};
    LogAction                 action{LogAction::Refuse};
    std::string               rule;          // empty unless Block/Uncloak
    std::vector<std::string>  cname_chain;   // empty unless chain was walked
    std::optional<std::string> upstream;      // "host:port" for upstream-hitting actions
    double                    latency_ms{};
    std::string               client;        // "ip:port"
};

// Serialize a QueryLog record to a single JSON line (no trailing newline).
// Escapes \", \\, and control bytes per RFC 8259.
std::string to_json_line(const QueryLog& record);

class QueryLogger {
public:
    struct Config {
        std::filesystem::path path;                   // empty = disabled
        bool                  async{true};
        size_t                queue_size{8192};       // drop records when exceeded
        size_t                max_size_bytes{0};      // 0 = no rotation
        bool                  redact_client{false};   // hash client addr
    };

    explicit QueryLogger(Config cfg = {});
    ~QueryLogger();

    QueryLogger(const QueryLogger&) = delete;
    QueryLogger& operator=(const QueryLogger&) = delete;

    // Record one query. Non-blocking in async mode: if the queue is
    // full, the record is dropped (dropped-count is tracked).
    void log(QueryLog record);

    // Block until all queued records are written (for tests / shutdown).
    void flush();

    size_t dropped_count() const noexcept;
    size_t rotated_count() const noexcept;

private:
    void writer_loop(std::stop_token st);
    void write_one(const std::string& line);
    void maybe_rotate();   // mu_ held by caller

    Config cfg_;
    std::ofstream stream_;
    size_t bytes_written_{0};   // current file size since open

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::string> queue_;

    size_t dropped_{0};
    size_t rotations_{0};
    std::jthread writer_;   // must outlive queue/stream; declared last so destroyed first
};

// Schema version emitted as `"v":N` at the head of every JSON line.
// Bump on any schema change that adds/removes/reshapes a top-level field
// — or extends the LogAction value set, which the dashboard switches on.
// v2: added LogAction::Suspicious for eTLD+1 cross signals (M13).
inline constexpr int kQueryLogSchemaVersion = 2;

// Stable, deterministic obfuscated identifier for [logging] redact_client.
// Implementation: FNV-1a 64-bit, top 32 bits → 8 hex chars, "hash:" prefix.
// Not cryptographic — collisions are possible — but enough to
// disambiguate clients within an analytics session without leaking the
// raw IP. Switch to HMAC-SHA-256 if a per-tenant secret is ever added.
std::string redact_client_id(std::string_view client);

} // namespace cloak
