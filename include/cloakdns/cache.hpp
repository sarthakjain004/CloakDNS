#pragma once

#include "cloakdns/dns_message.hpp"

#include <asio/awaitable.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace cloak {

struct CacheKey {
    std::string qname;   // already lowercase; matches parser output
    uint16_t qtype{};
    uint16_t qclass{};

    bool operator==(const CacheKey&) const = default;
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& k) const noexcept;
};

class DnsCache {
public:
    struct Config {
        std::chrono::milliseconds jitter_max{5};  // feature 12: FP-Radar defense
        std::chrono::seconds sweep_interval{30};
        size_t max_entries{50000};
    };

    struct Stats {
        size_t hits{};
        size_t misses{};
        size_t inserts{};
        size_t lru_evictions{};
        size_t expired_sweeps{};
    };

    // Two overloads instead of `Config cfg = {}` — see uncloaker.hpp
    // for the same Clang 18 / nested-Config rationale.
    DnsCache();
    explicit DnsCache(Config cfg);
    ~DnsCache();

    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(const DnsCache&) = delete;

    // Insert a response. `parsed` must be the DnsMessage produced by
    // parsing `response`; it's consumed for TTL offset collection,
    // avoiding a second parse inside the cache. If `ttl` is zero the
    // insert is skipped. If the cache is full, the LRU entry is evicted
    // to make room.
    void insert(CacheKey key, std::vector<std::byte> response,
                const DnsMessage& parsed, std::chrono::seconds ttl);

    // Returns a copy of the cached response with TTL fields rewritten
    // to the remaining time and the transaction id set to `client_id`
    // so the caller can forward the bytes unmodified. Returns nullopt
    // on miss or expired entry; expired entries are removed on hit.
    // Promotes the entry to the MRU end of the LRU list on hit.
    std::optional<std::vector<std::byte>>
    lookup(const CacheKey& key, uint16_t client_id);

    // Force a sweep of expired entries. Also called periodically by
    // the background jthread.
    size_t sweep_expired();

    size_t size() const;

    std::chrono::milliseconds jitter_max() const { return cfg_.jitter_max; }

    Stats stats() const noexcept;

private:
    struct Entry {
        std::vector<std::byte> response;
        std::chrono::steady_clock::time_point expires_at;
        std::vector<size_t> ttl_offsets;   // byte positions of TTL fields within `response`
        std::list<CacheKey>::iterator lru_it{};  // points into lru_; spliced on hit
    };

    void sweeper_loop();
    void evict_one_locked();   // mu_ held in unique mode

    Config cfg_;
    mutable std::shared_mutex mu_;
    std::unordered_map<CacheKey, Entry, CacheKeyHash> map_;
    std::list<CacheKey> lru_;     // front = LRU, back = MRU

    std::atomic<size_t> hits_{0};
    std::atomic<size_t> misses_{0};
    std::atomic<size_t> inserts_{0};
    std::atomic<size_t> lru_evictions_{0};
    std::atomic<size_t> expired_sweeps_{0};

    // Sweeper shutdown coordination. Was std::jthread + std::stop_token,
    // but Apple libc++ (Xcode 16-) gates those behind availability
    // annotations even on macOS 14+. Replaced with a portable
    // atomic-flag + cv pattern.
    std::atomic<bool>       stopping_{false};
    std::mutex              shutdown_mu_;
    std::condition_variable shutdown_cv_;
    std::thread             sweeper_;  // declared last so destruct doesn't race shutdown_*
};

// Build a CacheKey from a parsed query's first question. Returns
// nullopt if there isn't exactly one question.
std::optional<CacheKey> make_cache_key(const DnsMessage& msg);

// Minimum TTL across answer + authority RRs, skipping OPT. Returns
// zero if the response isn't cacheable (SERVFAIL, NOTIMP, no RRs, or
// any RR has TTL=0 per RFC 1035 §3.2.1 "not to be cached").
std::chrono::seconds compute_cache_ttl(const DnsMessage& response);

// Collect byte offsets of every non-OPT RR's TTL field within
// `response_bytes`. `parsed` must be the DnsMessage produced by
// parsing `response_bytes`. Used by DnsCache to precompute rewrite
// positions at insert time.
std::vector<size_t>
collect_ttl_offsets(std::span<const std::byte> response_bytes,
                    const DnsMessage& parsed);

// Write `ttl` (4 bytes, big-endian) at each offset in `response_bytes`.
void rewrite_ttls(std::span<std::byte> response_bytes,
                  const std::vector<size_t>& offsets,
                  uint32_t ttl);

// Sleep for a random duration in [0, max_jitter] on the current
// coroutine's executor. No-op if max_jitter is zero.
asio::awaitable<void> apply_jitter(std::chrono::milliseconds max_jitter);

} // namespace cloak
