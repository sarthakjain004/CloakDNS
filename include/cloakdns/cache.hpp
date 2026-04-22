#pragma once

#include "cloakdns/dns_message.hpp"

#include <asio/awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
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

    explicit DnsCache(Config cfg = {});
    ~DnsCache();

    DnsCache(const DnsCache&) = delete;
    DnsCache& operator=(const DnsCache&) = delete;

    // Insert a response. `parsed` must be the DnsMessage produced by
    // parsing `response`; it's consumed for TTL offset collection,
    // avoiding a second parse inside the cache. If `ttl` is zero or
    // the cache is full, the insert is skipped (simplest eviction
    // policy for M6 — M13 can add LRU).
    void insert(CacheKey key, std::vector<std::byte> response,
                const DnsMessage& parsed, std::chrono::seconds ttl);

    // Returns a copy of the cached response with TTL fields rewritten
    // to the remaining time and the transaction id set to `client_id`
    // so the caller can forward the bytes unmodified. Returns nullopt
    // on miss or expired entry; expired entries are removed on hit.
    std::optional<std::vector<std::byte>>
    lookup(const CacheKey& key, uint16_t client_id);

    // Force a sweep of expired entries. Also called periodically by
    // the background jthread.
    size_t sweep_expired();

    size_t size() const;

    std::chrono::milliseconds jitter_max() const { return cfg_.jitter_max; }

private:
    struct Entry {
        std::vector<std::byte> response;
        std::chrono::steady_clock::time_point expires_at;
        std::vector<size_t> ttl_offsets;   // byte positions of TTL fields within `response`
    };

    void sweeper_loop(std::stop_token st);

    Config cfg_;
    mutable std::shared_mutex mu_;
    std::unordered_map<CacheKey, Entry, CacheKeyHash> map_;
    std::jthread sweeper_;  // declared last so it's stopped before other members are destroyed
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
