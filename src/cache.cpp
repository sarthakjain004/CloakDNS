#include "cloakdns/cache.hpp"

#include "cloakdns/dns_parser.hpp"
#include "cloakdns/aliases.hpp"

#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <random>
#include <utility>

namespace cloak {

namespace {

// SOA RR type. Defined here rather than in dns_type because the cache
// is the only consumer.
constexpr uint16_t kTypeSOA = 6;

// RCODEs that must never be cached regardless of TTL.
constexpr uint8_t kRcodeServFail = 2;
constexpr uint8_t kRcodeNotImp   = 4;
constexpr uint8_t kRcodeNxDomain = 3;

constexpr size_t kTtlBackOffset  = 6;  // RDLEN(2) + TTL(4) back from RDATA

thread_local std::mt19937 jitter_rng{std::random_device{}()};

void collect_section_offsets(span<const byte> base,
                             const vector<ResourceRecord>& section,
                             vector<size_t>& out) {
    for (const auto& rr : section) {
        if (rr.type == dns_type::OPT) continue;
        const auto rdata_off = static_cast<size_t>(rr.rdata.data() - base.data());
        out.push_back(rdata_off - kTtlBackOffset);
    }
}

// RFC 2308 §3: cache lifetime of a negative response is min(SOA.TTL,
// SOA.MINIMUM). MINIMUM is the trailing 32-bit field of SOA RDATA;
// the preceding fields are MNAME (variable), RNAME (variable), then
// SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM (5 × u32). We only need the
// last 4 bytes of RDATA for MINIMUM — robust against compression in
// MNAME/RNAME because we read by offset from rdata end.
optional<uint32_t> read_soa_minimum(const ResourceRecord& soa) {
    if (soa.rdata.size() < 4) return nullopt;
    const auto* p = soa.rdata.data() + soa.rdata.size() - 4;
    return (uint32_t{to_integer<uint8_t>(p[0])} << 24) |
           (uint32_t{to_integer<uint8_t>(p[1])} << 16) |
           (uint32_t{to_integer<uint8_t>(p[2])} <<  8) |
            uint32_t{to_integer<uint8_t>(p[3])};
}

} // namespace

size_t CacheKeyHash::operator()(const CacheKey& k) const noexcept {
    size_t h = std::hash<string>{}(k.qname);
    h ^= std::hash<uint16_t>{}(k.qtype)  + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(k.qclass) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

optional<CacheKey> make_cache_key(const DnsMessage& msg) {
    if (msg.questions.size() != 1) return nullopt;
    return CacheKey{
        .qname  = msg.questions[0].qname,
        .qtype  = msg.questions[0].qtype,
        .qclass = msg.questions[0].qclass,
    };
}

chrono::seconds compute_cache_ttl(const DnsMessage& response) {
    if (response.header.rcode == kRcodeServFail ||
        response.header.rcode == kRcodeNotImp) {
        return chrono::seconds{0};
    }

    uint32_t min_ttl = std::numeric_limits<uint32_t>::max();
    bool saw_any = false;
    auto scan = [&](const vector<ResourceRecord>& section) {
        for (const auto& rr : section) {
            if (rr.type == dns_type::OPT) continue;
            min_ttl = std::min(min_ttl, rr.ttl);
            saw_any = true;
        }
    };
    scan(response.answers);
    scan(response.authority);

    if (!saw_any || min_ttl == 0) return chrono::seconds{0};

    // RFC 2308: for negative responses (NXDOMAIN or empty answer with
    // SOA in authority), cap the cache lifetime by SOA.MINIMUM. The
    // SOA TTL is already in `min_ttl`; we additionally clamp by MINIMUM.
    const bool is_negative =
        response.header.rcode == kRcodeNxDomain ||
        (response.answers.empty() && !response.authority.empty());
    if (is_negative) {
        for (const auto& rr : response.authority) {
            if (rr.type != kTypeSOA) continue;
            if (auto minimum = read_soa_minimum(rr)) {
                min_ttl = std::min(min_ttl, *minimum);
            }
            break;  // RFC says only one SOA in the authority section
        }
        // RFC 2308 §5: implementations MUST NOT cache negative responses
        // for longer than 24 hours, regardless of the SOA values. Without
        // this cap, a hostile or misconfigured upstream could pin a bogus
        // NXDOMAIN for years (MINIMUM is a uint32 — up to ~136 years).
        constexpr uint32_t kRfc2308NegativeCacheCeiling = 86400;
        min_ttl = std::min(min_ttl, kRfc2308NegativeCacheCeiling);
        if (min_ttl == 0) return chrono::seconds{0};
    }

    return chrono::seconds{min_ttl};
}

vector<size_t>
collect_ttl_offsets(span<const byte> response_bytes,
                    const DnsMessage& parsed) {
    vector<size_t> offsets;
    offsets.reserve(parsed.answers.size()
                  + parsed.authority.size()
                  + parsed.additional.size());
    collect_section_offsets(response_bytes, parsed.answers,    offsets);
    collect_section_offsets(response_bytes, parsed.authority,  offsets);
    collect_section_offsets(response_bytes, parsed.additional, offsets);
    return offsets;
}

void rewrite_ttls(span<byte> response_bytes,
                  const vector<size_t>& offsets,
                  uint32_t ttl) {
    const auto b0 = byte{static_cast<uint8_t>((ttl >> 24) & 0xff)};
    const auto b1 = byte{static_cast<uint8_t>((ttl >> 16) & 0xff)};
    const auto b2 = byte{static_cast<uint8_t>((ttl >>  8) & 0xff)};
    const auto b3 = byte{static_cast<uint8_t>( ttl        & 0xff)};
    for (size_t off : offsets) {
        if (off + 4 > response_bytes.size()) continue;  // defensive; should never trip
        response_bytes[off]     = b0;
        response_bytes[off + 1] = b1;
        response_bytes[off + 2] = b2;
        response_bytes[off + 3] = b3;
    }
}

asio::awaitable<void> apply_jitter(chrono::milliseconds max_jitter) {
    if (max_jitter.count() <= 0) co_return;

    std::uniform_int_distribution<int> dist(
        0, static_cast<int>(max_jitter.count()));
    const auto delay = chrono::milliseconds{dist(jitter_rng)};
    if (delay.count() == 0) co_return;

    auto exec = co_await asio::this_coro::executor;
    asio::steady_timer timer{exec, delay};
    co_await timer.async_wait(asio::use_awaitable);
}

// ---------- DnsCache ----------

DnsCache::DnsCache() : DnsCache(Config{}) {}

DnsCache::DnsCache(Config cfg) : cfg_(cfg) {
    sweeper_ = std::thread{[this] { sweeper_loop(); }};
}

DnsCache::~DnsCache() {
    {
        scoped_lock lk{shutdown_mu_};
        stopping_.store(true);
    }
    shutdown_cv_.notify_all();
    if (sweeper_.joinable()) sweeper_.join();
}

void DnsCache::insert(CacheKey key, vector<byte> response,
                      const DnsMessage& parsed, chrono::seconds ttl) {
    if (ttl.count() <= 0) return;

    Entry e;
    e.ttl_offsets = collect_ttl_offsets(response, parsed);
    e.expires_at  = chrono::steady_clock::now() + ttl;
    e.response    = std::move(response);

    unique_lock lk{mu_};

    // Replace existing entry: drop its LRU node first.
    if (auto existing = map_.find(key); existing != map_.end()) {
        lru_.erase(existing->second.lru_it);
        map_.erase(existing);
    }

    // Make room if at capacity.
    while (map_.size() >= cfg_.max_entries) {
        evict_one_locked();
    }

    e.lru_it = lru_.insert(lru_.end(), key);  // back = MRU
    map_.emplace(std::move(key), std::move(e));
    inserts_.fetch_add(1, memory_order_relaxed);
}

void DnsCache::evict_one_locked() {
    if (lru_.empty()) return;
    auto victim_it = map_.find(lru_.front());
    lru_.pop_front();
    if (victim_it != map_.end()) map_.erase(victim_it);
    lru_evictions_.fetch_add(1, memory_order_relaxed);
}

optional<vector<byte>>
DnsCache::lookup(const CacheKey& key, uint16_t client_id) {
    const auto now = chrono::steady_clock::now();

    vector<byte> copy;
    vector<size_t> offsets;
    chrono::seconds remaining{0};
    {
        // Need exclusive lock because we mutate the LRU list on hit.
        unique_lock lk{mu_};
        const auto it = map_.find(key);
        if (it == map_.end()) {
            misses_.fetch_add(1, memory_order_relaxed);
            return nullopt;
        }
        if (it->second.expires_at <= now) {
            // Expired — drop now so the next miss isn't spent walking past it.
            lru_.erase(it->second.lru_it);
            map_.erase(it);
            misses_.fetch_add(1, memory_order_relaxed);
            return nullopt;
        }

        copy    = it->second.response;
        offsets = it->second.ttl_offsets;
        remaining = chrono::duration_cast<chrono::seconds>(
            it->second.expires_at - now);
        // Promote to MRU end. splice is O(1) with the iterator we stored.
        lru_.splice(lru_.end(), lru_, it->second.lru_it);
    }

    hits_.fetch_add(1, memory_order_relaxed);

    const auto ttl = static_cast<uint32_t>(
        std::min<int64_t>(remaining.count(),
                          std::numeric_limits<uint32_t>::max()));
    rewrite_ttls(span<byte>{copy}, offsets, ttl);

    if (copy.size() >= 2) {
        copy[0] = byte{static_cast<uint8_t>(client_id >> 8)};
        copy[1] = byte{static_cast<uint8_t>(client_id & 0xff)};
    }
    return copy;
}

size_t DnsCache::sweep_expired() {
    const auto now = chrono::steady_clock::now();
    unique_lock lk{mu_};
    size_t n = 0;
    for (auto it = map_.begin(); it != map_.end();) {
        if (it->second.expires_at <= now) {
            lru_.erase(it->second.lru_it);
            it = map_.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    if (n) expired_sweeps_.fetch_add(n, memory_order_relaxed);
    return n;
}

size_t DnsCache::size() const {
    std::shared_lock lk{mu_};
    return map_.size();
}

DnsCache::Stats DnsCache::stats() const noexcept {
    return {
        .hits            = hits_.load(memory_order_relaxed),
        .misses          = misses_.load(memory_order_relaxed),
        .inserts         = inserts_.load(memory_order_relaxed),
        .lru_evictions   = lru_evictions_.load(memory_order_relaxed),
        .expired_sweeps  = expired_sweeps_.load(memory_order_relaxed),
    };
}

void DnsCache::sweeper_loop() {
    unique_lock lk{shutdown_mu_};
    while (!stopping_.load()) {
        shutdown_cv_.wait_for(lk, cfg_.sweep_interval,
                              [this] { return stopping_.load(); });
        if (stopping_.load()) break;
        // Release shutdown_mu_ while sweep_expired takes mu_ in unique
        // mode — different mutex, but releasing keeps shutdown signaling
        // responsive during long sweeps.
        lk.unlock();
        sweep_expired();
        lk.lock();
    }
}

} // namespace cloak
