#include "cloakdns/cache.hpp"

#include "cloakdns/dns_parser.hpp"

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

// RCODEs that must never be cached regardless of TTL.
constexpr uint8_t kRcodeServFail = 2;
constexpr uint8_t kRcodeNotImp   = 4;

constexpr size_t kTtlBackOffset  = 6;  // RDLEN(2) + TTL(4) back from RDATA

thread_local std::mt19937 jitter_rng{std::random_device{}()};

void collect_section_offsets(std::span<const std::byte> base,
                             const std::vector<ResourceRecord>& section,
                             std::vector<size_t>& out) {
    for (const auto& rr : section) {
        if (rr.type == dns_type::OPT) continue;
        const auto rdata_off = static_cast<size_t>(rr.rdata.data() - base.data());
        out.push_back(rdata_off - kTtlBackOffset);
    }
}

} // namespace

size_t CacheKeyHash::operator()(const CacheKey& k) const noexcept {
    size_t h = std::hash<std::string>{}(k.qname);
    h ^= std::hash<uint16_t>{}(k.qtype)  + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<uint16_t>{}(k.qclass) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

std::optional<CacheKey> make_cache_key(const DnsMessage& msg) {
    if (msg.questions.size() != 1) return std::nullopt;
    return CacheKey{
        .qname  = msg.questions[0].qname,
        .qtype  = msg.questions[0].qtype,
        .qclass = msg.questions[0].qclass,
    };
}

std::chrono::seconds compute_cache_ttl(const DnsMessage& response) {
    if (response.header.rcode == kRcodeServFail ||
        response.header.rcode == kRcodeNotImp) {
        return std::chrono::seconds{0};
    }

    uint32_t min_ttl = std::numeric_limits<uint32_t>::max();
    bool saw_any = false;
    auto scan = [&](const std::vector<ResourceRecord>& section) {
        for (const auto& rr : section) {
            if (rr.type == dns_type::OPT) continue;
            min_ttl = std::min(min_ttl, rr.ttl);
            saw_any = true;
        }
    };
    scan(response.answers);
    scan(response.authority);

    if (!saw_any || min_ttl == 0) return std::chrono::seconds{0};
    return std::chrono::seconds{min_ttl};
}

std::vector<size_t>
collect_ttl_offsets(std::span<const std::byte> response_bytes,
                    const DnsMessage& parsed) {
    std::vector<size_t> offsets;
    offsets.reserve(parsed.answers.size()
                  + parsed.authority.size()
                  + parsed.additional.size());
    collect_section_offsets(response_bytes, parsed.answers,    offsets);
    collect_section_offsets(response_bytes, parsed.authority,  offsets);
    collect_section_offsets(response_bytes, parsed.additional, offsets);
    return offsets;
}

void rewrite_ttls(std::span<std::byte> response_bytes,
                  const std::vector<size_t>& offsets,
                  uint32_t ttl) {
    const auto b0 = std::byte{static_cast<uint8_t>((ttl >> 24) & 0xff)};
    const auto b1 = std::byte{static_cast<uint8_t>((ttl >> 16) & 0xff)};
    const auto b2 = std::byte{static_cast<uint8_t>((ttl >>  8) & 0xff)};
    const auto b3 = std::byte{static_cast<uint8_t>( ttl        & 0xff)};
    for (size_t off : offsets) {
        if (off + 4 > response_bytes.size()) continue;  // defensive; should never trip
        response_bytes[off]     = b0;
        response_bytes[off + 1] = b1;
        response_bytes[off + 2] = b2;
        response_bytes[off + 3] = b3;
    }
}

asio::awaitable<void> apply_jitter(std::chrono::milliseconds max_jitter) {
    if (max_jitter.count() <= 0) co_return;

    std::uniform_int_distribution<int> dist(
        0, static_cast<int>(max_jitter.count()));
    const auto delay = std::chrono::milliseconds{dist(jitter_rng)};
    if (delay.count() == 0) co_return;

    auto exec = co_await asio::this_coro::executor;
    asio::steady_timer timer{exec, delay};
    co_await timer.async_wait(asio::use_awaitable);
}

// ---------- DnsCache ----------

DnsCache::DnsCache(Config cfg) : cfg_(cfg) {
    sweeper_ = std::jthread{[this](std::stop_token st) { sweeper_loop(st); }};
}

DnsCache::~DnsCache() {
    // sweeper_ stops automatically on destruction via std::jthread's
    // stop_token. sweeper_loop sleeps on a condition_variable and
    // checks the stop_token so the jthread exits promptly.
}

void DnsCache::insert(CacheKey key, std::vector<std::byte> response,
                      const DnsMessage& parsed, std::chrono::seconds ttl) {
    if (ttl.count() <= 0) return;

    Entry e;
    e.ttl_offsets = collect_ttl_offsets(response, parsed);
    e.expires_at  = std::chrono::steady_clock::now() + ttl;
    e.response    = std::move(response);

    std::unique_lock lk{mu_};
    if (map_.size() >= cfg_.max_entries && !map_.contains(key)) {
        return;  // full; skip insert rather than pick an arbitrary victim
    }
    map_[std::move(key)] = std::move(e);
}

std::optional<std::vector<std::byte>>
DnsCache::lookup(const CacheKey& key, uint16_t client_id) {
    const auto now = std::chrono::steady_clock::now();

    std::vector<std::byte> copy;
    std::vector<size_t> offsets;
    std::chrono::seconds remaining{0};
    {
        std::shared_lock lk{mu_};
        const auto it = map_.find(key);
        if (it == map_.end()) return std::nullopt;
        if (it->second.expires_at <= now) return std::nullopt;  // expired; sweeper will remove

        copy    = it->second.response;
        offsets = it->second.ttl_offsets;
        remaining = std::chrono::duration_cast<std::chrono::seconds>(
            it->second.expires_at - now);
    }

    const auto ttl = static_cast<uint32_t>(
        std::min<int64_t>(remaining.count(),
                          std::numeric_limits<uint32_t>::max()));
    rewrite_ttls(std::span<std::byte>{copy}, offsets, ttl);

    if (copy.size() >= 2) {
        copy[0] = std::byte{static_cast<uint8_t>(client_id >> 8)};
        copy[1] = std::byte{static_cast<uint8_t>(client_id & 0xff)};
    }
    return copy;
}

size_t DnsCache::sweep_expired() {
    const auto now = std::chrono::steady_clock::now();
    std::unique_lock lk{mu_};
    size_t n = 0;
    for (auto it = map_.begin(); it != map_.end();) {
        if (it->second.expires_at <= now) {
            it = map_.erase(it);
            ++n;
        } else {
            ++it;
        }
    }
    return n;
}

size_t DnsCache::size() const {
    std::shared_lock lk{mu_};
    return map_.size();
}

void DnsCache::sweeper_loop(std::stop_token st) {
    std::mutex local;
    std::condition_variable_any cv;
    std::unique_lock lk{local};
    while (!st.stop_requested()) {
        cv.wait_for(lk, st, cfg_.sweep_interval,
                    [&] { return st.stop_requested(); });
        if (st.stop_requested()) break;
        sweep_expired();
    }
}

} // namespace cloak
