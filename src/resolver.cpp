#include "cloakdns/resolver.hpp"

#include "cloakdns/aliases.hpp"
#include "cloakdns/dns_parser.hpp"
#include "cloakdns/edns_padding.hpp"
#include "cloakdns/wire_endian.hpp"

#include <atomic>
#include <random>
#include <stdexcept>
#include <utility>

namespace cloak::resolver {

namespace {

// RFC 5452 §6: validate the answer's question section echoes our
// request. Combined with ID match and (for UDP) src-IP / src-port match,
// this closes most off-path poisoning vectors at near-zero cost.
bool reply_matches_request(span<const byte> client_query,
                           span<const byte> reply) {
    try {
        const auto req = parse(client_query);
        const auto rep = parse(reply);
        if (req.questions.size() != rep.questions.size()) return false;
        for (size_t i = 0; i < req.questions.size(); ++i) {
            const auto& q = req.questions[i];
            const auto& r = rep.questions[i];
            if (q.qname != r.qname || q.qtype != r.qtype || q.qclass != r.qclass)
                return false;
        }
        return true;
    } catch (const ParseError&) {
        return false;
    }
}

// Per-Adapter counters. atomic<> for forward-compat with a future
// multi-threaded io_context; today the io_context is single-threaded
// (Resolver::forward is documented to require this in the header).
struct AdapterCounters {
    atomic<size_t> queries_answered{0};
    atomic<size_t> timeouts{0};
};

} // anonymous namespace

struct Resolver::Impl {
    Config                    cfg;
    vector<AdapterPtr>        adapters;
    vector<AdapterCounters>   counters;   // parallel to adapters
    // Single-threaded — see Resolver::forward header doc on io_context
    // thread requirement.
    std::mt19937              rng{std::random_device{}()};

    Impl(Config cfg_in, vector<AdapterPtr> a)
        : cfg{std::move(cfg_in)},
          adapters{std::move(a)},
          counters{adapters.size()} {
        if (adapters.empty())
            throw invalid_argument{"Resolver: at least one Adapter required"};
    }

    asio::awaitable<ForwardResult> forward(span<const byte> client_query) {
        if (client_query.size() < 12)
            throw runtime_error{"resolver: query too short"};

        const uint16_t client_id = read_u16_be(client_query, 0);

        std::uniform_int_distribution<uint32_t> dist{0, 0xffff};
        const uint16_t our_id = static_cast<uint16_t>(dist(rng));

        // Pad once; reuse across retries / fallbacks so every upstream
        // sees identical wire bytes (ADR 0002).
        vector<byte> outbound = (cfg.padding_block_size == 0)
            ? vector<byte>(client_query.begin(), client_query.end())
            : pad_query(client_query, cfg.padding_block_size);
        write_u16_be(span<byte>{outbound}, 0, our_id);

        for (size_t i = 0; i < adapters.size(); ++i) {
            const bool is_primary = (i == 0);
            const int  attempts   = is_primary
                ? (1 + cfg.retries_on_primary)
                : 1;
            auto& adapter  = *adapters[i];
            auto& counter  = counters[i];

            for (int a = 0; a < attempts; ++a) {
                auto reply = co_await adapter.try_once(outbound, cfg.timeout);
                if (!reply) {
                    counter.timeouts.fetch_add(1, memory_order_relaxed);
                    continue;
                }
                if (reply->bytes.size() < 12) continue;
                if (read_u16_be(reply->bytes, 0) != our_id) continue;
                if (!reply_matches_request(client_query, reply->bytes)) continue;

                write_u16_be(span<byte>{reply->bytes}, 0, client_id);
                counter.queries_answered.fetch_add(1, memory_order_relaxed);
                co_return ForwardResult{
                    .response   = std::move(reply->bytes),
                    .upstream   = string{adapter.label()},
                    .ech_status = reply->ech_status,
                };
            }
        }
        throw runtime_error{"resolver: all adapters exhausted"};
    }

    void swap_ech(span<const byte> bytes,
                  string outer,
                  chrono::system_clock::time_point at) {
        auto bytes_ptr = bytes.empty()
            ? nullptr
            : make_shared<const vector<byte>>(bytes.begin(), bytes.end());
        for (auto& a : adapters) {
            if (auto* tc = a->tls_context(); tc) {
                tc->ech_config().store(tls::EchConfig::Snapshot{
                    .bytes            = bytes_ptr,
                    .outer_servername = outer,
                    .fetched_at       = at,
                });
            }
        }
    }
};

Resolver::Resolver(asio::io_context& /*ctx*/, Config cfg, vector<AdapterPtr> adapters)
    : impl_{make_unique<Impl>(std::move(cfg), std::move(adapters))} {}

Resolver::~Resolver() = default;

asio::awaitable<vector<byte>>
Resolver::forward(span<const byte> client_query) {
    auto r = co_await impl_->forward(client_query);
    co_return std::move(r.response);
}

asio::awaitable<ForwardResult>
Resolver::forward_with_source(span<const byte> client_query) {
    co_return co_await impl_->forward(client_query);
}

Control Resolver::control() noexcept { return Control{this}; }

void Control::swap_ech_config(span<const byte> bytes,
                              string outer,
                              chrono::system_clock::time_point at) {
    r_->impl_->swap_ech(bytes, std::move(outer), at);
}

vector<Control::AdapterStats> Control::stats() const {
    vector<AdapterStats> out;
    out.reserve(r_->impl_->adapters.size());
    for (size_t i = 0; i < r_->impl_->adapters.size(); ++i) {
        AdapterStats s;
        s.label            = string{r_->impl_->adapters[i]->label()};
        s.queries_answered = r_->impl_->counters[i]
                                 .queries_answered.load(memory_order_relaxed);
        s.timeouts         = r_->impl_->counters[i]
                                 .timeouts.load(memory_order_relaxed);
        if (auto* tc = r_->impl_->adapters[i]->tls_context(); tc) {
            const auto snap = tc->ech_config().load();
            if (snap.fetched_at.time_since_epoch().count() > 0) {
                s.ech_fetched_at = snap.fetched_at;
            }
        }
        out.push_back(std::move(s));
    }
    return out;
}

} // namespace cloak::resolver
