#include "cloakdns/resolver.hpp"

#include "cloakdns/aliases.hpp"

#include <asio/buffer.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <utility>

namespace cloak::resolver {

namespace {

constexpr size_t kMaxResponse = 4096;

class UdpAdapter final : public Adapter {
public:
    UdpAdapter(asio::io_context& ctx, UdpAdapterConfig cfg)
        : ctx_{ctx}, cfg_{std::move(cfg)} {}

    asio::awaitable<optional<UpstreamReply>>
        try_once(span<const byte> outbound,
                 chrono::milliseconds timeout) override {
        // Fresh ephemeral socket per try — gives RFC 5452 source-port
        // entropy on every attempt and avoids reusing a port the kernel
        // might still have a stale binding for.
        auto s = make_shared<asio::ip::udp::socket>(ctx_);
        s->open(asio::ip::udp::v4());
        s->bind(asio::ip::udp::endpoint{asio::ip::udp::v4(), 0});

        co_await s->async_send_to(
            asio::buffer(outbound.data(), outbound.size()),
            cfg_.server, asio::use_awaitable);

        asio::steady_timer timer{ctx_};
        timer.expires_after(timeout);
        timer.async_wait([s](const error_code& ec) {
            if (!ec) {
                error_code ignore;
                s->cancel(ignore);
            }
        });

        array<byte, kMaxResponse> buf;
        asio::ip::udp::endpoint   from;

        try {
            const auto n = co_await s->async_receive_from(
                asio::buffer(buf.data(), buf.size()), from,
                asio::use_awaitable);
            timer.cancel();
            if (from != cfg_.server) co_return nullopt;
            if (n < 2) co_return nullopt;
            co_return UpstreamReply{
                .bytes = vector<byte>(buf.data(), buf.data() + n),
            };
        } catch (const system_error&) {
            co_return nullopt;
        }
    }

    string_view  label()       const noexcept override { return cfg_.label; }
    tls::Context* tls_context() noexcept override        { return nullptr;   }

private:
    asio::io_context& ctx_;
    UdpAdapterConfig  cfg_;
};

} // anonymous namespace

AdapterPtr make_udp_adapter(asio::io_context& ctx, UdpAdapterConfig cfg) {
    return make_unique<UdpAdapter>(ctx, std::move(cfg));
}

} // namespace cloak::resolver
