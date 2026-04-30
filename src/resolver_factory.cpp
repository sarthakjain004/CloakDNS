#include "cloakdns/resolver_factory.hpp"

#include "cloakdns/aliases.hpp"
#include "cloakdns/wire_endian.hpp"

#include <asio/ip/address.hpp>

namespace cloak::resolver {

namespace {

vector<AdapterPtr>
build_udp_adapters(asio::io_context& ctx, const UpstreamConfig& cfg) {
    vector<AdapterPtr> out;
    out.reserve(cfg.servers.size());
    for (const auto& ep : cfg.servers) {
        asio::ip::udp::endpoint udp_ep{
            asio::ip::make_address(ep.host), ep.port};
        out.push_back(make_udp_adapter(ctx, UdpAdapterConfig{
            .server = udp_ep,
            .label  = to_string_via_stream(udp_ep),
        }));
    }
    return out;
}

vector<AdapterPtr>
build_dot_adapters(asio::io_context& ctx, const UpstreamConfig& cfg) {
    vector<AdapterPtr> out;
    out.reserve(cfg.servers.size());
    for (const auto& ep : cfg.servers) {
        asio::ip::tcp::endpoint tcp_ep{
            asio::ip::make_address(ep.host), ep.port};
        out.push_back(make_dot_adapter(ctx, DotAdapterConfig{
            .server               = tcp_ep,
            .servername           = cfg.servername,
            .spki_pins            = cfg.spki_pins,
            .ca_file              = cfg.ca_file,
            .ech_outer_servername = cfg.ech_enabled ? cfg.ech_outer_servername : string{},
            .ech_config_list      = cfg.ech_enabled ? cfg.ech_config_list      : vector<byte>{},
            .ech_grease           = cfg.ech_grease,
            .label                = to_string_via_stream(tcp_ep),
        }));
    }
    return out;
}

vector<AdapterPtr>
build_doh_adapters(asio::io_context& ctx, const UpstreamConfig& cfg) {
    vector<AdapterPtr> out;
    out.reserve(cfg.servers.size());
    for (const auto& ep : cfg.servers) {
        asio::ip::tcp::endpoint tcp_ep{
            asio::ip::make_address(ep.host), ep.port};
        out.push_back(make_doh_adapter(ctx, DohAdapterConfig{
            .server               = tcp_ep,
            .servername           = cfg.servername,
            .doh_path             = cfg.doh_path,
            .spki_pins            = cfg.spki_pins,
            .ca_file              = cfg.ca_file,
            .ech_outer_servername = cfg.ech_enabled ? cfg.ech_outer_servername : string{},
            .ech_config_list      = cfg.ech_enabled ? cfg.ech_config_list      : vector<byte>{},
            .ech_grease           = cfg.ech_grease,
            .label                = to_string_via_stream(tcp_ep),
        }));
    }
    return out;
}

} // anonymous namespace

unique_ptr<Resolver>
build_from_config(asio::io_context& ctx, const UpstreamConfig& cfg) {
    vector<AdapterPtr> adapters;
    switch (cfg.protocol) {
      case UpstreamProtocol::Udp: adapters = build_udp_adapters(ctx, cfg); break;
      case UpstreamProtocol::Dot: adapters = build_dot_adapters(ctx, cfg); break;
      case UpstreamProtocol::Doh: adapters = build_doh_adapters(ctx, cfg); break;
    }
    return make_unique<Resolver>(ctx, Resolver::Config{
        .timeout            = cfg.timeout,
        .retries_on_primary = cfg.retries_on_primary,
        .padding_block_size = cfg.padding_block_size,
    }, std::move(adapters));
}

} // namespace cloak::resolver
