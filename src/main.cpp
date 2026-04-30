#include "cloakdns/aliases.hpp"
#include "cloakdns/config.hpp"
#include "cloakdns/paths.hpp"
#include "cloakdns/resolver_factory.hpp"
#include "cloakdns/server.hpp"

#include <asio/io_context.hpp>

#include <exception>
#include <iostream>

namespace {

cloak::Config load_or_default(int argc, char** argv) {
    if (argc > 1) {
        const fs::path p{argv[1]};
        if (p.extension().string() == ".toml") return cloak::load_config(p);
        // Legacy mode: argv[1] is a bare blocklist file path.
        cloak::Config c;
        c.blocklist.sources = {p};
        return c;
    }
    if (auto discovered = cloak::find_config_path(argc > 0 ? argv[0] : "")) {
        std::cout << "config: " << discovered->string() << std::endl;
        return cloak::load_config(*discovered);
    }
    return cloak::Config{};
}

// Capture the TOML path so the SIGHUP/SIGBREAK handler can re-parse from
// disk and pick up changes to ech_config_list_b64. Empty path = legacy
// "argv = bare blocklist" mode; reload disabled.
fs::path detect_reload_path(int argc, char** argv) {
    if (argc > 1) {
        fs::path p{argv[1]};
        if (p.extension().string() == ".toml") return p;
    }
    if (auto discovered = cloak::find_config_path(argc > 0 ? argv[0] : "")) {
        return *discovered;
    }
    return {};
}

} // namespace

int main(int argc, char** argv) try {
    auto reload_path = detect_reload_path(argc, argv);
    auto cfg         = load_or_default(argc, argv);

    asio::io_context ctx;
    auto resolver = cloak::resolver::build_from_config(ctx, cfg.upstream);

    cloak::Server server{ctx, std::move(cfg), std::move(resolver),
                         std::move(reload_path)};
    return server.run();
} catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << std::endl;
    return 1;
}
