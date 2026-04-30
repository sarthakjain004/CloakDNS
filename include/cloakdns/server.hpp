#pragma once

#include "cloakdns/config.hpp"
#include "cloakdns/resolver.hpp"

#include <asio/io_context.hpp>

#include <filesystem>
#include <memory>

namespace cloak {

// The CloakDNS daemon Module. Wires Blocklist + Uncloaker + DNS Cache +
// Query Logger + Resolver onto a UDP listen socket and drives the io
// loop until SIGINT/SIGTERM (or stop()).
//
// Construction:
//   Server takes a parsed Config and a wired Resolver. main() does the
//   Resolver factory dance via resolver::build_from_config; Server only
//   runs the loop, hot path, signal handlers, and reload. Tests can
//   inject a fake Resolver wrapping fake Adapters and exercise the
//   server end-to-end without real network.
//
// Reload:
//   SIGHUP (Linux) / SIGBREAK (Windows) re-reads the captured TOML
//   path, rebuilds the Blocklist, and (if ECH+autobootstrap) re-fetches
//   the upstream's HTTPS RR before swapping the new ECHConfigList into
//   every TLS-bearing Resolver Adapter. Reload is internal — there is
//   no public reload() method.
//
// Lifetime:
//   io_context is owned by the caller (idiomatic Asio). Server captures
//   a reference. Resolver is owned by Server (transferred at construction).
//   Pass an empty `reload_path` to disable hot reload (legacy
//   "argv = bare blocklist file" mode).
class Server {
public:
    Server(asio::io_context& ctx,
           Config cfg,
           std::unique_ptr<resolver::Resolver> resolver,
           std::filesystem::path reload_path = {});
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Blocks until shutdown. Eager ECH bootstrap (when configured)
    // runs inside this body, before bind(). Returns 0 on clean exit;
    // throws on bind / wire failure before the listen loop starts.
    int run();

    // Triggers a clean shutdown from another thread or signal handler.
    // Idempotent.
    void stop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace cloak
