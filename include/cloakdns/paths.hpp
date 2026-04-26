#pragma once

#include <filesystem>
#include <optional>
#include <string_view>

namespace cloak {

// Default directory where CloakDNS looks for its config when none is
// specified on the command line. Windows: %ProgramData%\CloakDNS\.
// Linux / other POSIX: /etc/cloakdns/.
std::filesystem::path default_config_dir();

// Resolve the path CloakDNS should load its config from. Search order:
//   1. argv[0]'s directory: sibling `cloakdns.toml` (portable install).
//   2. Platform default dir (Windows %ProgramData%, Linux /etc).
//   3. Current working directory: `./cloakdns.toml` (dev convenience).
// Returns std::nullopt if nothing exists — callers then fall back to
// hardcoded defaults.
std::optional<std::filesystem::path>
find_config_path(std::string_view argv0);

} // namespace cloak
