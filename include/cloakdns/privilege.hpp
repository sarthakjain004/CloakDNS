#pragma once

#include <string_view>

namespace cloak {

// Drop process privileges to the given POSIX user/group. No-op on
// Windows. Throws std::runtime_error on any setgid/setuid/getpwnam
// failure — starting up un-dropped-but-alive would be a security
// regression (parser runs as root), so fail loudly.
//
// Typical call flow:
//   1. Start as root (needed for bind(53) via CAP_NET_BIND_SERVICE).
//   2. Open the listening socket.
//   3. Call drop_privileges("_cloakdns", "_cloakdns").
//
// If `user` is empty this is a no-op (used by dev-mode / non-root runs).
void drop_privileges(std::string_view user, std::string_view group);

} // namespace cloak
