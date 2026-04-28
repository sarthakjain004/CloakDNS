#include "cloakdns/privilege.hpp"
#include "cloakdns/aliases.hpp"

#include <stdexcept>
#include <string>

#ifdef __linux__
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

namespace cloak {

#ifdef __linux__

namespace {

[[noreturn]] void fail(const string& step) {
    throw runtime_error{"drop_privileges: " + step +
                             " failed: " + std::strerror(errno)};
}

} // namespace

void drop_privileges(string_view user, string_view group) {
    if (user.empty()) return;

    const string user_str{user};
    const string group_str{group.empty() ? user : group};

    const auto* grp = ::getgrnam(group_str.c_str());
    if (!grp) fail("getgrnam(" + group_str + ")");

    const auto* pwd = ::getpwnam(user_str.c_str());
    if (!pwd) fail("getpwnam(" + user_str + ")");

    if (::setgroups(1, &grp->gr_gid) != 0) fail("setgroups");
    if (::setgid(grp->gr_gid) != 0)        fail("setgid");
    if (::setuid(pwd->pw_uid) != 0)        fail("setuid");

    // Verify we can't re-acquire root. setuid(0) from a non-privileged
    // process must fail; if it succeeds, we never actually dropped.
    if (::setuid(0) == 0) {
        throw runtime_error{
            "drop_privileges: regained root after setuid — refusing to run"};
    }
}

#else

void drop_privileges(string_view /*user*/, string_view /*group*/) {
    // Windows uses virtual service accounts (NT SERVICE\CloakDNS) set
    // up at install time; no runtime privilege-drop step is needed.
}

#endif

} // namespace cloak
