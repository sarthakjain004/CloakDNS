#include "cloakdns/paths.hpp"
#include "cloakdns/aliases.hpp"

#include <cstdlib>
#include <string>
#include <system_error>

namespace cloak {

namespace {

constexpr string_view kConfigFileName = "cloakdns.toml";

} // namespace

fs::path default_config_dir() {
#ifdef _WIN32
    // _dupenv_s is MSVC's deprecation-free getenv wrapper: allocates
    // on success (we free with std::free), returns nullptr if unset.
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, "ProgramData") == 0 && buf) {
        fs::path out = fs::path{buf} / "CloakDNS";
        std::free(buf);
        return out;
    }
    return R"(C:\ProgramData\CloakDNS)";
#else
    return "/etc/cloakdns";
#endif
}

optional<fs::path>
find_config_path(string_view argv0) {
    error_code ec;

    // 1. Sibling of the executable. Portable install layout:
    //    <install>/cloakdns.exe
    //    <install>/cloakdns.toml
    if (!argv0.empty()) {
        fs::path p{string{argv0}};
        auto sibling = p.parent_path() / kConfigFileName;
        if (fs::exists(sibling, ec)) return sibling;
    }

    // 2. Platform-default directory.
    auto system_path = default_config_dir() / kConfigFileName;
    if (fs::exists(system_path, ec)) return system_path;

    // 3. Current working directory — convenient for dev, but brittle
    //    when the binary runs as a service with CWD outside the repo.
    fs::path cwd{kConfigFileName};
    if (fs::exists(cwd, ec)) return cwd;

    return nullopt;
}

} // namespace cloak
