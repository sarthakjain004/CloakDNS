#include "cloakdns/paths.hpp"

#include <cstdlib>
#include <string>
#include <system_error>

namespace cloak {

namespace {

constexpr std::string_view kConfigFileName = "cloakdns.toml";

} // namespace

std::filesystem::path default_config_dir() {
#ifdef _WIN32
    // _dupenv_s is MSVC's deprecation-free getenv wrapper: allocates
    // on success (we free with std::free), returns nullptr if unset.
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, "ProgramData") == 0 && buf) {
        std::filesystem::path out = std::filesystem::path{buf} / "CloakDNS";
        std::free(buf);
        return out;
    }
    return R"(C:\ProgramData\CloakDNS)";
#else
    return "/etc/cloakdns";
#endif
}

std::optional<std::filesystem::path>
find_config_path(std::string_view argv0) {
    std::error_code ec;

    // 1. Sibling of the executable. Portable install layout:
    //    <install>/cloakdns.exe
    //    <install>/cloakdns.toml
    if (!argv0.empty()) {
        std::filesystem::path p{std::string{argv0}};
        auto sibling = p.parent_path() / kConfigFileName;
        if (std::filesystem::exists(sibling, ec)) return sibling;
    }

    // 2. Platform-default directory.
    auto system_path = default_config_dir() / kConfigFileName;
    if (std::filesystem::exists(system_path, ec)) return system_path;

    // 3. Current working directory — convenient for dev, but brittle
    //    when the binary runs as a service with CWD outside the repo.
    std::filesystem::path cwd{kConfigFileName};
    if (std::filesystem::exists(cwd, ec)) return cwd;

    return std::nullopt;
}

} // namespace cloak
