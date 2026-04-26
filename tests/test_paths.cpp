#include "cloakdns/paths.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace cloak;

namespace {

struct TempDir {
    std::filesystem::path path;
    TempDir()
        : path(std::filesystem::temp_directory_path() /
               ("cloak_paths_" + std::to_string(std::rand()))) {
        std::filesystem::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
};

void touch(const std::filesystem::path& p) {
    std::ofstream{p} << "";
}

} // namespace

TEST(Paths, DefaultConfigDirIsNonEmpty) {
    const auto d = default_config_dir();
    EXPECT_FALSE(d.empty());
#ifdef _WIN32
    EXPECT_NE(d.string().find("CloakDNS"), std::string::npos);
#else
    EXPECT_EQ(d.string(), "/etc/cloakdns");
#endif
}

TEST(Paths, SiblingOfArgv0IsPreferred) {
    TempDir tmp;
    const auto argv0 = tmp.path / "cloakdns.exe";
    const auto sibling = tmp.path / "cloakdns.toml";
    touch(argv0);
    touch(sibling);

    const auto resolved = find_config_path(argv0.string());
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(*resolved, sibling);
}

TEST(Paths, MissingEverywhereReturnsNullopt) {
    TempDir tmp;
    const auto argv0 = tmp.path / "cloakdns.exe";
    touch(argv0);  // binary exists but no .toml anywhere
    // If the workstation happens to have /etc/cloakdns/cloakdns.toml or
    // %ProgramData%\CloakDNS\cloakdns.toml or ./cloakdns.toml, this
    // test isn't meaningful — skip rather than assert nullopt. Most
    // dev machines won't have those.
    if (std::filesystem::exists(default_config_dir() / "cloakdns.toml") ||
        std::filesystem::exists("cloakdns.toml")) {
        GTEST_SKIP() << "pre-existing config interferes with this test";
    }
    const auto resolved = find_config_path(argv0.string());
    EXPECT_FALSE(resolved.has_value());
}

TEST(Paths, EmptyArgv0StillChecksSystemAndCwd) {
    // With empty argv0, sibling check is skipped; system/cwd checks
    // should still work. Exercise the no-crash path.
    const auto resolved = find_config_path("");
    // Don't assert a specific outcome — depends on workstation state.
    // Just ensure the call returns without throwing.
    SUCCEED();
    (void)resolved;
}
