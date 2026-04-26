// libFuzzer entry point for the DNS parser.
//
// Build with clang on Linux:
//   clang++ -std=c++20 -fsanitize=fuzzer,address,undefined \
//     -I../../include -I../../build/_deps/asio-src/asio/include \
//     fuzz_dns_parser.cpp ../../src/dns_parser.cpp -o fuzz_parser
//
// Run:
//   ./fuzz_parser -max_total_time=3600 corpus/
//
// Corpus seed: drop a few captured DNS queries and responses into
// corpus/ as raw bytes. libFuzzer will mutate from there.

#include "cloakdns/dns_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const auto bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(data), size};
    try {
        (void)cloak::parse(bytes);
    } catch (const cloak::ParseError&) {
        // Expected path for malformed input.
    }
    return 0;
}
