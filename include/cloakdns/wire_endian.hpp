#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <sstream>
#include <string>

namespace cloak {

inline std::uint16_t read_u16_be(std::span<const std::byte> b, std::size_t off) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[off])) << 8) |
         static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(b[off + 1])));
}

inline void write_u16_be(std::span<std::byte> b, std::size_t off, std::uint16_t v) {
    b[off]     = std::byte{static_cast<std::uint8_t>((v >> 8) & 0xff)};
    b[off + 1] = std::byte{static_cast<std::uint8_t>(v & 0xff)};
}

// Stream a value to an ostringstream and return its string form. Useful
// for any type with operator<< — e.g. asio endpoints — where there is
// no cheaper to_string overload available.
template <class T>
std::string to_string_via_stream(const T& v) {
    std::ostringstream os;
    os << v;
    return os.str();
}

} // namespace cloak
