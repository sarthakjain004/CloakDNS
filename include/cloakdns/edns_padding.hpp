#pragma once

#include <cstddef>
#include <span>
#include <vector>

namespace cloak {

// RFC 8467 recommended padding block sizes.
inline constexpr size_t kPadBlockDefault = 128;  // unencrypted / DoH queries
inline constexpr size_t kPadBlockDot     = 468;  // DoT

// Best-effort: pad a DNS query to the next multiple of `block_size`
// bytes per RFC 7830 / 8467 by appending or expanding an EDNS0 OPT
// record's padding option (option code 12). Returns a new owning byte
// vector; returns an unchanged copy when block_size == 0, when the
// query cannot be parsed, or when an OPT record exists but is not the
// last record (serializing a modified OPT RDATA would invalidate
// trailing bytes). Real-world stubs place OPT last.
std::vector<std::byte>
pad_query(std::span<const std::byte> query, size_t block_size);

} // namespace cloak
