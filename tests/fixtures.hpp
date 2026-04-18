#pragma once

#include <array>
#include <cstddef>

namespace cloak::fixtures {

// -------------------------------------------------------------------------
// kExampleQueryEdns — 40 bytes
//
// Standard query for example.com A IN, with an EDNS0 OPT record in the
// Additional section. Hex adapted from docs/06-implementation-roadmap.md §M1
// and cross-checked against docs/01-dns-primer.md §"Header — 12 bytes".
//
//   id    = 0xa37c
//   flags = 0x0120  (RD=1, AD=1)
//   qdcount=1 ancount=0 nscount=0 arcount=1
//   question: "example.com" A IN
//   additional: . OPT class=4096 ttl=... rdlen=0
// -------------------------------------------------------------------------
inline constexpr std::array<std::byte, 40> kExampleQueryEdns{{
    std::byte{0xa3}, std::byte{0x7c},            // ID
    std::byte{0x01}, std::byte{0x20},            // flags: RD=1, AD=1
    std::byte{0x00}, std::byte{0x01},            // QDCOUNT=1
    std::byte{0x00}, std::byte{0x00},            // ANCOUNT=0
    std::byte{0x00}, std::byte{0x00},            // NSCOUNT=0
    std::byte{0x00}, std::byte{0x01},            // ARCOUNT=1
    std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
    std::byte{'m'},  std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
    std::byte{0x03}, std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
    std::byte{0x00},                             // name terminator
    std::byte{0x00}, std::byte{0x01},            // QTYPE=A
    std::byte{0x00}, std::byte{0x01},            // QCLASS=IN
    std::byte{0x00},                             // OPT NAME = root
    std::byte{0x00}, std::byte{0x29},            // TYPE=41 (OPT)
    std::byte{0x10}, std::byte{0x00},            // CLASS = 4096 (max UDP)
    std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x80},            // TTL (extended flags)
    std::byte{0x00}, std::byte{0x00},            // RDLEN=0
}};

// -------------------------------------------------------------------------
// kExampleResponseCompressed — 49 bytes
//
// Synthetic response: www.example.com A IN → 93.184.216.34, with the
// answer NAME encoded as a compression pointer (0xc00c) back to the
// question QNAME. Mirrors docs/01-dns-primer.md §"Name encoding".
// -------------------------------------------------------------------------
inline constexpr std::array<std::byte, 49> kExampleResponseCompressed{{
    std::byte{0xa3}, std::byte{0x7c},            // ID
    std::byte{0x81}, std::byte{0x80},            // flags: QR=1 RD=1 RA=1
    std::byte{0x00}, std::byte{0x01},            // QDCOUNT=1
    std::byte{0x00}, std::byte{0x01},            // ANCOUNT=1
    std::byte{0x00}, std::byte{0x00},            // NSCOUNT=0
    std::byte{0x00}, std::byte{0x00},            // ARCOUNT=0
    std::byte{0x03}, std::byte{'w'}, std::byte{'w'}, std::byte{'w'},
    std::byte{0x07}, std::byte{'e'}, std::byte{'x'}, std::byte{'a'},
    std::byte{'m'},  std::byte{'p'}, std::byte{'l'}, std::byte{'e'},
    std::byte{0x03}, std::byte{'c'}, std::byte{'o'}, std::byte{'m'},
    std::byte{0x00},                             // terminator
    std::byte{0x00}, std::byte{0x01},            // QTYPE=A
    std::byte{0x00}, std::byte{0x01},            // QCLASS=IN
    std::byte{0xc0}, std::byte{0x0c},            // NAME = pointer to offset 12
    std::byte{0x00}, std::byte{0x01},            // TYPE=A
    std::byte{0x00}, std::byte{0x01},            // CLASS=IN
    std::byte{0x00}, std::byte{0x00},
    std::byte{0x01}, std::byte{0x2c},            // TTL=300
    std::byte{0x00}, std::byte{0x04},            // RDLEN=4
    std::byte{0x5d}, std::byte{0xb8},
    std::byte{0xd8}, std::byte{0x22},            // 93.184.216.34
}};

} // namespace cloak::fixtures
