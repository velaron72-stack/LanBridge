// LanBridge native core: IPv6 helpers (addresses, header walk, source rewrite with incremental checksum).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace lb {

using Ip6 = std::array<uint8_t, 16>;

std::string ip6Str(const Ip6& a);               // RFC 5952 text form (lower case, longest zero run compressed)
bool parseIp6(const std::string& s, Ip6& out);  // textual address; a "%zone" suffix is ignored

bool ip6IsUnspecified(const Ip6& a);  // ::
bool ip6IsLoopback(const Ip6& a);     // ::1
bool ip6IsLinkLocal(const Ip6& a);    // fe80::/10
bool ip6IsMulticast(const Ip6& a);    // ff00::/8
bool ip6IsV4Mapped(const Ip6& a);     // ::ffff:0:0/96
inline unsigned ip6McastScope(const Ip6& a) { return a[1] & 0x0F; }  // 1 interface-local, 2 link-local, 5 site, e global
bool ip6SamePrefix64(const Ip6& a, const Ip6& b);

struct Ip6Info {
    bool ok = false;         // a well-formed header chain inside the buffer
    size_t tot = 0;          // 40 + payload length
    size_t l4off = 0;        // offset of the upper-layer header (or of the data of a non-first fragment)
    uint8_t proto = 0;       // upper-layer protocol (6 TCP, 17 UDP, 58 ICMPv6, ...)
    bool fragment = false;   // carries a fragment header
    bool first = true;       // the upper-layer header is present (false only for non-first fragments)
};

// Walks the extension headers (hop-by-hop, routing, destination options, fragment, AH). Jumbograms are rejected.
Ip6Info ip6Parse(const uint8_t* p, size_t n);

// Replaces the source address and fixes the TCP/UDP/ICMPv6 checksum incrementally. A non-first fragment only gets
// the new address (its checksum lives in the first fragment, which is rewritten on its own).
void ip6RewriteSrc(uint8_t* p, size_t tot, const Ip6& newSrc);

// ICMPv6 messages that only make sense on the local link (MLD, neighbour and router discovery) and must never
// cross the tunnel: types 130-137, 141, 142, 143.
bool icmp6LocalOnly(uint8_t type);

}  // namespace lb
