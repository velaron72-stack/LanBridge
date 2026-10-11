// LanBridge native core: a UDP endpoint of either family (the tunnel's outer transport runs over IPv4 and IPv6).
#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <string>

#include "ipv6.h"

namespace lb {

struct Addr {
    bool v6 = false;
    uint32_t ip4 = 0;  // host byte order
    Ip6 ip6{};
    uint16_t port = 0;

    bool operator==(const Addr& o) const { return v6 == o.v6 && port == o.port && (v6 ? ip6 == o.ip6 : ip4 == o.ip4); }
    bool operator!=(const Addr& o) const { return !(*this == o); }
};

Addr addr4(uint32_t ip, uint16_t port);
Addr addr6(const Ip6& ip, uint16_t port);

std::string addrStr(const Addr& a);  // "1.2.3.4:5" or "[2001:db8::1]:5"

// Conversions to and from the system structures. An IPv4-mapped IPv6 address read from a socket becomes an IPv4 Addr.
bool addrToSock(const Addr& a, sockaddr_storage& ss, socklen_t& len);
bool addrFromSock(const sockaddr* sa, socklen_t len, Addr& out);

// Host or private-network address (RFC 1918, loopback, link-local; IPv6: unique-local, link-local, loopback).
bool addrIsLocalNet(const Addr& a);

// A destination worth sending to: not 0.0.0.0, not multicast/reserved (IPv4 >= 224.0.0.0); IPv6 must be a global or
// unique-local unicast address (no unspecified, loopback, link-local, multicast, IPv4-mapped); the port is not 0.
bool addrUsablePeer(const Addr& a);

}  // namespace lb
