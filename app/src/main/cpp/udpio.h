// LanBridge native core: the UDP sockets of the tunnel (one per address family). The engine only talks to this
// interface, so tests can put another transport underneath (this is how IPv6 is tested on a host without IPv6).
#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "addr.h"

namespace lb {

class UdpSocket {
public:
    virtual ~UdpSocket() {}
    virtual int fd() const = 0;        // pollable, non-blocking
    virtual bool v6() const = 0;
    virtual uint16_t port() const = 0;  // local port
    // Like sendto(MSG_DONTWAIT): the number of bytes, or -1 with errno set (EAGAIN: try later).
    virtual ssize_t sendTo(const Addr& to, const uint8_t* b, size_t n) = 0;
    // Like recvfrom(MSG_DONTWAIT): the length, 0 for a datagram to ignore, -1 when nothing is waiting.
    virtual ssize_t recvFrom(uint8_t* b, size_t cap, Addr& from) = 0;
};

using UdpFactory = std::function<std::unique_ptr<UdpSocket>(bool v6, std::string& err)>;

// The real thing: a non-blocking UDP socket bound to the wildcard address and a free port. An IPv6 socket is
// IPv6-only (IPv4 has its own socket), so both can use any port and neither depends on v4-mapped addresses.
std::unique_ptr<UdpSocket> openSysUdp(bool v6, std::string& err);

}  // namespace lb
