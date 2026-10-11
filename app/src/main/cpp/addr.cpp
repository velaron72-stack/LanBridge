#include "addr.h"

#include <cstring>

#include "util.h"

namespace lb {

Addr addr4(uint32_t ip, uint16_t port) {
    Addr a;
    a.v6 = false;
    a.ip4 = ip;
    a.port = port;
    return a;
}

Addr addr6(const Ip6& ip, uint16_t port) {
    Addr a;
    a.v6 = true;
    a.ip6 = ip;
    a.port = port;
    return a;
}

std::string addrStr(const Addr& a) {
    if (a.v6) return strfmt("[%s]:%u", ip6Str(a.ip6).c_str(), (unsigned)a.port);
    return strfmt("%s:%u", ipStr(a.ip4).c_str(), (unsigned)a.port);
}

bool addrToSock(const Addr& a, sockaddr_storage& ss, socklen_t& len) {
    memset(&ss, 0, sizeof ss);
    if (a.v6) {
        sockaddr_in6 s6;
        memset(&s6, 0, sizeof s6);
        s6.sin6_family = AF_INET6;
        s6.sin6_port = htons(a.port);
        memcpy(&s6.sin6_addr, a.ip6.data(), 16);
        memcpy(&ss, &s6, sizeof s6);
        len = sizeof s6;
    } else {
        sockaddr_in s4;
        memset(&s4, 0, sizeof s4);
        s4.sin_family = AF_INET;
        s4.sin_port = htons(a.port);
        s4.sin_addr.s_addr = htonl(a.ip4);
        memcpy(&ss, &s4, sizeof s4);
        len = sizeof s4;
    }
    return true;
}

bool addrFromSock(const sockaddr* sa, socklen_t len, Addr& out) {
    if (!sa) return false;
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(sockaddr_in)) {
        sockaddr_in s4;
        memcpy(&s4, sa, sizeof s4);
        out = addr4(ntohl(s4.sin_addr.s_addr), ntohs(s4.sin_port));
        return true;
    }
    if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(sockaddr_in6)) {
        sockaddr_in6 s6;
        memcpy(&s6, sa, sizeof s6);
        Ip6 ip;
        memcpy(ip.data(), &s6.sin6_addr, 16);
        if (ip6IsV4Mapped(ip)) {
            out = addr4(be32(ip.data() + 12), ntohs(s6.sin6_port));
        } else {
            out = addr6(ip, ntohs(s6.sin6_port));
        }
        return true;
    }
    return false;
}

bool addrIsLocalNet(const Addr& a) {
    if (!a.v6) return isPrivateIp(a.ip4);
    return ip6IsLoopback(a.ip6) || ip6IsLinkLocal(a.ip6) || (a.ip6[0] & 0xFE) == 0xFC;
}

bool addrUsablePeer(const Addr& a) {
    if (a.port == 0) return false;
    if (!a.v6) return a.ip4 != 0 && (a.ip4 >> 24) < 224;
    return !(ip6IsUnspecified(a.ip6) || ip6IsLoopback(a.ip6) || ip6IsLinkLocal(a.ip6) || ip6IsMulticast(a.ip6) ||
             ip6IsV4Mapped(a.ip6));
}

}  // namespace lb
