#include "ipv6.h"

#include <arpa/inet.h>

#include <cstdio>
#include <cstring>

#include "util.h"

namespace lb {

std::string ip6Str(const Ip6& a) {
    uint16_t w[8];
    for (int i = 0; i < 8; i++) w[i] = (uint16_t)((a[(size_t)i * 2] << 8) | a[(size_t)i * 2 + 1]);
    int bestStart = -1, bestLen = 0;
    for (int i = 0; i < 8;) {
        if (w[i] != 0) {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && w[j] == 0) j++;
        if (j - i > bestLen) {
            bestLen = j - i;
            bestStart = i;
        }
        i = j;
    }
    if (bestLen < 2) bestStart = -1;
    std::string s;
    char buf[8];
    for (int i = 0; i < 8; i++) {
        if (i == bestStart) {
            s += "::";
            i += bestLen - 1;
            continue;
        }
        if (!s.empty() && s.back() != ':') s += ':';
        snprintf(buf, sizeof buf, "%x", (unsigned)w[i]);
        s += buf;
    }
    if (s.empty()) s = "::";
    return s;
}

bool parseIp6(const std::string& str, Ip6& out) {
    std::string s = str;
    size_t pc = s.find('%');
    if (pc != std::string::npos) s.resize(pc);
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') s = s.substr(1, s.size() - 2);
    if (s.empty() || s.find(':') == std::string::npos) return false;
    in6_addr a;
    if (inet_pton(AF_INET6, s.c_str(), &a) != 1) return false;
    memcpy(out.data(), &a, 16);
    return true;
}

bool ip6IsUnspecified(const Ip6& a) {
    for (uint8_t b : a)
        if (b) return false;
    return true;
}

bool ip6IsLoopback(const Ip6& a) {
    for (size_t i = 0; i < 15; i++)
        if (a[i]) return false;
    return a[15] == 1;
}

bool ip6IsLinkLocal(const Ip6& a) { return a[0] == 0xFE && (a[1] & 0xC0) == 0x80; }

bool ip6IsMulticast(const Ip6& a) { return a[0] == 0xFF; }

bool ip6IsV4Mapped(const Ip6& a) {
    for (size_t i = 0; i < 10; i++)
        if (a[i]) return false;
    return a[10] == 0xFF && a[11] == 0xFF;
}

bool ip6SamePrefix64(const Ip6& a, const Ip6& b) { return memcmp(a.data(), b.data(), 8) == 0; }

Ip6Info ip6Parse(const uint8_t* p, size_t n) {
    Ip6Info r;
    if (n < 40 || (p[0] >> 4) != 6) return r;
    size_t payload = be16(p + 4);
    if (payload == 0) return r;  // empty or a jumbogram
    size_t tot = 40 + payload;
    if (tot > n) return r;
    uint8_t nh = p[6];
    size_t off = 40;
    for (int i = 0; i < 10; i++) {
        if (nh == 0 || nh == 43 || nh == 60) {  // hop-by-hop, routing, destination options
            if (off + 8 > tot) return r;
            size_t len = ((size_t)p[off + 1] + 1) * 8;
            if (off + len > tot) return r;
            nh = p[off];
            off += len;
        } else if (nh == 44) {  // fragment
            if (off + 8 > tot) return r;
            uint16_t fo = be16(p + off + 2);
            r.fragment = true;
            nh = p[off];
            off += 8;
            if ((fo & 0xFFF8) != 0) {
                r.first = false;
                r.ok = true;
                r.tot = tot;
                r.proto = nh;
                r.l4off = off;
                return r;
            }
        } else if (nh == 51) {  // authentication header
            if (off + 8 > tot) return r;
            size_t len = ((size_t)p[off + 1] + 2) * 4;
            if (off + len > tot) return r;
            nh = p[off];
            off += len;
        } else {
            r.ok = true;
            r.tot = tot;
            r.proto = nh;
            r.l4off = off;
            return r;
        }
    }
    return r;  // too many extension headers
}

static void patchChecksum(uint8_t* c, const uint8_t* oldSrc, const uint8_t* newSrc, bool udp) {
    uint16_t oc = be16(c);
    if (udp && oc == 0) return;
    uint32_t sum = (~(uint32_t)oc) & 0xFFFF;
    for (int i = 0; i < 8; i++) {
        uint32_t o = be16(oldSrc + i * 2), nw = be16(newSrc + i * 2);
        sum += (~o) & 0xFFFF;
        sum += nw;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t nc = (uint16_t)~sum;
    if (udp && nc == 0) nc = 0xFFFF;
    putBe16(c, nc);
}

void ip6RewriteSrc(uint8_t* p, size_t tot, const Ip6& newSrc) {
    Ip6Info in = ip6Parse(p, tot);
    uint8_t oldSrc[16];
    memcpy(oldSrc, p + 8, 16);
    memcpy(p + 8, newSrc.data(), 16);
    if (!in.ok || !in.first) return;
    size_t coff = 0;
    bool udp = false;
    if (in.proto == 6 && in.l4off + 18 <= in.tot) coff = in.l4off + 16;
    else if (in.proto == 17 && in.l4off + 8 <= in.tot) coff = in.l4off + 6, udp = true;
    else if (in.proto == 58 && in.l4off + 4 <= in.tot) coff = in.l4off + 2;
    if (!coff) return;
    patchChecksum(p + coff, oldSrc, newSrc.data(), udp);
}

bool icmp6LocalOnly(uint8_t type) { return (type >= 130 && type <= 137) || type == 141 || type == 142 || type == 143; }

}  // namespace lb
