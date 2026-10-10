#include "offer.h"

#include <cstring>

#include "crypto.h"
#include "util.h"

namespace lb {

static const size_t kMaxName = 24;
static const size_t kMaxCands = 8;
static const size_t kMaxV6 = 3;

bool offerEncode(const Offer& o, std::vector<uint8_t>& out) {
    out.clear();
    if (o.cands.empty() || o.cands.size() > kMaxCands || o.v6.size() > kMaxV6) return false;
    std::string name = o.name.substr(0, kMaxName);
    out.push_back(kOfferVersion);
    out.push_back(0);  // flags
    uint8_t b4[4];
    putBe32(b4, o.expiresAt);
    out.insert(out.end(), b4, b4 + 4);
    out.insert(out.end(), o.pub, o.pub + 32);
    out.push_back(o.nat);
    out.push_back((uint8_t)name.size());
    out.insert(out.end(), name.begin(), name.end());
    out.push_back((uint8_t)o.cands.size());
    for (const Candidate& c : o.cands) {
        out.push_back(c.type);
        putBe32(b4, c.ip);
        out.insert(out.end(), b4, b4 + 4);
        uint8_t b2[2];
        putBe16(b2, c.port);
        out.insert(out.end(), b2, b2 + 2);
    }
    out.push_back((uint8_t)o.v6.size());
    for (const Ip6& a : o.v6) out.insert(out.end(), a.begin(), a.end());
    uint8_t chk[4];
    crypto::blake2s(chk, 4, nullptr, 0, out.data(), out.size());
    out.insert(out.end(), chk, chk + 4);
    return true;
}

int offerDecode(const uint8_t* p, size_t n, Offer& o) {
    if (n < 8) return OFFER_FORMAT;
    if (p[0] != kOfferVersion) return OFFER_VERSION;
    size_t pos = 2;
    if (n < 6 + 32 + 2 + 1 + 4) return OFFER_FORMAT;
    Offer r;
    r.version = p[0];
    r.expiresAt = be32(p + pos);
    pos += 4;
    memcpy(r.pub, p + pos, 32);
    pos += 32;
    r.nat = p[pos++];
    size_t nl = p[pos++];
    if (nl > kMaxName || pos + nl + 1 > n) return OFFER_FORMAT;
    r.name.assign((const char*)p + pos, nl);
    pos += nl;
    size_t nc = p[pos++];
    if (nc == 0 || nc > kMaxCands) return OFFER_FORMAT;
    if (pos + nc * 7 + 1 + 4 > n) return OFFER_FORMAT;
    for (size_t i = 0; i < nc; i++) {
        Candidate c;
        c.type = p[pos];
        c.ip = be32(p + pos + 1);
        c.port = be16(p + pos + 5);
        pos += 7;
        if (c.type > 1 || c.port == 0) return OFFER_FORMAT;
        r.cands.push_back(c);
    }
    size_t n6 = p[pos++];
    if (n6 > kMaxV6 || pos + n6 * 16 + 4 != n) return OFFER_FORMAT;
    for (size_t i = 0; i < n6; i++) {
        Ip6 a;
        memcpy(a.data(), p + pos, 16);
        pos += 16;
        r.v6.push_back(a);
    }
    uint8_t chk[4];
    crypto::blake2s(chk, 4, nullptr, 0, p, pos);
    if (!crypto::ctEqual(chk, p + pos, 4)) return OFFER_CHECKSUM;
    r.name = sanitize(r.name, kMaxName);
    o = r;
    return OFFER_OK;
}

static uint32_t A(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return (a << 24) | (b << 16) | (c << 8) | d; }

Layout computeLayout(const Offer& mine, const Offer& peer) {
    const uint32_t nets[] = {A(192, 168, 77, 0), A(192, 168, 177, 0), A(192, 168, 217, 0), A(10, 77, 77, 0),
                             A(172, 30, 77, 0),  A(10, 213, 77, 0),   A(192, 168, 233, 0), A(172, 29, 213, 0)};
    std::vector<uint32_t> used;
    for (const Candidate& c : mine.cands)
        if (c.type == 0) used.push_back(c.ip);
    for (const Candidate& c : peer.cands)
        if (c.type == 0) used.push_back(c.ip);
    uint32_t chosen = nets[0];
    for (uint32_t n : nets) {
        bool clash = false;
        for (uint32_t ip : used) {
            if ((ip & 0xFFFFFF00u) == n) {
                clash = true;
                break;
            }
        }
        if (!clash) {
            chosen = n;
            break;
        }
    }
    Layout l;
    l.net = chosen;
    l.prefix = 24;
    l.bcast = chosen | 255u;
    l.initiator = memcmp(mine.pub, peer.pub, 32) < 0;
    l.myIp = chosen | (l.initiator ? 1u : 2u);
    l.peerIp = chosen | (l.initiator ? 2u : 1u);

    // A real address is mirrored through the tunnel unless it could be confused with something on the side that
    // installs the route: it must differ from every host address of that side, and inside a network shared with that
    // side it must not look like a gateway or a broadcast address (.0, .1, .254, .255). The Android side additionally
    // drops addresses that are its actual gateway or DNS server.
    auto aliasOk = [&](uint32_t ip, const Offer& installer) {
        uint32_t a = ip >> 24;
        if (a == 0 || a == 127 || a >= 224) return false;
        if ((ip >> 16) == ((169u << 8) | 254u)) return false;
        if ((ip & 0xFFFFFF00u) == l.net) return false;
        uint32_t last = ip & 0xFFu;
        if (last == 0 || last == 255) return false;
        for (const Candidate& c : installer.cands) {
            if (c.type != 0) continue;
            if (c.ip == ip) return false;
            if ((c.ip >> 8) == (ip >> 8) && (last == 1 || last == 254)) return false;
        }
        return true;
    };
    auto collect = [&](const Offer& from, const Offer& installer, std::vector<uint32_t>& out) {
        for (const Candidate& c : from.cands) {
            if (c.type != 0 || out.size() >= 4) continue;
            if (!aliasOk(c.ip, installer)) continue;
            bool dup = false;
            for (uint32_t x : out) dup |= x == c.ip;
            if (!dup) out.push_back(c.ip);
        }
    };
    collect(peer, mine, l.aliasPeer);
    collect(mine, peer, l.aliasMine);

    // IPv6: a unique-local /64 (fdXX:XXXX:XXXX::/64) that both sides derive from the two public keys, so no
    // coordination is needed and two different pairs of devices get different networks.
    {
        const uint8_t* lo = l.initiator ? mine.pub : peer.pub;
        const uint8_t* hi = l.initiator ? peer.pub : mine.pub;
        uint8_t buf[3 + 64];
        memcpy(buf, "LB6", 3);
        memcpy(buf + 3, lo, 32);
        memcpy(buf + 35, hi, 32);
        uint8_t h[32];
        crypto::blake2s(h, 32, nullptr, 0, buf, sizeof buf);
        l.net6.fill(0);
        l.net6[0] = 0xFD;
        memcpy(l.net6.data() + 1, h, 5);
        l.myIp6 = l.net6;
        l.peerIp6 = l.net6;
        l.myIp6[15] = l.initiator ? 1 : 2;
        l.peerIp6[15] = l.initiator ? 2 : 1;
        l.prefix6 = 64;
    }
    // A real IPv6 address is mirrored under the same conditions as an IPv4 one: it must be a global or unique-local
    // unicast address, outside the virtual /64, different from every address of the side that installs the route,
    // and in a network shared with that side it must not look like a router (interface id 0 .. 0xff).
    auto aliasOk6 = [&](const Ip6& a, const Offer& installer) {
        if (ip6IsUnspecified(a) || ip6IsLoopback(a) || ip6IsLinkLocal(a) || ip6IsMulticast(a) || ip6IsV4Mapped(a))
            return false;
        if (ip6SamePrefix64(a, l.net6)) return false;
        bool lowIid = true;
        for (size_t i = 8; i < 15; i++) lowIid &= a[i] == 0;
        for (const Ip6& b : installer.v6) {
            if (a == b) return false;
            if (ip6SamePrefix64(a, b) && lowIid) return false;
        }
        return true;
    };
    auto collect6 = [&](const Offer& from, const Offer& installer, std::vector<Ip6>& out) {
        for (const Ip6& a : from.v6) {
            if (out.size() >= 3 || !aliasOk6(a, installer)) continue;
            bool dup = false;
            for (const Ip6& x : out) dup |= x == a;
            if (!dup) out.push_back(a);
        }
    };
    collect6(peer, mine, l.aliasPeer6);
    collect6(mine, peer, l.aliasMine6);
    return l;
}

}  // namespace lb
