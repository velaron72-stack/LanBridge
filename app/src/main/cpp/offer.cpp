#include "offer.h"

#include <cstring>

#include "crypto.h"
#include "util.h"

namespace lb {

static const size_t kMaxName = 24;
static const size_t kMaxCands = 8;

bool offerEncode(const Offer& o, std::vector<uint8_t>& out) {
    out.clear();
    if (o.cands.empty() || o.cands.size() > kMaxCands) return false;
    std::string name = o.name.substr(0, kMaxName);
    out.push_back(1);  // version
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
    uint8_t chk[4];
    crypto::blake2s(chk, 4, nullptr, 0, out.data(), out.size());
    out.insert(out.end(), chk, chk + 4);
    return true;
}

int offerDecode(const uint8_t* p, size_t n, Offer& o) {
    if (n < 8) return OFFER_FORMAT;
    if (p[0] != 1) return OFFER_VERSION;
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
    if (pos + nc * 7 + 4 != n) return OFFER_FORMAT;
    for (size_t i = 0; i < nc; i++) {
        Candidate c;
        c.type = p[pos];
        c.ip = be32(p + pos + 1);
        c.port = be16(p + pos + 5);
        pos += 7;
        if (c.type > 1 || c.port == 0) return OFFER_FORMAT;
        r.cands.push_back(c);
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
    return l;
}

}  // namespace lb
