#include "group.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

#include "crypto.h"
#include "util.h"

namespace lb {

// ============================================================ derived values

void groupGuestKeys(const uint8_t secret[32], KeyPair& kp) {
    uint8_t buf[11 + 32];
    memcpy(buf, "LBguest-key", 11);
    memcpy(buf + 11, secret, 32);
    crypto::blake2s(kp.priv, 32, nullptr, 0, buf, sizeof buf);
    kp.priv[0] &= 248;
    kp.priv[31] &= 127;
    kp.priv[31] |= 64;
    crypto::x25519Base(kp.pub, kp.priv);
    crypto::wipe(buf, sizeof buf);
}

Ip6 groupNet6(const uint8_t secret[32]) {
    uint8_t buf[4 + 32];
    memcpy(buf, "LB6G", 4);
    memcpy(buf + 4, secret, 32);
    uint8_t h[32];
    crypto::blake2s(h, 32, nullptr, 0, buf, sizeof buf);
    Ip6 n;
    n.fill(0);
    n[0] = 0xFD;
    memcpy(n.data() + 1, h, 5);
    return n;
}

uint8_t groupPickThird(const uint8_t secret[32], const std::vector<uint32_t>& hostIps) {
    uint8_t buf[4 + 32];
    memcpy(buf, "LBG3", 4);
    memcpy(buf + 4, secret, 32);
    uint8_t h[32];
    crypto::blake2s(h, 32, nullptr, 0, buf, sizeof buf);
    const unsigned span = 150;  // 100 .. 249
    unsigned start = h[0] % span;
    for (unsigned i = 0; i < span; i++) {
        uint8_t third = (uint8_t)(100 + (start + i) % span);
        uint32_t net = groupNet4(third);
        bool clash = false;
        for (uint32_t ip : hostIps) clash |= (ip & 0xFFFFFF00u) == net;
        if (!clash) return third;
    }
    return (uint8_t)(100 + start);
}

std::string utf8Trunc(const std::string& s, size_t maxBytes) {
    std::string o;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        size_t len = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
        if (len == 0) {  // a stray continuation byte or an invalid lead byte
            i++;
            continue;
        }
        if (i + len > s.size()) break;
        bool good = true;
        for (size_t k = 1; k < len; k++) good &= ((unsigned char)s[i + k] & 0xC0) == 0x80;
        if (!good) {
            i++;
            continue;
        }
        if (o.size() + len > maxBytes) break;
        if (len == 1 && (c < 0x20 || c == 0x7f)) {
            o.push_back('?');
        } else {
            o.append(s, i, len);
        }
        i += len;
    }
    return o;
}

// ============================================================ the network of a group

static Ip6 withSlot(const Ip6& net, int slot) {
    Ip6 a = net;
    a[15] = (uint8_t)slot;
    return a;
}

GroupNets computeGroupNets(uint32_t net4, const Ip6& net6, int mySlot, const Offer& me,
                           const std::vector<GroupMemberRef>& others) {
    GroupNets g;
    g.mySlot = mySlot;
    g.net4 = net4;
    g.net6 = net6;
    g.myIp4 = net4 | (uint32_t)mySlot;
    g.myIp6 = withSlot(net6, mySlot);

    // how many members announce each real address
    std::map<uint32_t, int> cnt4;
    std::map<Ip6, int> cnt6;
    auto count = [&](const Offer& o) {
        std::set<uint32_t> s4;
        for (const Candidate& c : o.cands)
            if (c.type == 0 && !c.v6) s4.insert(c.ip);
        for (uint32_t ip : s4) cnt4[ip]++;
        std::set<Ip6> s6(o.v6.begin(), o.v6.end());
        for (const Ip6& a : s6) cnt6[a]++;
    };
    count(me);
    for (const GroupMemberRef& m : others) count(*m.offer);

    auto collect4 = [&](const Offer& from, const Offer& installer, std::vector<uint32_t>& out) {
        for (const Candidate& c : from.cands) {
            if (c.type != 0 || c.v6 || out.size() >= 4) continue;
            if (cnt4[c.ip] != 1 || !aliasUsable4(c.ip, installer, net4)) continue;
            if (std::find(out.begin(), out.end(), c.ip) == out.end()) out.push_back(c.ip);
        }
    };
    auto collect6 = [&](const Offer& from, const Offer& installer, std::vector<Ip6>& out) {
        for (const Ip6& a : from.v6) {
            if (out.size() >= 3 || cnt6[a] != 1 || !aliasUsable6(a, installer, net6)) continue;
            if (std::find(out.begin(), out.end(), a) == out.end()) out.push_back(a);
        }
    };

    for (const GroupMemberRef& m : others) {
        MemberNet mn;
        mn.slot = m.slot;
        mn.ip4 = net4 | (uint32_t)m.slot;
        mn.ip6 = withSlot(net6, m.slot);
        collect4(*m.offer, me, mn.aliasPeer);
        collect4(me, *m.offer, mn.aliasMine);
        collect6(*m.offer, me, mn.aliasPeer6);
        collect6(me, *m.offer, mn.aliasMine6);
        for (uint32_t x : mn.aliasPeer)
            if (std::find(g.realPeer.begin(), g.realPeer.end(), x) == g.realPeer.end()) g.realPeer.push_back(x);
        for (uint32_t x : mn.aliasMine)
            if (std::find(g.realMine.begin(), g.realMine.end(), x) == g.realMine.end()) g.realMine.push_back(x);
        for (const Ip6& x : mn.aliasPeer6)
            if (std::find(g.realPeer6.begin(), g.realPeer6.end(), x) == g.realPeer6.end()) g.realPeer6.push_back(x);
        for (const Ip6& x : mn.aliasMine6)
            if (std::find(g.realMine6.begin(), g.realMine6.end(), x) == g.realMine6.end()) g.realMine6.push_back(x);
        g.peers.push_back(mn);
    }
    return g;
}

// ============================================================ messages

namespace {

constexpr size_t kMaxOfferBytes = 500;

void put16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x >> 8));
    v.push_back((uint8_t)x);
}

}  // namespace

std::vector<uint8_t> msgJoin(const std::vector<uint8_t>& offerBlob) {
    std::vector<uint8_t> v;
    v.push_back(K_JOIN);
    v.push_back(1);  // format version
    put16(v, (uint16_t)offerBlob.size());
    v.insert(v.end(), offerBlob.begin(), offerBlob.end());
    return v;
}

bool parseJoin(const uint8_t* p, size_t n, std::vector<uint8_t>& offerBlob) {
    if (n < 4 || p[0] != K_JOIN || p[1] != 1) return false;
    size_t len = be16(p + 2);
    if (len == 0 || len > kMaxOfferBytes || 4 + len != n) return false;
    offerBlob.assign(p + 4, p + 4 + len);
    return true;
}

std::vector<uint8_t> msgWelcome(uint8_t slot, uint8_t maxMembers, uint8_t others) {
    return {K_WELCOME, slot, maxMembers, others};
}

bool parseWelcome(const uint8_t* p, size_t n, uint8_t& slot, uint8_t& maxMembers, uint8_t& others) {
    if (n != 4 || p[0] != K_WELCOME) return false;
    if (p[1] < 2 || p[1] > kGroupMax || p[2] < 2 || p[2] > kGroupMax || p[1] > p[2]) return false;
    if (p[3] > kGroupMax - 2) return false;
    slot = p[1];
    maxMembers = p[2];
    others = p[3];
    return true;
}

std::vector<uint8_t> msgReject(uint8_t reason) { return {K_REJECT, reason}; }

bool parseReject(const uint8_t* p, size_t n, uint8_t& reason) {
    if (n != 2 || p[0] != K_REJECT) return false;
    reason = p[1];
    return true;
}

std::vector<uint8_t> msgMember(const MemberMsg& m) {
    std::vector<uint8_t> v;
    v.push_back(K_MEMBER);
    v.push_back(m.slot);
    v.push_back(m.present ? 1 : 0);
    put16(v, m.ver);
    size_t len = m.present ? m.offer.size() : 0;
    put16(v, (uint16_t)len);
    if (len) v.insert(v.end(), m.offer.begin(), m.offer.begin() + (long)len);
    return v;
}

bool parseMember(const uint8_t* p, size_t n, MemberMsg& m) {
    if (n < 7 || p[0] != K_MEMBER) return false;
    if (p[1] < 1 || p[1] > kGroupMax || p[2] > 1) return false;
    size_t len = be16(p + 5);
    if (len > kMaxOfferBytes || 7 + len != n) return false;
    if ((p[2] == 1) != (len > 0)) return false;
    m.slot = p[1];
    m.present = p[2] == 1;
    m.ver = be16(p + 3);
    m.offer.assign(p + 7, p + 7 + len);
    return true;
}

std::vector<uint8_t> msgMemberAck(uint8_t slot, uint16_t ver) {
    std::vector<uint8_t> v{K_MEMBER_ACK, slot};
    put16(v, ver);
    return v;
}

bool parseMemberAck(const uint8_t* p, size_t n, uint8_t& slot, uint16_t& ver) {
    if (n != 4 || p[0] != K_MEMBER_ACK || p[1] < 1 || p[1] > kGroupMax) return false;
    slot = p[1];
    ver = be16(p + 2);
    return true;
}

std::vector<uint8_t> msgProfile(uint16_t ver, const std::string& name, uint16_t avatarLen) {
    std::string nm = utf8Trunc(name, kProfileNameMax);
    std::vector<uint8_t> v{K_PROFILE};
    put16(v, ver);
    v.push_back((uint8_t)nm.size());
    v.insert(v.end(), nm.begin(), nm.end());
    put16(v, avatarLen);
    return v;
}

bool parseProfile(const uint8_t* p, size_t n, uint16_t& ver, std::string& name, uint16_t& avatarLen) {
    if (n < 6 || p[0] != K_PROFILE) return false;
    size_t nl = p[3];
    if (nl > kProfileNameMax || 4 + nl + 2 != n) return false;
    size_t av = be16(p + 4 + nl);
    if (av > kAvatarMax) return false;
    ver = be16(p + 1);
    name = utf8Trunc(std::string((const char*)p + 4, nl), kProfileNameMax);
    avatarLen = (uint16_t)av;
    return true;
}

std::vector<uint8_t> msgAvatar(uint16_t ver, uint8_t idx, uint8_t cnt, const uint8_t* data, size_t len) {
    std::vector<uint8_t> v{K_AVATAR};
    put16(v, ver);
    v.push_back(idx);
    v.push_back(cnt);
    v.insert(v.end(), data, data + len);
    return v;
}

bool parseAvatar(const uint8_t* p, size_t n, uint16_t& ver, uint8_t& idx, uint8_t& cnt, const uint8_t*& data, size_t& len) {
    if (n < 5 || p[0] != K_AVATAR) return false;
    ver = be16(p + 1);
    idx = p[3];
    cnt = p[4];
    if (cnt < 1 || cnt > kAvatarMaxChunks || idx >= cnt) return false;
    len = n - 5;
    if (len == 0 || len > kAvatarChunk) return false;
    data = p + 5;
    return true;
}

std::vector<uint8_t> msgProfileAck(uint16_t ver, bool haveMeta, uint16_t mask) {
    std::vector<uint8_t> v{K_PROFILE_ACK};
    put16(v, ver);
    v.push_back(haveMeta ? 1 : 0);
    put16(v, mask);
    return v;
}

bool parseProfileAck(const uint8_t* p, size_t n, uint16_t& ver, bool& haveMeta, uint16_t& mask) {
    if (n != 6 || p[0] != K_PROFILE_ACK || p[3] > 1) return false;
    ver = be16(p + 1);
    haveMeta = p[3] == 1;
    mask = be16(p + 4);
    return true;
}

}  // namespace lb
