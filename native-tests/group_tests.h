// Group tests: the group code (offer version 5), the pure functions of group.cpp, the message formats, and groups of
// 2..9 engines on the simulated network (simnet.h): admission, mesh, relay through the creator, strict NAT with a hint,
// churn, names and avatars, TUN replacement.
// Included by selftest.cpp after transport_tests.h; uses its helpers.
#pragma once

#include <memory>

#include "engine_impl.h"
#include "group.h"

// ------------------------------------------------------------------ helpers
static Offer gDevice(uint32_t host4, uint8_t n) {
    Offer o;
    o.version = 4;
    o.expiresAt = (uint32_t)(wallMs() / 1000 + 600);
    randomBytes(o.pub, 32);
    o.nat = 1;
    o.name = "dev" + std::to_string(n);
    o.cands.push_back(Candidate{0, host4, (uint16_t)(4000 + n)});
    o.cands.push_back(Candidate{1, t4(203, 0, 113, n), (uint16_t)(5000 + n)});
    return o;
}

static std::string kvGet(const std::string& text, const std::string& key) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        if (e == std::string::npos) e = text.size();
        if (text.compare(pos, key.size() + 1, key + "=") == 0) return text.substr(pos + key.size() + 1, e - pos - key.size() - 1);
        pos = e + 1;
    }
    return "";
}

static std::vector<std::string> splitTab(const std::string& s) {
    std::vector<std::string> v;
    size_t pos = 0;
    for (;;) {
        size_t e = s.find('\t', pos);
        if (e == std::string::npos) {
            v.push_back(s.substr(pos));
            return v;
        }
        v.push_back(s.substr(pos, e - pos));
        pos = e + 1;
    }
}

// ------------------------------------------------------------------ units
static void testGroupOffer() {
    printf("[group] group code (offer v5)\n");
    Offer g = gDevice(t4(192, 168, 1, 5), 1);
    g.group = true;
    randomBytes(g.gsecret, 32);
    g.gthird = 150;
    g.gmax = 8;
    g.v6 = {A6("2001:db8:a::5")};
    g.port6 = 4001;
    std::vector<uint8_t> b;
    CHECK(offerEncode(g, b) && b[0] == 5 && b[1] == 1);
    Offer d;
    CHECK(offerDecode(b.data(), b.size(), d) == OFFER_OK);
    CHECK(d.group && memcmp(d.gsecret, g.gsecret, 32) == 0 && d.gthird == 150 && d.gmax == 8);
    CHECK(memcmp(d.pub, g.pub, 32) == 0 && d.cands.size() == 2 && d.v6.size() == 1 && d.port6 == 4001 && d.name == "dev1");
    // the same device as a direct code: still version 4, no group fields
    Offer plain = g;
    plain.group = false;
    std::vector<uint8_t> bp;
    CHECK(offerEncode(plain, bp) && bp[0] == 4 && bp[1] == 0 && bp.size() + 34 == b.size());
    Offer dp;
    CHECK(offerDecode(bp.data(), bp.size(), dp) == OFFER_OK && !dp.group);
    // fields that make no sense
    for (uint8_t third : {(uint8_t)0, (uint8_t)255}) {
        Offer x = g;
        x.gthird = third;
        std::vector<uint8_t> t;
        CHECK(!offerEncode(x, t));
    }
    for (uint8_t mx : {(uint8_t)0, (uint8_t)1, (uint8_t)9, (uint8_t)255}) {
        Offer x = g;
        x.gmax = mx;
        std::vector<uint8_t> t;
        CHECK(!offerEncode(x, t));
    }
    // a version 5 code needs the group flag; version 4 must not carry one
    {
        std::vector<uint8_t> z = b;
        z[1] = 0;
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);
        z = bp;
        z[1] = 1;  // flags of a version 4 code are not looked at (as in build 20004): still a direct code
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) == OFFER_OK && !d.group);
        z = bp;
        z[0] = 5;
        z[1] = 1;
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);  // the group tail is missing
        z = b;
        z[0] = 4;
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);  // a group tail in a direct code
    }
    // damage anywhere is noticed
    for (size_t i = 0; i < b.size(); i++) {
        std::vector<uint8_t> z = b;
        z[i] ^= (uint8_t)(1u << (i % 8));
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);
    }
    for (size_t n = 0; n < b.size(); n++) CHECK(offerDecode(b.data(), n, d) != OFFER_OK);
    for (int i = 0; i < 20000; i++) {
        uint8_t r[200];
        randomBytes(r, sizeof r);
        r[0] = 5;
        r[1] = 1;
        offerDecode(r, 1 + (size_t)(rand() % 199), d);
    }
    // a resealed group tail with a bad value is refused as well
    {
        std::vector<uint8_t> z = b;
        z[z.size() - 4 - 2] = 0;  // gthird
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);
        z = b;
        z[z.size() - 4 - 1] = 9;  // gmax
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) != OFFER_OK);
    }
}

static void testGroupPure() {
    printf("[group] keys, addresses, text, versions\n");
    uint8_t s1[32], s2[32];
    randomBytes(s1, 32);
    randomBytes(s2, 32);
    KeyPair k1, k1b, k2;
    groupGuestKeys(s1, k1);
    groupGuestKeys(s1, k1b);
    groupGuestKeys(s2, k2);
    CHECK(memcmp(k1.priv, k1b.priv, 32) == 0 && memcmp(k1.pub, k1b.pub, 32) == 0);
    CHECK(memcmp(k1.pub, k2.pub, 32) != 0);
    uint8_t chk[32];
    crypto::x25519Base(chk, k1.priv);
    CHECK(memcmp(chk, k1.pub, 32) == 0);
    CHECK((k1.priv[0] & 7) == 0 && (k1.priv[31] & 0x80) == 0 && (k1.priv[31] & 0x40) != 0);  // clamped

    Ip6 n1 = groupNet6(s1), n1b = groupNet6(s1), n2 = groupNet6(s2);
    CHECK(n1 == n1b && n1 != n2 && n1[0] == 0xFD);
    for (size_t i = 6; i < 16; i++) CHECK(n1[i] == 0);

    for (int i = 0; i < 300; i++) {
        uint8_t s[32];
        randomBytes(s, 32);
        uint8_t t = groupPickThird(s, {});
        CHECK(t >= 100 && t <= 249);
        CHECK(groupPickThird(s, {}) == t);
        // the pick avoids the networks of the host's own interfaces
        uint8_t t2 = groupPickThird(s, {groupNet4(t) | 7});
        CHECK(t2 != t && t2 >= 100 && t2 <= 249);
    }
    {
        uint8_t s[32];
        randomBytes(s, 32);
        std::vector<uint32_t> all;
        for (unsigned t = 100; t <= 248; t++) all.push_back(groupNet4((uint8_t)t) | 9);
        CHECK(groupPickThird(s, all) == 249);  // the only free network
    }

    CHECK(utf8Trunc("abc", 40) == "abc" && utf8Trunc("abc", 2) == "ab" && utf8Trunc("", 5).empty());
    CHECK(utf8Trunc("привет", 5) == "пр" && utf8Trunc("привет", 12) == "привет" && utf8Trunc("привет", 1).empty());
    CHECK(utf8Trunc("\xF0\x9F\x98\x80", 3).empty() && utf8Trunc("\xF0\x9F\x98\x80", 4) == "\xF0\x9F\x98\x80");
    CHECK(utf8Trunc("a\tb\nc", 40) == "a?b?c" && utf8Trunc(std::string("a\0b", 3), 40) == "a?b");
    CHECK(utf8Trunc("\xff\xfe", 40).empty() && utf8Trunc("a\x80z", 40) == "az");
    CHECK(utf8Trunc("\xE2\x82", 40).empty());  // a cut-off character
    for (int i = 0; i < 3000; i++) {
        std::string x((size_t)(rand() % 60), '\0');
        for (char& c : x) c = (char)rand();
        std::string r = utf8Trunc(x, 20);
        CHECK(r.size() <= 20);
        for (unsigned char c : r) CHECK(c >= 0x20 && c != 0x7f);
        CHECK(utf8Trunc(r, 20) == r);  // idempotent, and what is left is valid UTF-8
    }

    CHECK(verNewer(1, 0) && !verNewer(0, 1) && !verNewer(5, 5) && verNewer(0, 65535) && verNewer(10, 65530));
    CHECK(!verNewer(32768, 0) && verNewer(32767, 0));
    CHECK(avatarChunks(0) == 0 && avatarChunks(1) == 1 && avatarChunks(1000) == 1 && avatarChunks(1001) == 2 &&
          avatarChunks(kAvatarMax) == kAvatarMaxChunks && kAvatarMaxChunks <= 16);
    CHECK(groupNet4(150) == t4(192, 168, 150, 0));
}

static void testGroupNets() {
    printf("[group] the network of a group as every member sees it\n");
    const uint32_t net4 = groupNet4(150);
    uint8_t sec[32];
    randomBytes(sec, 32);
    Ip6 net6 = groupNet6(sec);
    Offer a = gDevice(t4(192, 168, 1, 5), 1), b = gDevice(t4(192, 168, 2, 5), 2), c = gDevice(t4(192, 168, 3, 5), 3);
    a.v6 = {A6("2001:db8:a::5")};
    b.v6 = {A6("2001:db8:b::5")};
    c.v6 = {A6("2001:db8:c::5")};
    GroupNets ga = computeGroupNets(net4, net6, 1, a, {{2, &b}, {3, &c}});
    GroupNets gb = computeGroupNets(net4, net6, 2, b, {{1, &a}, {3, &c}});
    GroupNets gc = computeGroupNets(net4, net6, 3, c, {{1, &a}, {2, &b}});
    CHECK(ga.myIp4 == (net4 | 1) && gb.myIp4 == (net4 | 2) && gc.myIp4 == (net4 | 3));
    CHECK(ga.myIp6[15] == 1 && gb.myIp6[15] == 2 && gc.myIp6[15] == 3 && ga.myIp6[0] == 0xFD);
    CHECK(ga.peers.size() == 2 && ga.peers[0].slot == 2 && ga.peers[1].slot == 3);
    CHECK(ga.peers[0].ip4 == gb.myIp4 && ga.peers[1].ip4 == gc.myIp4 && ga.peers[0].ip6 == gb.myIp6);
    CHECK(ga.peers[0].aliasPeer == std::vector<uint32_t>{t4(192, 168, 2, 5)});
    CHECK(ga.peers[0].aliasMine == std::vector<uint32_t>{t4(192, 168, 1, 5)});
    CHECK(ga.realPeer.size() == 2 && ga.realMine == std::vector<uint32_t>{t4(192, 168, 1, 5)});
    // both ends agree: what one routes is what the other keeps as its source address
    CHECK(ga.peers[0].aliasPeer == std::vector<uint32_t>(gb.realMine) && gb.peers[0].aliasPeer == std::vector<uint32_t>(ga.realMine));
    CHECK(ga.peers[0].aliasPeer6 == std::vector<Ip6>{A6("2001:db8:b::5")} && ga.peers[0].aliasMine6 == std::vector<Ip6>{A6("2001:db8:a::5")});
    CHECK(ga.realPeer6.size() == 2 && ga.realMine6.size() == 1);

    // an address announced by two members means nothing across the tunnel
    Offer d = gDevice(t4(192, 168, 1, 5), 4);  // the same home address as `a`
    GroupNets gd = computeGroupNets(net4, net6, 4, d, {{1, &a}, {2, &b}});
    CHECK(gd.peers.size() == 2 && gd.peers[0].aliasPeer.empty() && gd.peers[0].aliasMine.empty());
    CHECK(gd.peers[1].aliasPeer == std::vector<uint32_t>{t4(192, 168, 2, 5)});
    GroupNets ga2 = computeGroupNets(net4, net6, 1, a, {{2, &b}, {4, &d}});
    CHECK(ga2.peers[1].aliasPeer.empty() && ga2.peers[0].aliasPeer.size() == 1);
    // addresses inside the virtual network, loopback and gateway-looking ones are not mirrored
    Offer e = gDevice(net4 | 77, 5);
    e.cands.push_back(Candidate{0, t4(127, 0, 0, 1), 4005});
    e.cands.push_back(Candidate{0, t4(192, 168, 1, 1), 4005});  // looks like a gateway of a's own network
    e.cands.push_back(Candidate{0, t4(10, 0, 0, 9), 4005});
    GroupNets ge = computeGroupNets(net4, net6, 5, e, {{1, &a}});
    GroupNets ga3 = computeGroupNets(net4, net6, 1, a, {{5, &e}});
    CHECK(ga3.peers[0].aliasPeer == std::vector<uint32_t>{t4(10, 0, 0, 9)});
    CHECK(ge.peers[0].aliasPeer == std::vector<uint32_t>{t4(192, 168, 1, 5)});
    // no other members: an empty network that is still valid
    GroupNets gz = computeGroupNets(net4, net6, 1, a, {});
    CHECK(gz.peers.empty() && gz.myIp4 == (net4 | 1) && gz.realPeer.empty());
    // at most four mirrored IPv4 and three IPv6 addresses per member
    Offer f = gDevice(t4(192, 168, 9, 5), 6);
    for (int i = 6; i < 12; i++) f.cands.push_back(Candidate{0, t4(192, 168, (uint32_t)(10 + i), 5), 4006});
    f.v6 = {A6("2001:db8:f::1"), A6("2001:db8:f::2"), A6("2001:db8:f::3"), A6("2001:db8:f::4")};
    GroupNets gf = computeGroupNets(net4, net6, 1, a, {{6, &f}});
    CHECK(gf.peers[0].aliasPeer.size() == 4 && gf.peers[0].aliasPeer6.size() == 3);
}

static void testGroupMessages() {
    printf("[group] message formats\n");
    std::vector<uint8_t> blob(200);
    randomBytes(blob.data(), blob.size());
    {
        auto m = msgJoin(blob);
        std::vector<uint8_t> back;
        CHECK(m[0] == K_JOIN && parseJoin(m.data(), m.size(), back) && back == blob);
        CHECK(!parseJoin(m.data(), m.size() - 1, back) && !parseJoin(m.data(), 3, back) && !parseJoin(m.data(), 0, back));
        auto z = m;
        z[1] = 2;
        CHECK(!parseJoin(z.data(), z.size(), back));
        z = m;
        z[0] = K_WELCOME;
        CHECK(!parseJoin(z.data(), z.size(), back));
        auto e = msgJoin({});
        CHECK(!parseJoin(e.data(), e.size(), back));
        std::vector<uint8_t> huge(501);
        auto h = msgJoin(huge);
        CHECK(!parseJoin(h.data(), h.size(), back));
    }
    {
        uint8_t slot, mx, others;
        auto m = msgWelcome(3, 8, 1);
        CHECK(m[0] == K_WELCOME && parseWelcome(m.data(), m.size(), slot, mx, others) && slot == 3 && mx == 8 && others == 1);
        for (auto bad : {msgWelcome(1, 8, 0), msgWelcome(0, 8, 0), msgWelcome(9, 8, 0), msgWelcome(4, 3, 0), msgWelcome(3, 1, 0),
                         msgWelcome(3, 9, 0), msgWelcome(3, 8, 7)})
            CHECK(!parseWelcome(bad.data(), bad.size(), slot, mx, others));
        CHECK(!parseWelcome(m.data(), 3, slot, mx, others));
        uint8_t why;
        auto r = msgReject(REJ_FULL);
        CHECK(parseReject(r.data(), r.size(), why) && why == REJ_FULL && !parseReject(r.data(), 1, why));
    }
    {
        MemberMsg m, back;
        m.slot = 4;
        m.present = true;
        m.ver = 777;
        m.offer = blob;
        auto w = msgMember(m);
        CHECK(w[0] == K_MEMBER && parseMember(w.data(), w.size(), back) && back.slot == 4 && back.present && back.ver == 777 && back.offer == blob);
        MemberMsg gone;
        gone.slot = 5;
        gone.present = false;
        gone.ver = 9;
        gone.offer = blob;  // ignored when the member is not present
        auto g = msgMember(gone);
        CHECK(g.size() == 7 && parseMember(g.data(), g.size(), back) && !back.present && back.offer.empty() && back.slot == 5);
        auto z = w;
        z[1] = 0;
        CHECK(!parseMember(z.data(), z.size(), back));
        z = w;
        z[1] = 9;
        CHECK(!parseMember(z.data(), z.size(), back));
        z = w;
        z[2] = 2;
        CHECK(!parseMember(z.data(), z.size(), back));
        z = w;
        z[2] = 0;  // not present, but an offer follows
        CHECK(!parseMember(z.data(), z.size(), back));
        z = g;
        z[2] = 1;  // present, but no offer
        CHECK(!parseMember(z.data(), z.size(), back));
        CHECK(!parseMember(w.data(), w.size() - 1, back) && !parseMember(w.data(), 6, back));
        uint8_t slot;
        uint16_t ver;
        auto a = msgMemberAck(6, 4242);
        CHECK(parseMemberAck(a.data(), a.size(), slot, ver) && slot == 6 && ver == 4242);
        a[1] = 0;
        CHECK(!parseMemberAck(a.data(), a.size(), slot, ver));
    }
    {
        uint16_t ver, av, mask;
        std::string name;
        bool meta;
        auto p = msgProfile(12, "Игрок", 5000);
        CHECK(p[0] == K_PROFILE && parseProfile(p.data(), p.size(), ver, name, av) && ver == 12 && name == "Игрок" && av == 5000);
        auto lp = msgProfile(1, std::string(100, 'x'), 0);  // the name is cut to 40 bytes
        CHECK(parseProfile(lp.data(), lp.size(), ver, name, av) && name.size() == 40 && av == 0);
        auto bad = msgProfile(1, "x", (uint16_t)(kAvatarMax + 1));
        CHECK(!parseProfile(bad.data(), bad.size(), ver, name, av));
        CHECK(!parseProfile(p.data(), p.size() - 1, ver, name, av) && !parseProfile(p.data(), 5, ver, name, av));
        auto z = p;
        z[3] = 41;
        CHECK(!parseProfile(z.data(), z.size(), ver, name, av));
        std::vector<uint8_t> data(1000);
        randomBytes(data.data(), data.size());
        auto c = msgAvatar(7, 2, 5, data.data(), data.size());
        uint8_t idx, cnt;
        const uint8_t* dp;
        size_t dl;
        CHECK(c[0] == K_AVATAR && parseAvatar(c.data(), c.size(), ver, idx, cnt, dp, dl) && ver == 7 && idx == 2 && cnt == 5 &&
              dl == 1000 && memcmp(dp, data.data(), 1000) == 0);
        auto c0 = msgAvatar(7, 5, 5, data.data(), 10);  // index past the count
        CHECK(!parseAvatar(c0.data(), c0.size(), ver, idx, cnt, dp, dl));
        auto c1 = msgAvatar(7, 0, 0, data.data(), 10);
        CHECK(!parseAvatar(c1.data(), c1.size(), ver, idx, cnt, dp, dl));
        auto c2 = msgAvatar(7, 0, (uint8_t)(kAvatarMaxChunks + 1), data.data(), 10);
        CHECK(!parseAvatar(c2.data(), c2.size(), ver, idx, cnt, dp, dl));
        auto c3 = msgAvatar(7, 0, 2, data.data(), 0);  // empty chunk
        CHECK(!parseAvatar(c3.data(), c3.size(), ver, idx, cnt, dp, dl));
        std::vector<uint8_t> big(1001);
        auto c4 = msgAvatar(7, 0, 2, big.data(), big.size());
        CHECK(!parseAvatar(c4.data(), c4.size(), ver, idx, cnt, dp, dl));
        auto k = msgProfileAck(3, true, 0x1234);
        CHECK(parseProfileAck(k.data(), k.size(), ver, meta, mask) && ver == 3 && meta && mask == 0x1234);
        k[3] = 2;
        CHECK(!parseProfileAck(k.data(), k.size(), ver, meta, mask));
    }
    // random garbage never crashes a parser or passes as something it is not
    for (int i = 0; i < 30000; i++) {
        uint8_t g[80];
        size_t n = (size_t)(rand() % 80);
        randomBytes(g, sizeof g);
        g[0] = (uint8_t)(K_JOIN + rand() % 9);
        std::vector<uint8_t> bb;
        MemberMsg mm;
        uint8_t u8, u8b, u8c, u8d;
        uint16_t u16, u16b;
        bool bl;
        std::string st;
        const uint8_t* dp;
        size_t dl;
        parseJoin(g, n, bb);
        parseWelcome(g, n, u8, u8b, u8c);
        parseReject(g, n, u8);
        parseMember(g, n, mm);
        parseMemberAck(g, n, u8, u16);
        parseProfile(g, n, u16, st, u16b);
        parseAvatar(g, n, u16, u8, u8d, dp, dl);
        parseProfileAck(g, n, u16, bl, u16b);
    }
}

// ------------------------------------------------------------------ the group lab
struct GM {  // one device
    sim::Host h;
    Node n;
    std::string name;
    std::vector<std::string> ips;
    bool started = false;
};

static void sendTun(GM& g, const std::vector<uint8_t>& p) { sendTun(g.n, p); }

struct GLab {
    sim::Net net;  // first: the sockets of the engines refer to it
    std::vector<std::unique_ptr<GM>> m;
    Config cfg;
    std::vector<uint8_t> code;

    GLab() {
        cfg = fastCfg();
        cfg.memberReapMs = 600;
        cfg.syncMs = 100;
        cfg.joinTimeoutMs = 8000;
        net.addStun(addr4(t4(192, 0, 2, 1), 3478));
        net.addStun(addr4(t4(192, 0, 2, 2), 3478));
        net.addStun(addr6(A6("2001:db8:5::1"), 3478));
    }
    ~GLab() {
        for (auto& g : m) g->n.e.stop();
    }
    static std::vector<std::string> stunNames() { return {"192.0.2.1:3478", "192.0.2.2:3478", "[2001:db8:5::1]:3478"}; }

    GM& add(const char* name, bool v4 = true, bool v6 = true, bool fw = false, std::vector<std::string> extra = {}) {
        std::unique_ptr<GM> g(new GM());
        int i = (int)m.size() + 1;
        g->name = name;
        g->h.name = name;
        g->h.pub4 = t4(203, 0, 113, (uint32_t)(10 + i));
        g->h.shift4 = 3 + 2 * i;
        char b[64];
        snprintf(b, sizeof b, "2001:db8:%x::5", (unsigned)(0xa0 + i));
        g->h.addr6 = A6(b);
        g->h.open4 = g->h.has4 = v4;
        g->h.open6 = g->h.has6 = v6;
        g->h.fw4 = g->h.fw6 = fw;
        if (v4) g->ips.push_back(strfmt("192.168.%d.5", i));
        if (v6) g->ips.push_back(b);
        for (const std::string& e : extra) g->ips.push_back(e);
        m.push_back(std::move(g));
        return *m.back();
    }
    void prep(GM& g) {
        g.n.e.setConfig(cfg);
        g.n.e.setSocketFactory(net.factory(&g.h));
    }
    bool create(GM& g, int ttl = 600) {
        prep(g);
        return g.n.e.prepareGroup(stunNames(), g.ips, g.name, ttl, g.n.offer) == 0 && (code = g.n.offer, true);
    }
    int join(GM& g, const std::vector<uint8_t>& c) {
        prep(g);
        if (g.n.e.prepare(stunNames(), g.ips, g.name, 600, g.n.offer) != 0) return -1;
        return g.n.e.joinGroup(c);
    }
    bool admitted(GM& g, int ms = 10000) {
        return waitFor([&] { return g.n.field(27) == 2 && g.n.field(31) == 1; }, ms);
    }
    bool startTun(GM& g) {
        g.n.tun = mkTun();
        g.started = g.n.e.start(g.n.tun.engineFd, 1500) == 0;
        return g.started;
    }
    // creator + members, all admitted and started
    bool open(GM& creator, std::vector<GM*> members) {
        bool ok = create(creator) && startTun(creator);
        for (GM* x : members) {
            ok &= join(*x, code) == OFFER_OK;
            ok &= admitted(*x);
            ok &= startTun(*x);
        }
        return ok;
    }
    // every listed device sees all the others connected
    bool meshUp(const std::vector<GM*>& all, int ms = 12000) {
        return waitFor(
            [&] {
                for (GM* x : all)
                    if (x->n.field(25) != (int64_t)all.size() - 1 || x->n.state() != ST_CONNECTED) return false;
                return true;
            },
            ms);
    }
    static uint32_t ip4(GM& g) {
        uint32_t ip = 0;
        parseIp(kvGet(g.n.e.netLayout(), "my"), ip);
        return ip;
    }
    static Ip6 ip6(GM& g) {
        Ip6 a{};
        parseIp6(kvGet(g.n.e.netLayout(), "my6"), a);
        return a;
    }
    static void drain(GM& g) {
        std::vector<uint8_t> t;
        while (g.n.tun.testFd >= 0 && readPkt(g.n.tun.testFd, t, 0)) {
        }
    }
    // one datagram of the inner network from `a` to `b`, must arrive unchanged at `b` and nowhere else
    bool unicast(GM& a, GM& b, const std::vector<GM*>& all, size_t size = 100) {
        for (GM* x : all) drain(*x);
        std::string pay(size - 28, 'a' + (char)(ip4(a) & 7));
        auto p = mkUdp(ip4(a), ip4(b), 5000, 6000, pay);
        sendTun(a, p);
        std::vector<uint8_t> got;
        bool ok = readPkt(b.n.tun.testFd, got, 3000) && got == p;
        for (GM* x : all)
            if (x != &b && x->started) ok &= !readPkt(x->n.tun.testFd, got, 60);
        return ok;
    }
    bool unicast6(GM& a, GM& b, const std::vector<GM*>& all) {
        for (GM* x : all) drain(*x);
        auto p = mkUdp6(ip6(a), ip6(b), 5000, 6000, "inner IPv6 in a group");
        sendTun(a, p);
        std::vector<uint8_t> got;
        bool ok = readPkt(b.n.tun.testFd, got, 3000) && got == p;
        for (GM* x : all)
            if (x != &b && x->started) ok &= !readPkt(x->n.tun.testFd, got, 60);
        return ok;
    }
    bool allPairs(const std::vector<GM*>& all, size_t size = 100) {
        bool ok = true;
        for (GM* a : all)
            for (GM* b : all)
                if (a != b) ok &= unicast(*a, *b, all, size);
        return ok;
    }
    // "M" line of the member list of `g` for the member with this slot (empty when absent)
    static std::vector<std::string> mline(GM& g, int slot) {
        std::string t = g.n.e.members();
        size_t pos = 0;
        while (pos < t.size()) {
            size_t e = t.find('\n', pos);
            if (e == std::string::npos) e = t.size();
            std::vector<std::string> f = splitTab(t.substr(pos, e - pos));
            if (f.size() >= 15 && f[0] == "M" && f[1] == std::to_string(slot)) return f;
            pos = e + 1;
        }
        return {};
    }
    static std::string sline(GM& g) {
        std::string t = g.n.e.members();
        return t.substr(0, t.find('\n'));
    }
    int slotOf(GM& g) { return (int)g.n.field(28); }
};

// ------------------------------------------------------------------ scenarios

static std::vector<uint8_t> rndBytes(size_t n) {
    std::vector<uint8_t> v(n);
    if (n) randomBytes(v.data(), n);
    return v;
}

static void testGroupApi() {
    printf("[group] API misuse\n");
    GLab L;
    GM& c = L.add("C");
    GM& j = L.add("J");
    GM& k = L.add("K");
    GM& z = L.add("Z");
    L.prep(c);
    std::vector<uint8_t> out, note;
    CHECK(c.n.e.joinGroup({1, 2, 3}) != OFFER_OK);  // nothing prepared, and not a code
    CHECK(c.n.e.renewGroup(600, out) != 0);         // not a creator
    CHECK(c.n.e.members().compare(0, 2, "S\t") == 0);
    CHECK(c.n.e.netLayout().empty() && c.n.e.hintTopic().empty());
    CHECK(!c.n.e.sealHint(note) && c.n.e.openHint({1, 2, 3}) == -1);
    int64_t st[STATUS_FIELDS];
    c.n.e.status(st);
    CHECK(st[24] == 0 && st[26] == 0 && st[27] == 0 && st[28] == 0 && st[31] == 1);

    CHECK(L.create(c));
    Offer d;
    CHECK(offerDecode(L.code.data(), L.code.size(), d) == OFFER_OK && d.group && d.gmax == 8 && d.gthird >= 100 && d.gthird <= 249);
    CHECK(c.n.e.hintTopic().size() == 26 && c.n.e.hintTopic().compare(0, 2, "lb") == 0);
    std::string nl = c.n.e.netLayout();
    CHECK(kvGet(nl, "group") == "1" && kvGet(nl, "slot") == "1" && kvGet(nl, "net") == ipStr(groupNet4(d.gthird)));
    CHECK(L.ip4(c) == (groupNet4(d.gthird) | 1) && L.ip6(c)[15] == 1);
    std::string text;
    CHECK(c.n.e.describe(L.code, text) == OFFER_OWN && has(text, "group=1") && has(text, "max=8"));
    CHECK(c.n.e.setPeer(L.code) != OFFER_OK);    // a creator cannot take a friend
    CHECK(c.n.e.joinGroup(L.code) != OFFER_OK);  // nor join (its own code, or busy)
    std::vector<uint8_t> again;
    CHECK(c.n.e.prepareGroup(GLab::stunNames(), c.ips, "C", 600, again) == 0);  // a new group replaces the old one
    CHECK(again != L.code);
    L.code = again;

    // a direct code is not a group code, and the other way round
    L.prep(k);
    CHECK(k.n.e.prepare(GLab::stunNames(), k.ips, "K", 600, k.n.offer) == 0);
    L.prep(j);
    CHECK(j.n.e.prepare(GLab::stunNames(), j.ips, "J", 600, j.n.offer) == 0);
    CHECK(j.n.e.joinGroup(k.n.offer) == OFFER_NOT_GROUP);
    CHECK(j.n.e.setPeer(L.code) == OFFER_NOT_GROUP);
    CHECK(j.n.e.joinGroup(j.n.offer) != OFFER_OK);
    int rc = j.n.e.joinGroup({1, 2, 3, 4});
    CHECK(rc == OFFER_FORMAT || rc == OFFER_CHECKSUM);
    {
        Offer o;
        CHECK(offerDecode(L.code.data(), L.code.size(), o) == OFFER_OK);
        o.expiresAt = (uint32_t)(wallMs() / 1000 - 1000);
        std::vector<uint8_t> old;
        CHECK(offerEncode(o, old));
        CHECK(j.n.e.joinGroup(old) == OFFER_EXPIRED);
    }

    // a group whose creator is gone: the newcomer waits, cannot start, and gives up with a reason
    L.cfg.joinTimeoutMs = 1500;
    CHECK(L.create(z));
    std::vector<uint8_t> dead = L.code;
    z.n.e.stop();
    L.code = again;
    j.n.e.setConfig(L.cfg);
    CHECK(j.n.e.joinGroup(dead) == OFFER_OK);
    CHECK(j.n.e.joinGroup(dead) == OFFER_GROUP_BUSY);
    CHECK(j.n.e.setPeer(k.n.offer) != OFFER_OK);
    FakeTun t = mkTun();
    CHECK(j.n.e.start(t.engineFd, 1500) != 0);  // not admitted (the descriptor is closed by the engine)
    CHECK(waitFor([&] { return j.n.field(27) == 3; }, 6000));
    CHECK(has(j.n.e.lastError(), "не отвечает"));
    plat::closeFd(t.testFd);
    // prepare() again resets that state; this time the creator is there
    L.cfg.joinTimeoutMs = 8000;
    CHECK(L.join(j, L.code) == OFFER_OK && L.admitted(j) && L.startTun(j));
    CHECK(c.n.e.members().find("M\t2\t") != std::string::npos);

    // a running device cannot prepare again
    CHECK(waitFor([&] { return j.n.state() == ST_CONNECTED; }, 8000));
    std::vector<uint8_t> o2;
    CHECK(j.n.e.prepare(GLab::stunNames(), j.ips, "J", 600, o2) == 3);
    CHECK(j.n.e.prepareGroup(GLab::stunNames(), j.ips, "J", 600, o2) == 3);
    CHECK(j.n.e.swapTun(-1) != 0);

    // renewing gives the same group with a later expiry; the old code keeps working
    std::vector<uint8_t> renewed;
    CHECK(c.n.e.renewGroup(1200, renewed) == 0);
    Offer r, o1;
    CHECK(offerDecode(renewed.data(), renewed.size(), r) == OFFER_OK && offerDecode(L.code.data(), L.code.size(), o1) == OFFER_OK);
    CHECK(r.group && memcmp(r.gsecret, o1.gsecret, 32) == 0 && memcmp(r.pub, o1.pub, 32) == 0 && r.expiresAt > o1.expiresAt + 300);
    CHECK(r.gthird == o1.gthird && r.gmax == o1.gmax);
    CHECK(L.join(k, renewed) == OFFER_OK && L.admitted(k));
    CHECK(L.slotOf(j) != L.slotOf(k) && L.slotOf(j) >= 2 && L.slotOf(k) >= 2);
}

static void testGroupMesh() {
    printf("[group] three devices: admission, mesh, traffic, broadcast\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Anna", true, true, true);  // behind a stateful filter
    GM& b = L.add("Boris");
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.open(c, {&a, &b}));
    CHECK(L.meshUp(all));
    CHECK(L.slotOf(c) == 1 && L.slotOf(a) == 2 && L.slotOf(b) == 3);
    const uint32_t net = L.ip4(c) & 0xFFFFFF00u;
    for (GM* x : all) {
        CHECK((L.ip4(*x) & 0xFFFFFF00u) == net && (L.ip4(*x) & 0xFF) == (uint32_t)L.slotOf(*x));
        CHECK(L.ip6(*x)[15] == (uint8_t)L.slotOf(*x) && L.ip6(*x)[0] == 0xFD && L.ip6(*x)[1] == L.ip6(c)[1]);
        CHECK(x->n.field(24) == 2 && x->n.field(25) == 2 && x->n.field(23) >= 1 && x->n.field(31) == 1);
        CHECK(x->n.field(26) == (x == &c ? 1 : 2));
        std::string nl = x->n.e.netLayout();
        CHECK(kvGet(nl, "group") == "1" && kvGet(nl, "prefix") == "24" && kvGet(nl, "bcast") == ipStr(net | 255) &&
              kvGet(nl, "prefix6") == "64" && !kvGet(nl, "ver").empty());
    }
    CHECK(c.n.field(29) > (int64_t)(wallMs() / 1000));  // the code is valid for a while
    CHECK(a.n.field(29) == 0);                           // only the creator has one
    CHECK(L.allPairs(all));
    for (GM* x : all)
        for (GM* y : all)
            if (x != y) CHECK(L.unicast6(*x, *y, all));
    CHECK(L.unicast(a, b, all, 3000) && L.unicast(b, c, all, 1500) && L.unicast(c, a, all, 1340));  // chunks

    // limited and directed broadcast reach everybody else, and nobody twice
    std::vector<uint8_t> got;
    for (GM* x : all) GLab::drain(*x);
    auto bc = mkUdp(L.ip4(a), 0xFFFFFFFFu, 5000, 47777, "hello everybody");
    sendTun(a, bc);
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && got == bc);
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == bc);
    CHECK(!readPkt(c.n.tun.testFd, got, 150) && !readPkt(b.n.tun.testFd, got, 10) && !readPkt(a.n.tun.testFd, got, 10));
    auto db = mkUdp(L.ip4(b), net | 255, 5000, 47777, "directed broadcast");
    sendTun(b, db);
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && got == db);
    CHECK(readPkt(a.n.tun.testFd, got, 3000) && got == db);
    auto mc = mkUdp(L.ip4(c), t4(224, 0, 0, 251), 5353, 5353, "mdns");
    sendTun(c, mc);
    CHECK(readPkt(a.n.tun.testFd, got, 3000) && got == mc);
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == mc);
    auto mc6 = mkUdp6(L.ip6(a), A6("ff02::fb"), 5353, 5353, "mdns v6");
    sendTun(a, mc6);
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && got == mc6);
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == mc6);
    CHECK(a.n.field(9) >= 1 && a.n.field(11) >= 1 && c.n.field(10) >= 1 && b.n.field(12) >= 1);

    // a member cannot speak with the address of another one: the source is put back to its own virtual address
    for (GM* x : all) GLab::drain(*x);
    sendTun(a, mkUdp(L.ip4(b), L.ip4(c), 5000, 6000, "spoofed source"));
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && be32(&got[12]) == L.ip4(a) && checksumsOk(got));
    sendTun(a, mkUdp(L.ip4(c), L.ip4(b), 5000, 6000, "pretending to be the creator"));
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && be32(&got[12]) == L.ip4(a) && checksumsOk(got));
    CHECK(!readPkt(c.n.tun.testFd, got, 100));
    // an address that belongs to nobody goes nowhere
    sendTun(a, mkUdp(L.ip4(a), net | 99, 5000, 6000, "nobody"));
    CHECK(!readPkt(c.n.tun.testFd, got, 300) && !readPkt(b.n.tun.testFd, got, 10));
    CHECK(has(a.n.e.flows(), "foreignDst=1"));

    // the member list
    auto la = GLab::mline(c, 2), lb2 = GLab::mline(c, 3);
    CHECK(la.size() >= 15 && la[2] == "Anna" && la[3] == "2" && la[10] == "0" && lb2[2] == "Boris");
    CHECK(GLab::mline(a, 1)[10] == "1" && GLab::mline(a, 1)[2] == "Creator");  // the creator is marked
    CHECK(GLab::mline(a, 3)[3] == "2" && GLab::mline(a, 3)[7] == ipStr(L.ip4(b)));
    CHECK(GLab::sline(a).compare(0, 4, "S\t2\t") == 0);
    CHECK(has(c.n.e.info(), "group=creator") && has(a.n.e.info(), "group=member") && has(a.n.e.info(), "slot=2"));
    CHECK(has(c.n.e.flows(), "T UDP") && has(c.n.e.info(), "guests="));
}

static void testGroupRelay() {
    printf("[group] members that cannot reach each other talk through the creator\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Anna");
    GM& b = L.add("Boris");
    std::vector<GM*> all{&c, &a, &b};
    L.net.block("Anna", "Boris");
    CHECK(L.open(c, {&a, &b}));
    CHECK(L.meshUp(all, 15000));
    CHECK(L.allPairs(all));
    CHECK(L.unicast6(a, b, all) && L.unicast6(b, a, all));
    CHECK(GLab::mline(a, 3)[5] == "3" && GLab::mline(b, 2)[5] == "3");  // "through the creator"
    CHECK(GLab::mline(a, 1)[5] == "1" && GLab::mline(c, 2)[5] == "1");
    CHECK(c.n.field(30) > 0 && a.n.field(30) > 0 && b.n.field(30) > 0);
    CHECK(has(GLab::mline(a, 3)[6], "создател"));
    // chunks and the largest unfragmented packet fit under the same outer limit as without a relay
    L.net.maxLen4 = 0;
    L.net.maxLen6 = 0;
    for (size_t sz : {(size_t)1200, (size_t)1308, (size_t)1309, (size_t)IP_MAX_UNFRAGMENTED, (size_t)1340, (size_t)1500, (size_t)4000})
        CHECK(L.unicast(a, b, all, sz) && L.unicast(b, a, all, sz));
    CHECK(L.net.maxLen4 <= DATA_HDR + 1 + IP_MAX_UNFRAGMENTED + AEAD_TAG);
    CHECK(L.net.maxLen6 <= DATA_HDR + 1 + IP_MAX_UNFRAGMENTED + AEAD_TAG);
    // broadcast crosses the relay too
    std::vector<uint8_t> got;
    for (GM* x : all) GLab::drain(*x);
    auto bc = mkUdp(L.ip4(a), 0xFFFFFFFFu, 5000, 47777, "hello through the creator");
    sendTun(a, bc);
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && got == bc);
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == bc);

    // the way opens: the members find each other directly and the relay is dropped
    L.net.block("Anna", "Boris", false);
    CHECK(waitFor([&] { return GLab::mline(a, 3)[5] == "1" && GLab::mline(b, 2)[5] == "1"; }, 10000));
    CHECK(L.allPairs(all));
    // ... and breaks again while traffic is running: nothing is lost for long
    L.net.block("Anna", "Boris");
    bool through = false;
    uint64_t t0 = nowMs();
    while (nowMs() - t0 < 5000 && !through) {
        for (GM* x : all) GLab::drain(*x);
        auto p = mkUdp(L.ip4(a), L.ip4(b), 5000, 6000, "failover");
        sendTun(a, p);
        through = readPkt(b.n.tun.testFd, got, 250) && got == p;
    }
    CHECK(through);
    CHECK(waitFor([&] { return GLab::mline(a, 3)[5] == "3"; }, 10000));
    CHECK(L.allPairs(all));
}

static void testGroupNoCommonFamily() {
    printf("[group] members without a common address family\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Only6", false, true);  // IPv6 only
    GM& b = L.add("Only4", true, false);  // IPv4 only
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.open(c, {&a, &b}));
    CHECK(L.meshUp(all, 15000));
    CHECK(L.allPairs(all));
    CHECK(L.unicast6(a, b, all) && L.unicast6(b, a, all) && L.unicast6(c, a, all));
    CHECK(GLab::mline(a, 3)[5] == "3" && GLab::mline(b, 2)[5] == "3");
    CHECK(GLab::mline(a, 3)[14] == "1" && GLab::mline(b, 2)[14] == "2");  // address families as announced (bit 0: IPv4)
    CHECK(L.unicast(a, b, all, 4000));
}

static void testGroupStrictNat() {
    printf("[group] creator behind a strict NAT: the newcomer's note opens it\n");
    GLab L;
    L.cfg.joinTimeoutMs = 2500;
    GM& c = L.add("Creator", true, true, true);  // accepts only from addresses it has sent to
    CHECK(L.create(c) && L.startTun(c));
    GM& a = L.add("Anna");
    CHECK(L.join(a, L.code) == OFFER_OK);
    CHECK(waitFor([&] { return a.n.field(27) == 3; }, 8000));  // nobody answers: the first packets are dropped
    CHECK(has(a.n.e.lastError(), "не отвечает") && c.n.field(24) == 0);
    std::vector<uint8_t> note;
    CHECK(!a.n.e.sealHint(note));  // only while joining

    L.cfg.joinTimeoutMs = 10000;
    GM& b = L.add("Boris");
    CHECK(L.join(b, L.code) == OFFER_OK);
    CHECK(b.n.e.hintTopic() == c.n.e.hintTopic() && !b.n.e.hintTopic().empty());
    CHECK(b.n.e.sealHint(note) && note.size() > 40 && note[0] == 0xB1);
    CHECK(c.n.e.openHint(note) >= 1);
    CHECK(has(c.n.e.info(), "pokes="));
    CHECK(L.admitted(b, 8000) && L.startTun(b));
    CHECK(waitFor([&] { return c.n.field(25) == 1 && b.n.field(25) == 1; }, 8000));
    std::vector<GM*> pair{&c, &b};
    CHECK(L.unicast(c, b, pair) && L.unicast(b, c, pair));
    CHECK(!b.n.e.sealHint(note));  // admitted
    // damaged notes, other groups' notes, wrong sizes
    GM& d = L.add("Dora");
    CHECK(L.join(d, L.code) == OFFER_OK);
    std::vector<uint8_t> dn;
    CHECK(d.n.e.sealHint(dn));
    for (size_t i = 0; i < dn.size(); i++) {
        std::vector<uint8_t> z = dn;
        z[i] ^= 0x04;
        CHECK(c.n.e.openHint(z) == -1);
    }
    CHECK(c.n.e.openHint({}) == -1 && c.n.e.openHint(std::vector<uint8_t>(dn.begin(), dn.begin() + 20)) == -1);
    CHECK(c.n.e.openHint(rndBytes(300)) == -1);
    CHECK(b.n.e.openHint(dn) == -1);  // only a creator takes notes
    GLab L2;
    GM& other = L2.add("Other");
    CHECK(L2.create(other));
    CHECK(other.n.e.openHint(dn) == -1);  // sealed for a different group
    CHECK(other.n.e.hintTopic() != c.n.e.hintTopic());
    CHECK(c.n.e.openHint(dn) >= 1 && L.admitted(d, 8000));
}

static void testGroupSecurity() {
    printf("[group] wrong code at the door\n");
    GLab L;
    L.cfg.joinTimeoutMs = 2500;
    GM& c = L.add("Creator");
    GM& x = L.add("Stranger");
    GM& y = L.add("Guest");
    CHECK(L.create(c) && L.startTun(c));
    // the right creator key and addresses but a wrong secret: the door does not open
    Offer o;
    CHECK(offerDecode(L.code.data(), L.code.size(), o) == OFFER_OK);
    o.gsecret[7] ^= 1;
    std::vector<uint8_t> forged;
    CHECK(offerEncode(o, forged));
    CHECK(L.join(x, forged) == OFFER_OK);
    CHECK(waitFor([&] { return x.n.field(27) == 3; }, 8000));
    CHECK(c.n.field(24) == 0 && x.n.field(28) == 0);
    CHECK(has(c.n.e.info(), "guests=0"));
    // the right code still works afterwards
    CHECK(L.join(y, L.code) == OFFER_OK && L.admitted(y, 8000));
    CHECK(c.n.field(24) == 1);
}

static void testGroupFull() {
    printf("[group] eight devices, the ninth is turned away\n");
    GLab L;
    // sixteen engine threads share the CPUs with the other test processes: a joiner may need seconds to be heard
    L.cfg.memberReapMs = 30000;
    L.cfg.hsRefreshMs = 1500;
    L.cfg.stallMs = 8000;
    L.cfg.connectTimeoutMs = 60000;
    GM& c = L.add("D1");
    std::vector<GM*> all{&c};
    std::vector<GM*> mem;
    for (int i = 2; i <= 8; i++) {
        char nm[16];
        snprintf(nm, sizeof nm, "D%d", i);
        GM& g = L.add(nm);
        all.push_back(&g);
        mem.push_back(&g);
    }
    CHECK(L.open(c, mem));
    bool up = L.meshUp(all, 40000);
    CHECK(up);
    if (!up) {
        for (GM* x : all)
            printf("---- %s\n%s\n%s\n", x->name.c_str(), x->n.e.info().c_str(), x->n.e.members().c_str());
    }
    for (GM* x : all) CHECK(x->n.field(24) == 7 && x->n.field(25) == 7);
    std::set<int> slots;
    for (GM* x : all) slots.insert(L.slotOf(*x));
    CHECK(slots.size() == 8 && *slots.begin() == 1 && *slots.rbegin() == 8);
    for (int i = 0; i < 12; i++) {
        GM* a = all[(size_t)(rand() % 8)];
        GM* b = all[(size_t)(rand() % 8)];
        if (a != b) CHECK(L.unicast(*a, *b, all));
    }
    // a broadcast from one reaches the seven others
    std::vector<uint8_t> got;
    for (GM* x : all) GLab::drain(*x);
    auto bc = mkUdp(L.ip4(*all[3]), 0xFFFFFFFFu, 5000, 47777, "to seven");
    sendTun(*all[3], bc);
    for (GM* x : all)
        if (x != all[3]) CHECK(readPkt(x->n.tun.testFd, got, 3000) && got == bc);
    // the ninth
    GM& n9 = L.add("D9");
    CHECK(L.join(n9, L.code) == OFFER_OK);
    CHECK(waitFor([&] { return n9.n.field(27) == 3; }, 8000));
    CHECK(has(n9.n.e.lastError(), "нет мест") && c.n.field(24) == 7);
    // one leaves, the ninth tries again with a fresh start
    all[4]->n.e.stop();
    CHECK(waitFor([&] { return c.n.field(24) == 6; }, 5000));
    CHECK(L.join(n9, L.code) == OFFER_OK && L.admitted(n9, 10000));
    CHECK(L.slotOf(n9) == 5);  // the freed place
}

static void testGroupChurn() {
    printf("[group] leaving, crashing, joining later, the creator going away\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Anna");
    GM& b = L.add("Boris");
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.open(c, {&a, &b}));
    CHECK(L.meshUp(all));
    // Boris leaves politely: everybody forgets him
    b.n.e.stop();
    CHECK(waitFor([&] { return c.n.field(24) == 1 && a.n.field(24) == 1; }, 6000));
    CHECK(GLab::mline(a, 3).empty() && GLab::mline(c, 3).empty());
    // a newcomer gets his place and everybody sees her
    GM& d = L.add("Dora");
    CHECK(L.join(d, L.code) == OFFER_OK && L.admitted(d) && L.startTun(d));
    CHECK(L.slotOf(d) == 3);
    std::vector<GM*> now3{&c, &a, &d};
    CHECK(L.meshUp(now3));
    CHECK(L.allPairs(now3));
    CHECK(GLab::mline(a, 3)[2] == "Dora");
    // Boris comes back with a new key (a new code of his own): a place again
    CHECK(L.join(b, L.code) == OFFER_OK && L.admitted(b) && L.startTun(b));
    CHECK(L.slotOf(b) == 4);
    std::vector<GM*> now4{&c, &a, &d, &b};
    CHECK(L.meshUp(now4));
    CHECK(L.unicast(b, a, now4) && L.unicast(d, b, now4));

    // Anna crashes (no goodbye gets through): the creator takes the place back after a while
    L.net.block("Anna", "Creator");
    L.net.block("Anna", "Dora");
    L.net.block("Anna", "Boris");
    a.n.e.stop();
    a.started = false;
    CHECK(waitFor([&] { return c.n.field(24) == 2; }, 12000));
    CHECK(waitFor([&] { return d.n.field(24) == 2 && b.n.field(24) == 2; }, 12000));
    CHECK(GLab::mline(d, 2).empty());
    std::vector<GM*> now3b{&c, &d, &b};
    CHECK(L.meshUp(now3b));
    CHECK(L.allPairs(now3b));

    // the creator goes away: the others stay connected to each other
    c.n.e.stop();
    c.started = false;
    CHECK(waitFor([&] { return GLab::mline(d, 1)[3] == "4"; }, 6000));  // "left"
    std::vector<GM*> rest{&d, &b};
    CHECK(waitFor([&] { return d.n.field(25) == 1 && b.n.field(25) == 1; }, 6000));
    CHECK(L.unicast(d, b, rest) && L.unicast(b, d, rest));
    CHECK(L.unicast6(d, b, rest));
    // and nobody new can come in
    GM& e = L.add("Eve");
    L.cfg.joinTimeoutMs = 1500;
    CHECK(L.join(e, L.code) == OFFER_OK);
    CHECK(waitFor([&] { return e.n.field(27) == 3; }, 6000));
}

static bool profileSeen(GM& viewer, GM& who, const std::string& name, const std::vector<uint8_t>& avatar) {
    auto line = GLab::mline(viewer, (int)who.n.field(28));
    if (line.empty() || line[2] != name) return false;
    std::vector<uint8_t> av;
    bool got = viewer.n.e.memberAvatar((int)who.n.field(28), av);
    return avatar.empty() ? !got : (got && av == avatar);
}

static void testGroupProfiles() {
    printf("[group] names and avatars\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Anna");
    GM& b = L.add("Boris");
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.open(c, {&a, &b}));
    CHECK(L.meshUp(all));
    // the device name is shown until there is a profile
    CHECK(GLab::mline(c, 2)[2] == "Anna" && GLab::mline(a, 3)[2] == "Boris" && GLab::mline(a, 3)[9] == "0");
    std::vector<uint8_t> av, none;
    CHECK(!a.n.e.memberAvatar(3, av) && !a.n.e.memberAvatar(9, av) && !a.n.e.memberAvatar(0, av));

    auto avA = rndBytes(3000), avB = rndBytes(kAvatarMax);
    CHECK(a.n.e.setProfile("Анна", avA));
    CHECK(b.n.e.setProfile("Борис 😀", avB));
    CHECK(c.n.e.setProfile("Владелец", none));
    CHECK(waitFor([&] {
        return profileSeen(b, a, "Анна", avA) && profileSeen(c, a, "Анна", avA) && profileSeen(a, b, "Борис 😀", avB) &&
               profileSeen(c, b, "Борис 😀", avB) && profileSeen(a, c, "Владелец", none) && profileSeen(b, c, "Владелец", none);
    }, 15000));
    CHECK(GLab::mline(c, 2)[9] != "0" && GLab::sline(a).find("\tАнна\t") != std::string::npos);
    CHECK(a.n.e.memberAvatar((int)a.n.field(28), av) && av == avA);  // own avatar by own slot
    // sizes at the chunk edges
    for (size_t sz : {(size_t)1, (size_t)999, (size_t)1000, (size_t)1001, (size_t)2000, (size_t)kAvatarMax - 1}) {
        auto x = rndBytes(sz);
        CHECK(a.n.e.setProfile("Анна", x));
        CHECK(waitFor([&] { return profileSeen(b, a, "Анна", x) && profileSeen(c, a, "Анна", x); }, 8000));
    }
    // too big: refused, nothing changes
    CHECK(!a.n.e.setProfile("Слишком", rndBytes(kAvatarMax + 1)));
    sleepMs(300);
    CHECK(GLab::mline(b, 2)[2] == "Анна");
    // changing the name alone, clearing everything
    CHECK(a.n.e.setProfile("Аня", none));
    CHECK(waitFor([&] { return profileSeen(b, a, "Аня", none) && profileSeen(c, a, "Аня", none); }, 8000));
    CHECK(a.n.e.setProfile("", none));
    CHECK(waitFor([&] { return profileSeen(b, a, "Anna", none) && profileSeen(c, a, "Anna", none); }, 8000));  // device name again
    // a name is cut to 40 bytes, control characters are replaced
    const std::string longName = "tab\there\nand a very long name that goes on and on and on";
    CHECK(a.n.e.setProfile(longName, none));
    CHECK(waitFor([&] { return GLab::mline(b, 2)[2].compare(0, 3, "tab") == 0; }, 8000));
    std::string nm = GLab::mline(b, 2)[2];
    CHECK(nm.size() <= 40 && nm.find('\t') == std::string::npos && nm.find('\n') == std::string::npos && nm.compare(0, 9, "tab?here?") == 0);
    // the same profile again changes nothing (no new version)
    std::string v1 = GLab::mline(b, 2)[9];
    CHECK(a.n.e.setProfile(longName, none));
    sleepMs(500);
    CHECK(GLab::mline(b, 2)[9] == v1);

    // lossy network: 30 % of the datagrams vanish, the avatar still arrives
    L.net.lossPermille = 300;
    auto big = rndBytes(kAvatarMax);
    CHECK(b.n.e.setProfile("Борис", big));
    CHECK(waitFor([&] { return profileSeen(a, b, "Борис", big) && profileSeen(c, b, "Борис", big); }, 30000));
    L.net.lossPermille = 0;
    // a newcomer sees the profiles of those present, and they see hers
    GM& d = L.add("Dora");
    CHECK(L.join(d, L.code) == OFFER_OK && L.admitted(d) && L.startTun(d));
    auto avD = rndBytes(5000);
    CHECK(d.n.e.setProfile("Дора", avD));
    CHECK(waitFor([&] {
        return profileSeen(d, b, "Борис", big) && profileSeen(d, c, "Владелец", none) && profileSeen(a, d, "Дора", avD) &&
               profileSeen(b, d, "Дора", avD) && profileSeen(c, d, "Дора", avD);
    }, 20000));
    // a profile set before the group even starts is sent as soon as there is somebody to send it to
    GLab L2;
    GM& c2 = L2.add("C2");
    GM& e = L2.add("E");
    auto avE = rndBytes(2500);
    CHECK(e.n.e.setProfile("Early", avE));
    CHECK(L2.open(c2, {&e}));
    CHECK(waitFor([&] { return profileSeen(c2, e, "Early", avE); }, 10000));
}

static void testGroupTunSwap() {
    printf("[group] TUN replacement, mirrored addresses\n");
    GLab L;
    GM& c = L.add("Creator");
    GM& a = L.add("Anna");
    std::vector<GM*> pair{&c, &a};
    CHECK(L.open(c, {&a}));
    CHECK(L.meshUp(pair));
    CHECK(L.allPairs(pair));
    int64_t ver = a.n.field(23);
    FakeTun t2 = mkTun();
    int oldTest = a.n.tun.testFd;
    CHECK(a.n.e.swapTun(t2.engineFd) == 0);
    plat::closeFd(oldTest);
    a.n.tun = t2;
    CHECK(a.n.field(23) == ver);
    CHECK(L.allPairs(pair));
    CHECK(a.n.state() == ST_CONNECTED);

    // Boris brings his own real address; everybody mirrors it (the version of the layout moves)
    int64_t vc = c.n.field(23);
    GM& b = L.add("Boris");
    CHECK(L.join(b, L.code) == OFFER_OK && L.admitted(b) && L.startTun(b));
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.meshUp(all));
    CHECK(c.n.field(23) > vc);
    std::string nl = c.n.e.netLayout();
    CHECK(has(kvGet(nl, "realPeer"), "192.168.2.5") && has(kvGet(nl, "realPeer"), "192.168.3.5") && kvGet(nl, "realMine") == "192.168.1.5");
    CHECK(has(kvGet(nl, "realPeer6"), "2001:db8:a2::5"));
    std::vector<uint8_t> got;
    const uint32_t rc = t4(192, 168, 1, 5), ra = t4(192, 168, 2, 5), rb = t4(192, 168, 3, 5);
    for (GM* x : all) GLab::drain(*x);
    auto r1 = mkUdp(rc, ra, 5000, 6000, "real to real");  // unchanged, to the right one only
    sendTun(c, r1);
    CHECK(readPkt(a.n.tun.testFd, got, 3000) && got == r1 && !readPkt(b.n.tun.testFd, got, 150));
    auto r2 = mkUdp(rb, rc, 6000, 5000, "reply from the real address");
    sendTun(b, r2);
    CHECK(readPkt(c.n.tun.testFd, got, 3000) && got == r2 && !readPkt(a.n.tun.testFd, got, 150));
    auto r3 = mkUdp(ra, rb, 6000, 5000, "member to member by real addresses");
    sendTun(a, r3);
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == r3 && !readPkt(c.n.tun.testFd, got, 150));
    // the swap of the TUN of the creator while members are connected
    FakeTun t3 = mkTun();
    plat::closeFd(c.n.tun.testFd);
    CHECK(c.n.e.swapTun(t3.engineFd) == 0);
    c.n.tun = t3;
    CHECK(L.allPairs(all));

    // two members with the same home address: neither is mirrored
    GLab L2;
    GM& c2 = L2.add("C2");
    GM& x = L2.add("X", true, true, false, {"192.168.50.7"});
    GM& y = L2.add("Y", true, true, false, {"192.168.50.7"});
    std::vector<GM*> all2{&c2, &x, &y};
    CHECK(L2.open(c2, {&x, &y}));
    CHECK(L2.meshUp(all2));
    std::string n2 = c2.n.e.netLayout();
    CHECK(!has(kvGet(n2, "realPeer"), "192.168.50.7") && has(kvGet(n2, "realPeer"), "192.168.2.5") && has(kvGet(n2, "realPeer"), "192.168.3.5"));
    CHECK(L2.allPairs(all2));
}

static void testGroupFlows() {
    printf("[group] load between members, direct and through the creator\n");
    for (int pass = 0; pass < 2; pass++) {
        GLab L;
        GM& c = L.add("Creator");
        GM& a = L.add("Anna");
        GM& b = L.add("Boris");
        std::vector<GM*> all{&c, &a, &b};
        if (pass == 1) L.net.block("Anna", "Boris");
        CHECK(L.open(c, {&a, &b}));
        CHECK(L.meshUp(all, 15000));
        // 600 packets of 1200 bytes each way at once between two members, and the third one is not disturbed
        std::vector<uint8_t> got;
        for (GM* x : all) GLab::drain(*x);
        int sentAB = 0, gotAB = 0, gotBA = 0;
        for (int i = 0; i < 600; i++) {
            std::string pay(1172, (char)('a' + i % 26));
            pay[0] = (char)(i & 0xFF);
            pay[1] = (char)(i >> 8);
            sendTun(a, mkUdp(L.ip4(a), L.ip4(b), 5000, 6000, pay));
            sendTun(b, mkUdp(L.ip4(b), L.ip4(a), 6000, 5000, pay));
            sentAB++;
            if (i % 20 == 19) {
                while (readPkt(b.n.tun.testFd, got, 0)) gotAB++;
                while (readPkt(a.n.tun.testFd, got, 0)) gotBA++;
                sleepMs(5);
            }
        }
        uint64_t end = nowMs() + 4000;
        while (nowMs() < end && (gotAB < sentAB * 98 / 100 || gotBA < sentAB * 98 / 100)) {
            while (readPkt(b.n.tun.testFd, got, 20)) gotAB++;
            while (readPkt(a.n.tun.testFd, got, 20)) gotBA++;
        }
        CHECK(gotAB >= sentAB * 98 / 100 && gotBA >= sentAB * 98 / 100);
        CHECK(!readPkt(c.n.tun.testFd, got, 100));  // the creator relays but does not deliver to itself
        if (pass == 1) CHECK(c.n.field(30) >= 1000);
    }
}

// ---- a creator's code that has expired, and a member that behaves like an attacker
namespace lb {
struct EngineTestAccess {
    static Engine::Impl* impl(Engine& e) { return e.p_.get(); }
};
}  // namespace lb

static void testGroupExpiry() {
    printf("[group] the code expires on the creator's side too, renewing opens it again\n");
    GLab L;
    L.cfg.joinGraceS = 0;
    GM& c = L.add("C");
    GM& a = L.add("A");
    GM& b = L.add("B");
    CHECK(L.create(c, 2) && L.startTun(c));
    CHECK(L.join(a, L.code) == OFFER_OK && L.admitted(a, 5000));
    sleepMs(3500);  // the code is past its time now
    Offer o;
    CHECK(offerDecode(L.code.data(), L.code.size(), o) == OFFER_OK);
    o.expiresAt = (uint32_t)(wallMs() / 1000 + 600);  // a stale copy that claims to be fresh: the creator decides
    std::vector<uint8_t> forged;
    CHECK(offerEncode(o, forged));
    CHECK(L.join(b, forged) == OFFER_OK);
    CHECK(waitFor([&] { return b.n.field(27) == 3; }, 6000));
    CHECK(has(b.n.e.lastError(), "истёк") && c.n.field(24) == 1);
    std::vector<uint8_t> renewed;
    CHECK(c.n.e.renewGroup(600, renewed) == 0);
    CHECK(L.join(b, renewed) == OFFER_OK && L.admitted(b, 8000));
    CHECK(c.n.field(24) == 2);
}

static void rogueSend(GM& from, int toSlot, const std::vector<uint8_t>& plain) {
    Engine::Impl* im = EngineTestAccess::impl(from.n.e);
    std::lock_guard<std::mutex> g(im->mu);
    Peer* p = im->peerBySlot(toSlot);
    if (!p) return;
    Session* s = im->bestSession(p, nowMs());
    if (!s) return;
    im->sendTransport(p, s, plain.data(), plain.size(), nowMs());
}

static void testGroupRogueMember() {
    printf("[group] a member cannot edit the member list or speak for the creator\n");
    GLab L;
    GM& c = L.add("C");
    GM& a = L.add("A");
    GM& b = L.add("B");
    GM& z = L.add("Z");
    CHECK(L.open(c, {&a, &b}));
    std::vector<GM*> all{&c, &a, &b};
    CHECK(L.meshUp(all, 15000));
    L.prep(z);
    CHECK(z.n.e.prepare(GLab::stunNames(), z.ips, "Z", 600, z.n.offer) == 0);
    int sa = L.slotOf(a), sb = L.slotOf(b);
    CHECK(sa >= 2 && sb >= 2);
    // a forged member-list entry: only the creator's word counts
    MemberMsg m;
    m.slot = 7;
    m.present = true;
    m.ver = 500;
    m.offer = z.n.offer;
    for (int i = 0; i < 5; i++) {
        rogueSend(a, sb, msgMember(m));
        sleepMs(100);
    }
    sleepMs(800);
    CHECK(b.n.field(24) == 2);
    CHECK(b.n.e.members().find("M\t7\t") == std::string::npos);
    // a datagram "relayed" by a member instead of the creator is not taken in
    int64_t before = b.n.field(16);
    std::vector<uint8_t> fake{K_RELAY, 1, T_DATA};
    for (int i = 0; i < 40; i++) fake.push_back((uint8_t)(0x40 + i));
    for (int i = 0; i < 20; i++) rogueSend(a, sb, fake);
    sleepMs(1200);
    CHECK(b.n.field(16) - before < 10);
    CHECK(b.n.state() == ST_CONNECTED && b.n.field(24) == 2 && b.n.field(25) == 2);

    // inner packets: a member may only speak from its own addresses, and only to the receiver or to everybody
    auto ipPlain = [](const std::vector<uint8_t>& pkt) {
        std::vector<uint8_t> pl{K_IP};
        pl.insert(pl.end(), pkt.begin(), pkt.end());
        return pl;
    };
    std::vector<uint8_t> got;
    GLab::drain(b);
    auto good = mkUdp(L.ip4(a), L.ip4(b), 5000, 47001, "from A to B");
    rogueSend(a, sb, ipPlain(good));
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == good);  // the way in works
    auto good6 = mkUdp6(L.ip6(a), L.ip6(b), 5000, 47001, "from A to B, v6");
    rogueSend(a, sb, ipPlain(good6));
    CHECK(readPkt(b.n.tun.testFd, got, 3000) && got == good6);
    auto spoofSrc = mkUdp(L.ip4(c), L.ip4(b), 5000, 47002, "A pretends to be the creator");
    auto spoofDst = mkUdp(L.ip4(a), L.ip4(c), 5000, 47003, "meant for the creator, sent to B");
    auto spoofSrc6 = mkUdp6(L.ip6(c), L.ip6(b), 5000, 47002, "A pretends to be the creator, v6");
    auto spoofDst6 = mkUdp6(L.ip6(a), L.ip6(c), 5000, 47003, "meant for the creator, sent to B, v6");
    for (const auto* pk : {&spoofSrc, &spoofDst, &spoofSrc6, &spoofDst6}) rogueSend(a, sb, ipPlain(*pk));
    CHECK(!readPkt(b.n.tun.testFd, got, 1500));

    // a late copy of an old member-list entry (datagrams get reordered) does not bring a departed member back
    std::vector<uint8_t> bOffer = b.n.offer;
    b.n.e.stop();
    CHECK(waitFor([&] { return a.n.field(24) == 1 && c.n.field(24) == 1; }, 8000));
    MemberMsg old;
    old.slot = (uint8_t)sb;
    old.present = true;
    old.ver = 1;
    old.offer = bOffer;
    // (the creator repeats its newer entry until it is acknowledged, so a wrong acceptance would only flicker: look often)
    bool flicker = false;
    for (int i = 0; i < 3; i++) {
        rogueSend(c, sa, msgMember(old));  // the creator itself is the sender: only the version tells it is stale
        for (int k = 0; k < 12; k++) {
            sleepMs(12);
            if (a.n.field(24) != 1) flicker = true;
        }
    }
    CHECK(!flicker);
    CHECK(a.n.field(24) == 1);
    CHECK(a.n.e.members().find("M\t" + std::to_string(sb) + "\t") == std::string::npos);
}

static const char* g_onlyGroupTest = nullptr;  // selftest groups <name>: run one scenario
static void testGroups() {
#define RUN_GROUP(fn) \
    if (!g_onlyGroupTest || !strcmp(g_onlyGroupTest, #fn)) fn()
    RUN_GROUP(testGroupOffer);
    RUN_GROUP(testGroupPure);
    RUN_GROUP(testGroupNets);
    RUN_GROUP(testGroupMessages);
    RUN_GROUP(testGroupApi);
    RUN_GROUP(testGroupMesh);
    RUN_GROUP(testGroupRelay);
    RUN_GROUP(testGroupNoCommonFamily);
    RUN_GROUP(testGroupStrictNat);
    RUN_GROUP(testGroupSecurity);
    RUN_GROUP(testGroupFlows);
    RUN_GROUP(testGroupTunSwap);
    RUN_GROUP(testGroupProfiles);
    RUN_GROUP(testGroupChurn);
    RUN_GROUP(testGroupFull);
    RUN_GROUP(testGroupExpiry);
    RUN_GROUP(testGroupRogueMember);
#undef RUN_GROUP
}
