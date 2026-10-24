// Transport tests: endpoints of both families, STUN over IPv4 and IPv6, the connection code with IPv6 candidates, and
// the engine on a simulated network (simnet.h) where IPv6 works regardless of the host kernel.
// Included by selftest.cpp; uses its helpers (CHECK, Node, mkTun, readPkt, mkUdp, mkUdp6, A6, waitFor, ...).
#pragma once


#include "addr.h"
#include "simnet.h"

static uint32_t t4(uint32_t a, uint32_t b, uint32_t c, uint32_t d) { return (a << 24) | (b << 16) | (c << 8) | d; }

// ------------------------------------------------------------------ Addr
static void testAddr() {
    printf("[addr] endpoints of both families\n");
    Addr a = addr4(t4(1, 2, 3, 4), 5), b = addr6(A6("2001:db8::1"), 5);
    CHECK(addrStr(a) == "1.2.3.4:5" && addrStr(b) == "[2001:db8::1]:5");
    CHECK(a == a && b == b && a != b);
    CHECK(addr4(1, 5) != addr4(2, 5) && addr4(1, 5) != addr4(1, 6));
    CHECK(addr6(A6("2001:db8::1"), 5) != addr6(A6("2001:db8::2"), 5) && addr6(A6("2001:db8::1"), 5) != addr6(A6("2001:db8::1"), 6));
    CHECK(addr4(0, 7) != addr6(Ip6{}, 7));  // the family is part of the identity

    sockaddr_storage ss;
    socklen_t sl = 0;
    Addr back;
    CHECK(addrToSock(a, ss, sl) && sl == sizeof(sockaddr_in) && ss.ss_family == AF_INET);
    sockaddr_in s4;
    memcpy(&s4, &ss, sizeof s4);
    CHECK(ntohl(s4.sin_addr.s_addr) == t4(1, 2, 3, 4) && ntohs(s4.sin_port) == 5);
    CHECK(addrFromSock((const sockaddr*)&ss, sl, back) && back == a);
    CHECK(addrToSock(b, ss, sl) && sl == sizeof(sockaddr_in6) && ss.ss_family == AF_INET6);
    sockaddr_in6 s6;
    memcpy(&s6, &ss, sizeof s6);
    CHECK(memcmp(&s6.sin6_addr, b.ip6.data(), 16) == 0 && ntohs(s6.sin6_port) == 5);
    CHECK(addrFromSock((const sockaddr*)&ss, sl, back) && back == b);

    sockaddr_in6 m;  // an IPv4-mapped address from a dual-stack socket is an IPv4 endpoint
    memset(&m, 0, sizeof m);
    m.sin6_family = AF_INET6;
    m.sin6_port = htons(9);
    const uint8_t mp[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 3};
    memcpy(&m.sin6_addr, mp, 16);
    CHECK(addrFromSock((const sockaddr*)&m, sizeof m, back) && back == addr4(t4(10, 1, 2, 3), 9));
    CHECK(!addrFromSock((const sockaddr*)&m, sizeof(sockaddr_in6) - 1, back));   // truncated
    CHECK(!addrFromSock((const sockaddr*)&s4, sizeof(sockaddr_in) - 1, back));
    sockaddr_storage other;
    memset(&other, 0, sizeof other);
    other.ss_family = 1;  // AF_UNIX on both systems
    CHECK(!addrFromSock((const sockaddr*)&other, sizeof other, back));            // another family
    CHECK(!addrFromSock(nullptr, 16, back));

    // networks that are local to the device or the LAN
    CHECK(addrIsLocalNet(addr4(t4(10, 1, 2, 3), 1)) && addrIsLocalNet(addr4(t4(192, 168, 0, 1), 1)) &&
          addrIsLocalNet(addr4(t4(172, 16, 5, 5), 1)) && addrIsLocalNet(addr4(t4(127, 0, 0, 1), 1)) &&
          addrIsLocalNet(addr4(t4(169, 254, 3, 4), 1)));
    CHECK(!addrIsLocalNet(addr4(t4(8, 8, 8, 8), 1)) && !addrIsLocalNet(addr4(t4(172, 32, 0, 1), 1)));
    CHECK(addrIsLocalNet(addr6(A6("fd00::1"), 1)) && addrIsLocalNet(addr6(A6("fc12::1"), 1)) &&
          addrIsLocalNet(addr6(A6("fe80::1"), 1)) && addrIsLocalNet(addr6(A6("::1"), 1)));
    CHECK(!addrIsLocalNet(addr6(A6("2001:db8::1"), 1)) && !addrIsLocalNet(addr6(A6("2a00:1450::1"), 1)));

    // destinations worth sending to
    CHECK(addrUsablePeer(addr4(t4(1, 2, 3, 4), 5)) && addrUsablePeer(addr4(t4(192, 168, 1, 1), 5)) &&
          addrUsablePeer(addr4(t4(127, 0, 0, 1), 5)));
    CHECK(!addrUsablePeer(addr4(t4(1, 2, 3, 4), 0)) && !addrUsablePeer(addr4(0, 5)) &&
          !addrUsablePeer(addr4(t4(224, 0, 0, 1), 5)) && !addrUsablePeer(addr4(0xFFFFFFFFu, 5)));
    CHECK(addrUsablePeer(addr6(A6("2001:db8::1"), 5)) && addrUsablePeer(addr6(A6("fd00::1"), 5)));
    CHECK(!addrUsablePeer(addr6(A6("2001:db8::1"), 0)) && !addrUsablePeer(addr6(A6("::"), 5)) &&
          !addrUsablePeer(addr6(A6("::1"), 5)) && !addrUsablePeer(addr6(A6("fe80::1"), 5)) &&
          !addrUsablePeer(addr6(A6("ff02::1"), 5)) && !addrUsablePeer(addr6(A6("::ffff:1.2.3.4"), 5)));
}

// ------------------------------------------------------------------ STUN over both families
static std::vector<uint8_t> mkStunResp(const uint8_t tx[12], const Addr& a, bool xored, uint16_t type = 0x0101) {
    size_t alen = a.v6 ? 20 : 8;
    std::vector<uint8_t> r(24 + alen, 0);
    putBe16(&r[0], type);
    putBe16(&r[2], (uint16_t)(4 + alen));
    putBe32(&r[4], 0x2112A442u);
    memcpy(&r[8], tx, 12);
    putBe16(&r[20], xored ? 0x0020 : 0x0001);
    putBe16(&r[22], (uint16_t)alen);
    r[25] = a.v6 ? 2 : 1;
    putBe16(&r[26], xored ? (uint16_t)(a.port ^ 0x2112) : a.port);
    if (a.v6) {
        uint8_t mask[16];
        putBe32(mask, 0x2112A442u);
        memcpy(mask + 4, tx, 12);
        for (size_t i = 0; i < 16; i++) r[28 + i] = xored ? (uint8_t)(a.ip6[i] ^ mask[i]) : a.ip6[i];
    } else {
        putBe32(&r[28], xored ? (a.ip4 ^ 0x2112A442u) : a.ip4);
    }
    return r;
}

static void testStunV6() {
    printf("[stun] IPv6 answers, names, sockets of both families\n");
    uint8_t tx[12], other[12];
    randomBytes(tx, 12);
    randomBytes(other, 12);
    const Addr m4 = addr4(t4(203, 0, 113, 9), 51234), m6 = addr6(A6("2001:db8:a::5"), 40001);
    Addr got;
    for (bool x : {true, false}) {
        auto r4 = mkStunResp(tx, m4, x), r6 = mkStunResp(tx, m6, x);
        CHECK(stunIsMessage(r4.data(), r4.size()) && stunIsMessage(r6.data(), r6.size()));
        CHECK(stunParseResponse(r4.data(), r4.size(), tx, got) && got == m4);
        CHECK(stunParseResponse(r6.data(), r6.size(), tx, got) && got == m6);
        CHECK(!stunParseResponse(r6.data(), r6.size(), other, got));  // somebody else's transaction
    }
    {
        auto r = mkStunResp(tx, m6, true, 0x0111);  // error response
        CHECK(!stunParseResponse(r.data(), r.size(), tx, got));
        r = mkStunResp(tx, m6, true);
        CHECK(!stunParseResponse(r.data(), r.size() - 4, tx, got));  // truncated
        r = mkStunResp(tx, m4, true);
        r[25] = 2;  // says IPv6 but carries an IPv4 sized value
        CHECK(!stunParseResponse(r.data(), r.size(), tx, got));
        r[25] = 3;  // unknown family
        CHECK(!stunParseResponse(r.data(), r.size(), tx, got));
    }
    {
        // XOR-MAPPED-ADDRESS wins over a plain MAPPED-ADDRESS (some servers send both)
        auto r = mkStunResp(tx, m6, true);
        auto plain = mkStunResp(tx, addr4(t4(9, 9, 9, 9), 9), false);
        r.insert(r.end(), plain.begin() + 20, plain.end());
        putBe16(&r[2], (uint16_t)(r.size() - 20));
        CHECK(stunParseResponse(r.data(), r.size(), tx, got) && got == m6);
        auto r2 = plain;
        auto xr = mkStunResp(tx, m4, true);
        r2.insert(r2.end(), xr.begin() + 20, xr.end());
        putBe16(&r2[2], (uint16_t)(r2.size() - 20));
        CHECK(stunParseResponse(r2.data(), r2.size(), tx, got) && got == m4);
    }
    for (int i = 0; i < 4000; i++) {  // garbage with a valid header: no crash, no wrong accept
        auto r = mkStunResp(tx, i % 2 ? m6 : m4, i % 3 != 0);
        size_t flips = 1 + (size_t)(i % 4);
        for (size_t k = 0; k < flips; k++) r[20 + (size_t)(rand() % (int)(r.size() - 20))] ^= (uint8_t)(1 + rand() % 255);
        stunParseResponse(r.data(), r.size(), tx, got);
    }

    // names and literals
    auto res = [](const char* s, std::vector<Addr>& v) {
        v.clear();
        return stunResolve(s, v);
    };
    std::vector<Addr> v;
    CHECK(res("198.51.100.1:19302", v) && v.size() == 1 && v[0] == addr4(t4(198, 51, 100, 1), 19302));
    CHECK(res("198.51.100.1", v) && v.size() == 1 && v[0].port == 3478);
    CHECK(res("[2001:db8::53]:3478", v) && v.size() == 1 && v[0] == addr6(A6("2001:db8::53"), 3478));
    CHECK(res("[2001:db8::53]:19302", v) && v[0].port == 19302);
    CHECK(res("[2001:db8::53]", v) && v.size() == 1 && v[0].v6 && v[0].port == 3478);
    CHECK(res("2001:db8::53", v) && v.size() == 1 && v[0].v6 && v[0].port == 3478);
    CHECK(!res("[2001:db8::53", v) && !res("[2001:db8::53]x", v) && !res("[2001:db8::53]:0", v) &&
          !res("[2001:db8::53]:70000", v) && !res("[zzzz]:3478", v) && !res("host:0", v) && !res("host:70000", v) &&
          !res("", v) && !res(":3478", v) && !res("1.2.3.4:", v));
    {
        std::vector<StunServer> all = stunResolveAll({"203.0.113.5:3478", "203.0.113.5:3478", "[2001:db8::53]:3478",
                                                      "[fe80::1]:3478", "[::1]:3478", "[ff02::1]:3478", "0.0.0.0:3478",
                                                      "224.0.0.1:3478", "[bad", ""},
                                                     2000);
        CHECK(all.size() == 2 && all[0].addr == addr4(t4(203, 0, 113, 5), 3478) && all[1].addr == addr6(A6("2001:db8::53"), 3478));
        all = stunResolveAll({"127.0.0.1:9"}, 2000);  // IPv4 loopback stays: tests and local servers
        CHECK(all.size() == 1);
        CHECK(stunResolveAll({}, 100).empty());
    }

    // gathering with one socket per family on the simulated network
    sim::Net net;
    sim::Host h;
    h.name = "h";
    h.pub4 = t4(203, 0, 113, 10);
    h.shift4 = 3;
    h.addr6 = A6("2001:db8:1::10");
    net.addStun(addr4(t4(198, 51, 100, 1), 3478));
    net.addStun(addr6(A6("2001:db8:ffff::1"), 3478));
    auto mk = [&](bool v6) {
        std::string err;
        return net.factory(&h)(v6, err);
    };
    const std::vector<std::string> names = {"198.51.100.1:3478", "[2001:db8:ffff::1]:3478"};
    {
        auto s4 = mk(false), s6 = mk(true);
        std::vector<StunServer> sv = stunResolveAll(names, 1000);
        CHECK(sv.size() == 2);
        uint64_t t0 = nowMs();
        CHECK(stunGather(s4.get(), s6.get(), sv, 3000) == 2);
        CHECK(nowMs() - t0 < 1500);  // ends as soon as everybody answered
        CHECK(sv[0].ok && sv[0].mapped == addr4(h.pub4, (uint16_t)(s4->port() + 3)));
        CHECK(sv[1].ok && sv[1].mapped == addr6(h.addr6, s6->port()));
    }
    {
        auto s4 = mk(false);  // no IPv6 socket: that server is given up at once
        std::vector<StunServer> sv = stunResolveAll(names, 1000);
        uint64_t t0 = nowMs();
        CHECK(stunGather(s4.get(), nullptr, sv, 3000) == 1);
        CHECK(nowMs() - t0 < 1500 && sv[0].ok && !sv[1].ok);
        auto s6 = mk(true);
        sv = stunResolveAll(names, 1000);
        CHECK(stunGather(nullptr, s6.get(), sv, 3000) == 1 && !sv[0].ok && sv[1].ok);
        CHECK(stunGather(nullptr, nullptr, sv, 3000) == 0);
        std::vector<StunServer> none;
        CHECK(stunGather(s4.get(), s6.get(), none, 100) == 0);
    }
    {
        h.has6 = false;  // IPv6 is there but unreachable: sending fails with ENETUNREACH, the server is dropped early
        auto s4 = mk(false), s6 = mk(true);
        std::vector<StunServer> sv = stunResolveAll(names, 1000);
        uint64_t t0 = nowMs();
        CHECK(stunGather(s4.get(), s6.get(), sv, 3000) == 1);
        CHECK(nowMs() - t0 < 1500 && sv[0].ok && !sv[1].ok);
        h.has6 = true;
    }
    {
        auto s4 = mk(false), s6 = mk(true);
        std::vector<StunServer> sv = stunResolveAll({"198.51.100.77:3478"}, 1000);  // nobody there
        uint64_t t0 = nowMs();
        CHECK(stunGather(s4.get(), s6.get(), sv, 700) == 0);
        CHECK(nowMs() - t0 >= 650 && !sv[0].ok);
    }
}

// ------------------------------------------------------------------ connection code, version 4
static void reseal(std::vector<uint8_t>& b) { crypto::blake2s(&b[b.size() - 4], 4, nullptr, 0, b.data(), b.size() - 4); }

static void testOfferV4() {
    printf("[offer] IPv4 and IPv6 candidates\n");
    KeyPair ka, kb;
    crypto::genKeypair(ka.priv, ka.pub);
    crypto::genKeypair(kb.priv, kb.pub);
    Offer a;
    memcpy(a.pub, ka.pub, 32);
    a.expiresAt = (uint32_t)(wallMs() / 1000 + 600);
    a.name = "Alpha";
    a.nat = 1;
    a.cands.push_back(Candidate{0, t4(192, 168, 1, 5), 4000});
    a.cands.push_back(Candidate{1, t4(203, 0, 113, 9), 51234});
    Candidate c6{1, 0, 50000};
    c6.v6 = true;
    c6.ip6 = A6("2001:db8:aaaa::1234");
    a.cands.push_back(c6);
    a.v6 = {A6("2001:db8:aaaa::5"), A6("fd00:1::77")};
    a.port6 = 50000;

    std::vector<uint8_t> blob;
    CHECK(offerEncode(a, blob) && blob[0] == 4 && kOfferVersion == 4);
    Offer d;
    CHECK(offerDecode(blob.data(), blob.size(), d) == OFFER_OK);
    CHECK(d.cands.size() == 3 && !d.cands[0].v6 && d.cands[0].type == 0 && d.cands[0].ip == t4(192, 168, 1, 5) && d.cands[0].port == 4000);
    CHECK(!d.cands[1].v6 && d.cands[1].type == 1 && d.cands[1].ip == t4(203, 0, 113, 9) && d.cands[1].port == 51234);
    CHECK(d.cands[2].v6 && d.cands[2].type == 1 && d.cands[2].ip6 == c6.ip6 && d.cands[2].port == 50000);
    CHECK(d.port6 == 50000 && d.v6 == a.v6 && d.nat == 1 && d.name == "Alpha" && d.expiresAt == a.expiresAt);
    CHECK(memcmp(d.pub, a.pub, 32) == 0);

    // the implicit IPv6 host candidates: every address of the list with the IPv6 port
    {
        std::vector<Candidate> all = offerCandidates(d);
        CHECK(all.size() == 5);
        int n4 = 0, n6 = 0;
        for (const Candidate& c : all) (c.v6 ? n6 : n4)++;
        CHECK(n4 == 2 && n6 == 3);
        bool haveImplicit = false, haveSecond = false;
        for (const Candidate& c : all) {
            if (c.v6 && c.type == 0 && c.ip6 == A6("2001:db8:aaaa::5") && c.port == 50000) haveImplicit = true;
            if (c.v6 && c.type == 0 && c.ip6 == A6("fd00:1::77") && c.port == 50000) haveSecond = true;
        }
        CHECK(haveImplicit && haveSecond);
        CHECK(offerFamilies(d) == 3);
    }
    // repeated addresses: once in the working list, all of them for display
    {
        Offer r = a;
        r.cands.push_back(Candidate{1, t4(192, 168, 1, 5), 4000});  // the same endpoint as the host candidate
        Candidate dup = c6;
        dup.type = 0;
        r.cands.push_back(dup);
        CHECK(offerCandidates(r).size() == 5);
        CHECK(offerCandidates(r, false).size() == 7);
        Offer imp = a;  // an explicit candidate that the list already implies is not added twice
        Candidate same{0, 0, 50000};
        same.v6 = true;
        same.ip6 = A6("2001:db8:aaaa::5");
        imp.cands.push_back(same);
        CHECK(offerCandidates(imp).size() == 5);
    }
    // an offer with IPv6 only, or with IPv4 only
    {
        Offer o6;
        memcpy(o6.pub, kb.pub, 32);
        o6.expiresAt = a.expiresAt;
        o6.v6 = {A6("2001:db8::5")};
        o6.port6 = 4000;
        std::vector<uint8_t> b6;
        CHECK(offerEncode(o6, b6));
        Offer r;
        CHECK(offerDecode(b6.data(), b6.size(), r) == OFFER_OK && r.cands.empty() && offerCandidates(r).size() == 1);
        CHECK(offerFamilies(r) == 2);
        Offer o4;
        memcpy(o4.pub, kb.pub, 32);
        o4.expiresAt = a.expiresAt;
        o4.cands.push_back(Candidate{0, t4(10, 0, 0, 5), 4000});
        std::vector<uint8_t> b4;
        CHECK(offerEncode(o4, b4) && offerDecode(b4.data(), b4.size(), r) == OFFER_OK && offerFamilies(r) == 1 && r.port6 == 0);
    }
    // nothing to connect to: refused when encoding
    {
        std::vector<uint8_t> t;
        Offer none;
        memcpy(none.pub, kb.pub, 32);
        CHECK(!offerEncode(none, t));
        none.v6 = {A6("2001:db8::5")};  // addresses without a port
        CHECK(!offerEncode(none, t));
        none.port6 = 4000;
        none.v6 = {A6("fe80::1"), A6("::1"), A6("ff02::1")};  // none of them can be a destination
        CHECK(!offerEncode(none, t));
        none.v6 = {A6("2001:db8::5")};
        CHECK(offerEncode(none, t));
        Offer many = a;
        many.cands.clear();
        for (int i = 0; i < 13; i++) many.cands.push_back(Candidate{0, t4(10, 0, 0, (uint32_t)(i + 1)), 4000});
        CHECK(!offerEncode(many, t));
        many.cands.pop_back();
        CHECK(offerEncode(many, t));  // 12 are fine
        Offer bad = a;
        bad.cands[0].port = 0;
        CHECK(!offerEncode(bad, t));
        bad = a;
        bad.cands[0].type = 2;
        CHECK(!offerEncode(bad, t));
    }
    // decoding drops candidates that cannot be destinations; a code left with none is of no use
    {
        Offer x = a;
        Candidate ll{0, 0, 4000};
        ll.v6 = true;
        ll.ip6 = A6("fe80::1");
        x.cands.push_back(ll);
        std::vector<uint8_t> bx;
        CHECK(offerEncode(x, bx));
        CHECK(offerDecode(bx.data(), bx.size(), d) == OFFER_OK && d.cands.size() == 3);  // the link-local one is gone
        // one IPv4 candidate, name "A": count at 41, tag at 42, address at 43..46
        Offer one;
        memcpy(one.pub, ka.pub, 32);
        one.name = "A";
        one.expiresAt = a.expiresAt;
        one.cands.push_back(Candidate{0, t4(192, 168, 1, 5), 4000});
        std::vector<uint8_t> b1;
        CHECK(offerEncode(one, b1) && b1[41] == 1 && b1[42] == 0);
        std::vector<uint8_t> z = b1;
        memset(&z[43], 0, 4);
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) == OFFER_NO_CANDIDATES);
        z = b1;
        putBe32(&z[43], t4(224, 0, 0, 251));
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) == OFFER_NO_CANDIDATES);
        z = b1;
        putBe32(&z[43], t4(127, 0, 0, 1));  // loopback is still a destination (two apps on one phone, tests)
        reseal(z);
        CHECK(offerDecode(z.data(), z.size(), d) == OFFER_OK);
    }
    // versions, damage, truncation
    {
        std::vector<uint8_t> o = blob;
        for (uint8_t v : {0, 1, 2, 3, 6, 9, 255}) {
            o[0] = v;
            CHECK(offerDecode(o.data(), o.size(), d) == OFFER_VERSION);
        }
        o[0] = 5;  // a group code without the group fields is not a code
        CHECK(offerDecode(o.data(), o.size(), d) != OFFER_OK);
        o = blob;
        o[blob.size() / 2] ^= 0x10;
        int rc = offerDecode(o.data(), o.size(), d);
        CHECK(rc == OFFER_CHECKSUM || rc == OFFER_FORMAT);
        for (size_t n = 0; n < blob.size(); n++) CHECK(offerDecode(blob.data(), n, d) != OFFER_OK);
        o = blob;
        o.insert(o.end() - 4, 0);
        CHECK(offerDecode(o.data(), o.size(), d) == OFFER_FORMAT);
        o = blob;
        o.insert(o.end(), 0);
        CHECK(offerDecode(o.data(), o.size(), d) != OFFER_OK);
    }
    // fuzz: mutated and resealed codes never crash and never produce a code that breaks the invariants
    {
        int ok = 0;
        for (int i = 0; i < 20000; i++) {
            std::vector<uint8_t> o = blob;
            int flips = 1 + rand() % 3;
            for (int k = 0; k < flips; k++) o[1 + (size_t)(rand() % (int)(o.size() - 5))] ^= (uint8_t)(1 + rand() % 255);
            if (i % 2) reseal(o);
            if (i % 7 == 0) o.resize(o.size() - (size_t)(rand() % 20));
            Offer r;
            if (offerDecode(o.data(), o.size(), r) != OFFER_OK) continue;
            ok++;
            bool good = r.cands.size() <= 12 && r.v6.size() <= 3 && !offerCandidates(r).empty() && r.name.size() <= 24;
            for (const Candidate& c : r.cands) good &= c.port != 0 && c.type <= 1 && addrUsablePeer(candAddr(c));
            CHECK(good);
        }
        CHECK(ok > 100);  // the resealed ones that only changed harmless fields
        for (int i = 0; i < 5000; i++) {
            uint8_t g[260];
            randomBytes(g, sizeof g);
            g[0] = 4;
            Offer r;
            offerDecode(g, 1 + (size_t)(rand() % 259), r);
        }
    }
    // the virtual network does not depend on the IPv6 candidates, and both sides still agree
    {
        Offer p;
        memcpy(p.pub, kb.pub, 32);
        p.expiresAt = a.expiresAt;
        p.cands.push_back(Candidate{0, t4(192, 168, 2, 42), 4001});
        p.v6 = {A6("2001:db8:b::7")};
        p.port6 = 4001;
        Layout l1 = computeLayout(a, p), l2 = computeLayout(p, a);
        Offer a4 = a;
        a4.cands.pop_back();
        Layout l3 = computeLayout(a4, p);
        CHECK(l1.net == l2.net && l1.net == l3.net && l1.net6 == l2.net6);
        CHECK(l1.myIp == l2.peerIp && l1.aliasPeer == l2.aliasMine);
        Offer q = p;  // an IPv6 candidate address must not be taken for an IPv4 host address
        Candidate w{0, t4(192, 168, 77, 20), 4001};
        w.v6 = true;
        q.cands.push_back(w);
        CHECK(computeLayout(a, q).net == l1.net);
    }
}

// ------------------------------------------------------------------ the engine on a simulated network
struct SimLab {
    sim::Net net;  // declared first: the sockets of the engines refer to it and are destroyed before it
    sim::Host ha, hb;
    Node A, B;
    std::vector<std::string> localA{"192.168.1.5", "2001:db8:a::5"}, localB{"192.168.2.42", "2001:db8:b::7"};

    SimLab() {
        ha.name = "A";
        hb.name = "B";
        ha.pub4 = t4(203, 0, 113, 10);
        hb.pub4 = t4(198, 51, 100, 20);
        ha.shift4 = 3;
        hb.shift4 = 11;
        ha.addr6 = A6("2001:db8:a::5");
        hb.addr6 = A6("2001:db8:b::7");
        net.addStun(addr4(t4(192, 0, 2, 1), 3478));
        net.addStun(addr4(t4(192, 0, 2, 2), 3478));
        net.addStun(addr6(A6("2001:db8:5::1"), 3478));
    }
    std::vector<std::string> stunNames() const { return {"192.0.2.1:3478", "192.0.2.2:3478", "[2001:db8:5::1]:3478"}; }

    int prepare(Node& n, sim::Host& h, const std::vector<std::string>& ips, const char* name) {
        n.e.setSocketFactory(net.factory(&h));
        return n.e.prepare(stunNames(), ips, name, 600, n.offer);
    }
    // Prepares both, exchanges the codes and starts; returns false if any step failed.
    bool setup(const Config& cfg, int delayB = 0) {
        A.e.setConfig(cfg);
        B.e.setConfig(cfg);
        bool ok = prepare(A, ha, localA, "Alpha") == 0 && prepare(B, hb, localB, "Bravo") == 0;
        ok &= A.e.setPeer(B.offer) == OFFER_OK && B.e.setPeer(A.offer) == OFFER_OK;
        A.tun = mkTun();
        B.tun = mkTun();
        ok &= A.e.start(A.tun.engineFd, 1500) == 0;
        if (delayB) sleepMs(delayB);
        ok &= B.e.start(B.tun.engineFd, 1500) == 0;
        return ok;
    }
    bool connected(int ms = 8000) {
        return waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, ms);
    }
    static std::string pathOf(Node& n) {
        std::string i = n.e.info();
        size_t p = i.find("path=");
        if (p == std::string::npos) return "";
        size_t e = i.find('\n', p);
        return i.substr(p + 5, e - p - 5);
    }
    // Inner traffic in both directions, IPv4 and IPv6 (the inner families do not depend on the outer one).
    bool exchange(size_t size4 = 100) {
        Layout la, lb2;
        A.e.layout(la);
        B.e.layout(lb2);
        std::vector<uint8_t> got;
        bool ok = true;
        auto u = mkUdp(la.myIp, la.peerIp, 5000, 6000, std::string(size4 - 28, 'q'));
        sendTun(A, u);
        ok &= readPkt(B.tun.testFd, got, 3000) && got == u;
        auto r = mkUdp(lb2.myIp, lb2.peerIp, 6000, 5000, std::string(size4 - 28, 'r'));
        sendTun(B, r);
        ok &= readPkt(A.tun.testFd, got, 3000) && got == r;
        auto u6 = mkUdp6(la.myIp6, la.peerIp6, 5000, 6000, "inner IPv6, A to B");
        sendTun(A, u6);
        ok &= readPkt(B.tun.testFd, got, 3000) && got == u6;
        auto r6 = mkUdp6(lb2.myIp6, lb2.peerIp6, 6000, 5000, "inner IPv6, B to A");
        sendTun(B, r6);
        ok &= readPkt(A.tun.testFd, got, 3000) && got == r6;
        return ok;
    }
    void stopAll() {
        A.e.stop();
        B.e.stop();
    }
};

static bool has(const std::string& s, const std::string& sub) { return s.find(sub) != std::string::npos; }

static void testSimDual() {
    printf("[transport] IPv4 and IPv6 together, NAT and stateful filters\n");
    SimLab L;
    L.ha.fw4 = L.ha.fw6 = L.hb.fw4 = L.hb.fw6 = true;
    Config cfg = fastCfg();
    CHECK(L.setup(cfg, 500));
    CHECK(L.connected());
    std::string text;
    CHECK(L.A.e.describe(L.B.offer, text) == OFFER_OK);
    CHECK(has(text, "families=3") && has(text, "common=1"));
    CHECK(has(text, "srflx:198.51.100.20:" + std::to_string(L.B.e.localPort() + 11)));
    CHECK(has(text, "host:[2001:db8:b::7]:" + std::to_string(L.B.e.localPort6())));
    CHECK(!has(text, "srflx:[2001:db8:b::7]"));  // implied by the host candidate, not written twice
    CHECK(L.A.e.localPort() != 0 && L.A.e.localPort6() != 0 && L.A.e.socketFd() >= 0 && L.A.e.socketFd6() >= 0);
    CHECK(L.A.e.socketFd() != L.A.e.socketFd6());
    CHECK(L.A.field(18) == 1 && L.B.field(18) == 1);  // both IPv4 servers see the same mapping: cone NAT
    std::string ia = L.A.e.info();
    CHECK(has(ia, "transport4=ok") && has(ia, "transport6=ok") && has(ia, "stun=3"));
    CHECK(has(ia, "mapped=203.0.113.10:") && has(ia, "[2001:db8:a::5]:"));
    CHECK(L.exchange());
    CHECK(L.net.delivered4 > 0 && L.net.delivered6 > 0);  // both families were punched
    std::string pa = SimLab::pathOf(L.A), pb = SimLab::pathOf(L.B);
    CHECK(!pa.empty() && !pb.empty());
    CHECK(L.A.field(8) == 0 && L.B.field(8) == 0);  // not a local-network path
    L.stopAll();
}

static void testSimV6Only() {
    printf("[transport] IPv6 only on both sides\n");
    SimLab L;
    L.ha.open4 = L.hb.open4 = false;
    L.ha.fw6 = L.hb.fw6 = true;
    CHECK(L.setup(fastCfg()));
    CHECK(L.connected());
    std::string ia = L.A.e.info();
    CHECK(has(ia, "transport6=ok") && has(ia, "transport4=simulated: no IPv4") && has(ia, "localPort=0"));
    CHECK(L.A.e.socketFd() == -1 && L.A.e.socketFd6() >= 0 && L.A.e.localPort() == 0 && L.A.e.localPort6() != 0);
    std::string text;
    CHECK(L.B.e.describe(L.A.offer, text) == OFFER_OK);
    CHECK(has(text, "families=2") && has(text, "common=1") && !has(text, "host:192.168") && !has(text, "srflx:203."));
    CHECK(has(text, "host:[2001:db8:a::5]:"));
    std::string pa = SimLab::pathOf(L.A), pb = SimLab::pathOf(L.B);
    CHECK(!pa.empty() && pa[0] == '[' && !pb.empty() && pb[0] == '[');
    CHECK(has(L.A.e.info(), "noRoute=0"));
    // everything inside works, big packets are cut into chunks that fit one outer datagram
    CHECK(L.exchange(100));
    CHECK(L.exchange(1500));
    CHECK(L.exchange(3900));
    CHECK(L.net.sent4 == 0 && L.net.delivered4 == 0);
    CHECK(L.net.maxLen6 > 1000 && L.net.maxLen6 <= 1400);
    // keep-alive and ping carry on, the STUN keep-alive goes over IPv6 too
    sleepMs(800);
    CHECK(L.A.state() == ST_CONNECTED && L.B.field(5) >= 0);
    L.stopAll();
}

static void testSimMixed() {
    printf("[transport] dual-stack device and IPv6-only device\n");
    SimLab L;
    L.hb.open4 = false;  // B has no IPv4 at all
    CHECK(L.setup(fastCfg()));
    CHECK(L.connected());
    std::string pa = SimLab::pathOf(L.A);
    CHECK(!pa.empty() && pa[0] == '[');
    std::string text;
    CHECK(L.B.e.describe(L.A.offer, text) == OFFER_OK);
    CHECK(has(text, "families=3") && has(text, "common=1"));
    CHECK(has(L.B.e.info(), "noRoute=0"));  // B never tries IPv4 candidates: it has no IPv4 socket
    CHECK(L.exchange(200));
    CHECK(L.net.delivered6 > 0);
    L.stopAll();
}

static void testSimNoCommon() {
    printf("[transport] no common protocol: reported at once\n");
    SimLab L;
    L.ha.open6 = false;  // A: IPv4 only
    L.hb.open4 = false;  // B: IPv6 only
    Config cfg = fastCfg();
    L.A.e.setConfig(cfg);
    L.B.e.setConfig(cfg);
    CHECK(L.prepare(L.A, L.ha, L.localA, "Alpha") == 0 && L.prepare(L.B, L.hb, L.localB, "Bravo") == 0);
    std::string text;
    CHECK(L.A.e.describe(L.B.offer, text) == OFFER_OK);
    CHECK(has(text, "families=2") && has(text, "common=0"));
    CHECK(L.B.e.describe(L.A.offer, text) == OFFER_OK && has(text, "families=1") && has(text, "common=0"));
    CHECK(L.A.e.setPeer(L.B.offer) == OFFER_OK && L.B.e.setPeer(L.A.offer) == OFFER_OK);
    L.A.tun = mkTun();
    CHECK(L.A.e.start(L.A.tun.engineFd, 1500) == 0);
    CHECK(waitFor([&] { return L.A.state() == ST_FAILED; }, 1500));
    CHECK(has(L.A.e.lastError(), "общего"));
    CHECK(L.net.sent4 == 0 && L.net.sent6 == 0);
    L.stopAll();
}

static void testSimFailover() {
    printf("[transport] the path moves from IPv4 to IPv6 when IPv4 breaks\n");
    SimLab L;
    L.net.drop6 = true;  // IPv6 is broken at the start: the connection comes up over IPv4
    CHECK(L.setup(fastCfg()));
    CHECK(L.connected());
    std::string pa = SimLab::pathOf(L.A);
    CHECK(!pa.empty() && pa[0] != '[');
    CHECK(L.exchange());
    // now IPv4 breaks and IPv6 starts to work
    L.net.drop4 = true;
    L.net.drop6 = false;
    CHECK(waitFor([&] { std::string p = SimLab::pathOf(L.A), q = SimLab::pathOf(L.B); return !p.empty() && p[0] == '[' && !q.empty() && q[0] == '['; }, 25000));
    CHECK(waitFor([&] { return L.A.state() == ST_CONNECTED && L.B.state() == ST_CONNECTED; }, 5000));
    CHECK(L.exchange());
    L.stopAll();
}

static void testSimPrivacyAddress() {
    printf("[transport] IPv6: the address the network sees differs from the interface address\n");
    SimLab L;
    L.ha.open4 = L.hb.open4 = false;
    L.ha.fw6 = L.hb.fw6 = true;
    L.ha.addr6 = A6("2001:db8:a::abcd");  // a temporary address is the one that leaves the device
    L.hb.addr6 = A6("2001:db8:b::beef");
    CHECK(L.setup(fastCfg(), 300));  // the code lists ::5 and ::7: nobody is there
    CHECK(L.connected());
    std::string text;
    CHECK(L.B.e.describe(L.A.offer, text) == OFFER_OK);
    CHECK(has(text, "srflx:[2001:db8:a::abcd]:" + std::to_string(L.A.e.localPort6())));
    CHECK(has(text, "host:[2001:db8:a::5]:"));
    CHECK(L.exchange());
    CHECK(has(SimLab::pathOf(L.A), "2001:db8:b::beef"));
    L.stopAll();
}

static void testSimSendErrors() {
    printf("[transport] a family that cannot send: counted and logged once\n");
    SimLab L;
    L.ha.has6 = false;  // IPv6 socket exists but the network is unreachable
    logClear();
    CHECK(L.setup(fastCfg()));
    CHECK(L.connected());
    CHECK(L.exchange());
    std::string ia = L.A.e.info();
    CHECK(numAfter(ia, "txErr6=") > 0 && numAfter(ia, "txErr4=") == 0);
    std::string lg = logDump();
    size_t cnt = 0;
    for (size_t p = lg.find("отправка на ["); p != std::string::npos; p = lg.find("отправка на [", p + 1)) cnt++;
    CHECK(cnt >= 1 && cnt <= 2);
    CHECK(!has(SimLab::pathOf(L.A), "["));
    L.stopAll();
}

static void testSimSocketFailure() {
    printf("[transport] sockets that cannot be created\n");
    SimLab L;
    L.ha.open4 = L.ha.open6 = false;
    L.A.e.setSocketFactory(L.net.factory(&L.ha));
    std::vector<uint8_t> o;
    CHECK(L.A.e.prepare(L.stunNames(), L.localA, "x", 600, o) == 1);
    std::string er = L.A.e.lastError();
    CHECK(has(er, "IPv4") && has(er, "IPv6"));
    CHECK(L.A.e.socketFd() == -1 && L.A.e.socketFd6() == -1 && L.A.state() == ST_IDLE);
    L.ha.open4 = true;  // IPv4 is back: prepare works again, IPv6 stays unavailable
    CHECK(L.A.e.prepare(L.stunNames(), L.localA, "x", 600, o) == 0);
    CHECK(L.A.e.socketFd() >= 0 && L.A.e.socketFd6() == -1 && L.A.e.localPort6() == 0);
    std::string text;
    CHECK(L.A.e.describe(o, text) == OFFER_OWN && has(text, "families=1") && !has(text, "host:[") && !has(text, "srflx:["));
    L.ha.open6 = true;  // and the other way round after a restart
    L.A.e.stop();
    CHECK(L.A.e.prepare(L.stunNames(), L.localA, "x", 600, o) == 0);
    CHECK(L.A.e.socketFd() >= 0 && L.A.e.socketFd6() >= 0);
    L.A.e.stop();
    CHECK(L.A.e.socketFd() == -1 && L.A.e.socketFd6() == -1);
    // a factory that hands out a socket of the wrong family is not trusted
    L.A.e.setSocketFactory([&](bool v6, std::string& err) -> std::unique_ptr<UdpSocket> {
        (void)err;
        std::string e2;
        return L.net.factory(&L.ha)(!v6, e2);
    });
    CHECK(L.A.e.prepare(L.stunNames(), L.localA, "x", 600, o) == 1);
    // no addresses at all
    L.A.e.setSocketFactory(L.net.factory(&L.ha));
    CHECK(L.A.e.prepare({}, {}, "x", 600, o) == 2);
    L.A.e.stop();
}

static void testSimStunKeepalive() {
    printf("[transport] STUN keep-alive per family and a changed public address\n");
    {
        SimLab L;
        L.A.e.setConfig(fastCfg());
        CHECK(L.prepare(L.A, L.ha, L.localA, "Alpha") == 0);
        CHECK(L.A.field(17) == 0);
        L.ha.shift4 = 99;  // the NAT starts to use another external port
        CHECK(waitFor([&] { return L.A.field(17) == 1; }, 3000));
        L.A.e.stop();
    }
    {
        SimLab L;
        L.ha.open4 = false;  // only the IPv6 keep-alive can notice this
        L.A.e.setConfig(fastCfg());
        CHECK(L.prepare(L.A, L.ha, L.localA, "Alpha") == 0);
        CHECK(L.A.field(17) == 0);
        L.ha.addr6 = A6("2001:db8:a::9999");
        CHECK(waitFor([&] { return L.A.field(17) == 1; }, 3000));
        L.A.e.stop();
    }
}

static void testSimBlackHole() {
    printf("[transport] one family is a black hole from the start: no connection, then it recovers\n");
    SimLab L;
    L.ha.open6 = L.hb.open6 = false;
    L.net.drop4 = true;
    Config cfg = fastCfg();
    cfg.connectTimeoutMs = 1500;
    CHECK(L.setup(cfg));
    CHECK(waitFor([&] { return L.A.state() == ST_FAILED && L.B.state() == ST_FAILED; }, 4000));
    CHECK(has(L.A.e.lastError(), "не ответил"));
    L.net.drop4 = false;
    L.A.e.retry();
    L.B.e.retry();
    CHECK(L.connected(6000));
    CHECK(L.exchange());
    L.stopAll();
}

static void testRealSockets() {
    printf("[engine] real sockets of both families\n");
    Engine e;
    std::vector<uint8_t> o;
    CHECK(e.prepare({}, {"127.0.0.1", "2001:db8::5"}, "real", 600, o) == 0);
    CHECK(e.socketFd() >= 0 && e.localPort() != 0);
    bool v6 = e.socketFd6() >= 0;  // the host kernel may have no IPv6: then the engine runs on IPv4 alone
    CHECK(v6 == (e.localPort6() != 0));
    std::string info = e.info();
    CHECK(has(info, "transport4=ok") && has(info, "transport6="));
    CHECK(v6 ? has(info, "transport6=ok") : !has(info, "transport6=ok"));
    std::string text;
    CHECK(e.describe(o, text) == OFFER_OWN);
    CHECK(has(text, v6 ? "families=3" : "families=1"));
    e.stop();
    CHECK(e.socketFd() == -1 && e.socketFd6() == -1);
}

static void testTransport() {
    testAddr();
    testStunV6();
    testOfferV4();
    testRealSockets();
    testSimDual();
    testSimV6Only();
    testSimMixed();
    testSimNoCommon();
    testSimPrivacyAddress();
    testSimSendErrors();
    testSimSocketFailure();
    testSimStunKeepalive();
    testSimBlackHole();
    testSimFailover();
}
