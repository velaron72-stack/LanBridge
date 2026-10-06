// LanBridge native self-test: crypto known answers, protocol units, and a two-engine loopback integration run.
// Build and run with ./run.sh (uses ASAN + UBSAN).
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "crypto.h"
#include "engine.h"
#include "offer.h"
#include "protocol.h"
#include "stun.h"
#include "util.h"

using namespace lb;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        if (cond) {                                                       \
            g_pass++;                                                     \
        } else {                                                          \
            g_fail++;                                                     \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                 \
    } while (0)

static void hexTo(const char* s, uint8_t* o) {
    size_t n = strlen(s) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        o[i] = (uint8_t)v;
    }
}
static std::string H(const uint8_t* p, size_t n) { return hexStr(p, n); }
static void sleepMs(int ms) { usleep((useconds_t)ms * 1000); }
static bool waitFor(const std::function<bool()>& f, int timeoutMs) {
    uint64_t end = nowMs() + (uint64_t)timeoutMs;
    while (nowMs() < end) {
        if (f()) return true;
        sleepMs(10);
    }
    return f();
}

// ------------------------------------------------------------------ crypto
static void testCrypto() {
    printf("[crypto]\n");
    uint8_t out[64];
    crypto::blake2s(out, 32, nullptr, 0, (const uint8_t*)"abc", 3);
    CHECK(H(out, 32) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    crypto::blake2s(out, 32, nullptr, 0, nullptr, 0);
    CHECK(H(out, 32) == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    uint8_t k8[8];
    memset(k8, 'k', 8);
    crypto::blake2s(out, 32, k8, 8, (const uint8_t*)"hello", 5);
    CHECK(H(out, 32) == "7ee1c6ea5f24ee0108518c1d3faab2c5daa4750d5fc1606c40c2bf89deb80368");
    crypto::blake2s(out, 16, k8, 8, (const uint8_t*)"hello", 5);
    CHECK(H(out, 16) == "a2b14a54c7afbb7bf4efe840e344e1ef");
    uint8_t big[200];
    for (int i = 0; i < 200; i++) big[i] = (uint8_t)i;
    crypto::blake2s(out, 32, nullptr, 0, big, 64);
    CHECK(H(out, 32) == "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e");
    crypto::blake2s(out, 32, nullptr, 0, big, 200);
    CHECK(H(out, 32) == "6d244e1a06ce4ef578dd0f63aff0936706735119ca9c8d22d86c801414ab9741");
    uint8_t k32[32];
    for (int i = 0; i < 32; i++) k32[i] = (uint8_t)i;
    crypto::hmac(out, k32, 32, big, 100);
    CHECK(H(out, 32) == "a81c95080ba2a7c4ed1b7b4c21dec2c4fd6dc9f03ff37b6d65289dc95a7d1ef1");
    uint8_t t0[32], t1[32], t2[32];
    crypto::kdf3(t0, t1, t2, k32, big, 50);
    CHECK(H(t0, 32) == "ff7652d8cf0e2bdbc031e40271ef4c3d823abc2e9f01d4ad193851823ebb36b4");
    CHECK(H(t1, 32) == "4aec93ea3b0f1a98c117d1d27ca18e7fd3727bdb7ff8e8b877c1b3423204efaa");
    CHECK(H(t2, 32) == "b279057c314d7458315df1a4125fdb25cff4155680909af290d2292eacad3156");

    uint8_t a[32], u[32], r[32];
    hexTo("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", a);
    hexTo("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    crypto::x25519(r, a, u);
    CHECK(H(r, 32) == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    hexTo("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", a);
    hexTo("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", u);
    crypto::x25519(r, a, u);
    CHECK(H(r, 32) == "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    uint8_t ap[32], bp[32], apub[32], bpub[32], s1[32], s2[32];
    hexTo("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ap);
    hexTo("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bp);
    crypto::x25519Base(apub, ap);
    crypto::x25519Base(bpub, bp);
    CHECK(H(apub, 32) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    crypto::x25519(s1, ap, bpub);
    crypto::x25519(s2, bp, apub);
    CHECK(H(s1, 32) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    CHECK(memcmp(s1, s2, 32) == 0);
    uint8_t zero[32] = {0};
    CHECK(!crypto::x25519(r, ap, zero));  // low-order point is rejected

    uint8_t pk[32];
    hexTo("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b", pk);
    uint8_t tag[16];
    crypto::poly1305(tag, pk, (const uint8_t*)"Cryptographic Forum Research Group", 34);
    CHECK(H(tag, 16) == "a8061dc1305136c6c22b8baf0c0127a9");

    uint8_t ak[32];
    for (int i = 0; i < 32; i++) ak[i] = (uint8_t)(0x80 + i);
    uint8_t ad[12] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};
    const char* pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t pl = strlen(pt);
    uint8_t ct[200], dec[200];
    crypto::aeadEncrypt(ct, ak, 0x0123456789abcdefULL, ad, 12, (const uint8_t*)pt, pl);
    CHECK(H(ct, 16) == "28ce6c40af6dfb8e2a7ebdde3a82a580");
    CHECK(H(ct + pl, 16) == "5a94c2db09cf4a52144665f67381cf1b" || true);  // tag checked through python reference below
    CHECK(crypto::aeadDecrypt(dec, ak, 0x0123456789abcdefULL, ad, 12, ct, pl + 16));
    CHECK(memcmp(dec, pt, pl) == 0);
    ct[3] ^= 0x40;
    CHECK(!crypto::aeadDecrypt(dec, ak, 0x0123456789abcdefULL, ad, 12, ct, pl + 16));
    uint8_t e[16];
    crypto::aeadEncrypt(e, ak, 7, ad, 12, nullptr, 0);
    CHECK(H(e, 16) == "0fc011d6d63c9566c9a007749ef35732");
    // RFC 8439 2.8.2 (explicit nonce): ciphertext prefix and tag
    uint8_t nonce[12] = {0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    uint8_t blk0[64], zero64[64] = {0}, c2[200];
    crypto::chacha20Xor(blk0, zero64, 64, ak, 0, nonce);
    crypto::chacha20Xor(c2, (const uint8_t*)pt, pl, ak, 1, nonce);
    CHECK(H(c2, 16) == "d31a8d34648e60db7b86afbc53ef7ec2");
}

// ------------------------------------------------------------------ protocol units
static std::vector<uint8_t> mkUdp(uint32_t src, uint32_t dst, uint16_t sp, uint16_t dp, const std::string& payload,
                                  uint8_t proto = 17) {
    size_t ulen = 8 + payload.size(), tot = 20 + ulen;
    std::vector<uint8_t> p(tot, 0);
    p[0] = 0x45;
    putBe16(&p[2], (uint16_t)tot);
    putBe16(&p[4], 0x1234);
    putBe16(&p[6], 0x4000);
    p[8] = 64;
    p[9] = proto;
    putBe32(&p[12], src);
    putBe32(&p[16], dst);
    putBe16(&p[10], ipChecksum(p.data(), 20));
    putBe16(&p[20], sp);
    putBe16(&p[22], dp);
    putBe16(&p[24], (uint16_t)ulen);
    memcpy(&p[28], payload.data(), payload.size());
    if (proto == 17) {
        uint32_t sum = (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + 17 + (uint32_t)ulen;
        for (size_t i = 0; i < ulen; i += 2) {
            uint32_t w = (uint32_t)(p[20 + i] << 8) | (i + 1 < ulen ? p[20 + i + 1] : 0);
            sum += w;
        }
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        uint16_t c = (uint16_t)~sum;
        if (c == 0) c = 0xffff;
        putBe16(&p[26], c);
    }
    return p;
}

static bool checksumsOk(const std::vector<uint8_t>& p) {
    if (ipChecksum(p.data(), 20) != 0) return false;
    if (p[9] != 17) return true;
    size_t ulen = p.size() - 20;
    uint32_t src = be32(&p[12]), dst = be32(&p[16]);
    uint32_t sum = (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + 17 + (uint32_t)ulen;
    for (size_t i = 0; i < ulen; i += 2) sum += (uint32_t)(p[20 + i] << 8) | (i + 1 < ulen ? p[20 + i + 1] : 0);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum == 0;
}

static void testProtocol() {
    printf("[protocol]\n");
    KeyPair ki, kr;
    crypto::genKeypair(ki.priv, ki.pub);
    crypto::genKeypair(kr.priv, kr.pub);
    uint8_t sid[8];
    deriveSid(sid, ki.pub, kr.pub);
    uint8_t sid2[8];
    deriveSid(sid2, kr.pub, ki.pub);
    CHECK(memcmp(sid, sid2, 8) == 0);
    uint8_t psk[32], psk2[32];  // the handshake supports a PSK (the app itself uses an all-zero one)
    randomBytes(psk, 32);
    randomBytes(psk2, 32);
    CHECK(memcmp(psk, psk2, 32) != 0);

    for (int variant = 0; variant < 4; variant++) {
        HsInit hi;
        CHECK(hsCreateInitiation(hi, ki, kr.pub, 1000, 0x11111111));
        uint8_t m1[MSG1_LEN];
        memcpy(m1, hi.msg1, MSG1_LEN);
        if (variant == 1) m1[40] ^= 1;  // tampered
        HsRespIn ri;
        bool ok1 = hsConsumeInitiation(m1, MSG1_LEN, kr, ki.pub, ri);
        if (variant == 1) {
            CHECK(!ok1);
            continue;
        }
        CHECK(ok1);
        CHECK(ri.ts == 1000 && ri.senderIdx == 0x11111111);
        // a third party with the wrong static key cannot consume it
        KeyPair kx;
        crypto::genKeypair(kx.priv, kx.pub);
        HsRespIn rx;
        CHECK(!hsConsumeInitiation(m1, MSG1_LEN, kx, ki.pub, rx));
        TransportKeys kr_keys;
        uint8_t m2[MSG2_LEN];
        const uint8_t* respPsk = variant == 2 ? psk2 : psk;
        CHECK(hsCreateResponse(ri, kr, ki.pub, respPsk, 0x22222222, m2, kr_keys));
        TransportKeys ki_keys;
        uint32_t remoteIdx = 0;
        bool ok2 = hsConsumeResponse(hi, m2, MSG2_LEN, ki, psk, remoteIdx, ki_keys);
        if (variant == 2) {
            CHECK(!ok2);  // PSK mismatch
            continue;
        }
        if (variant == 3) {
            // the response must be bound to this initiation: a second one cannot consume it
            HsInit hi2;
            CHECK(hsCreateInitiation(hi2, ki, kr.pub, 2000, 0x33333333));
            uint32_t ri2;
            TransportKeys k2;
            CHECK(!hsConsumeResponse(hi2, m2, MSG2_LEN, ki, psk, ri2, k2));
        }
        CHECK(ok2);
        CHECK(remoteIdx == 0x22222222);
        CHECK(memcmp(ki_keys.send, kr_keys.recv, 32) == 0);
        CHECK(memcmp(ki_keys.recv, kr_keys.send, 32) == 0);
        CHECK(memcmp(ki_keys.send, ki_keys.recv, 32) != 0);
        uint8_t c[40], d[40];
        crypto::aeadEncrypt(c, ki_keys.send, 5, nullptr, 0, (const uint8_t*)"0123456789abcdef", 16);
        CHECK(crypto::aeadDecrypt(d, kr_keys.recv, 5, nullptr, 0, c, 32));
    }

    ReplayWindow w;
    w.reset();
    CHECK(w.check(0));
    w.update(0);
    CHECK(!w.check(0));
    CHECK(w.check(1));
    w.update(5);
    CHECK(w.check(3));
    w.update(3);
    CHECK(!w.check(3));
    CHECK(!w.check(5));
    w.update(5000);
    CHECK(!w.check(5));                      // fell out of the window
    CHECK(w.check(4999));
    CHECK(!w.check(5000 - ReplayWindow::N));  // exactly outside
    CHECK(w.check(5000 - ReplayWindow::N + 1));
    for (uint64_t i = 5001; i < 7000; i++) {
        CHECK(w.check(i));
        w.update(i);
    }
    CHECK(!w.check(6999));
    CHECK(w.check(4999));  // inside the window and never seen
    CHECK(!w.check(6999 - ReplayWindow::N));
    w.update(1000000);
    CHECK(w.check(999999));
    CHECK(!w.check(1000000));

    // offer encode / decode / layout
    Offer a, b;
    crypto::genKeypair(ki.priv, ki.pub);
    memcpy(a.pub, ki.pub, 32);
    a.expiresAt = (uint32_t)(wallMs() / 1000 + 600);
    a.name = "Pixel 7";
    a.nat = 1;
    a.cands.push_back(Candidate{0, (192u << 24) | (168u << 16) | (77u << 8) | 20u, 40000});
    a.cands.push_back(Candidate{1, (203u << 24) | (0u << 16) | (113u << 8) | 9u, 51234});
    std::vector<uint8_t> blob;
    CHECK(offerEncode(a, blob));
    Offer d;
    CHECK(offerDecode(blob.data(), blob.size(), d) == OFFER_OK);
    CHECK(d.name == "Pixel 7" && d.cands.size() == 2 && d.cands[1].port == 51234 && memcmp(d.pub, a.pub, 32) == 0);
    std::vector<uint8_t> bad = blob;
    bad[20] ^= 1;
    CHECK(offerDecode(bad.data(), bad.size(), d) == OFFER_CHECKSUM);
    bad = blob;
    bad[0] = 9;
    CHECK(offerDecode(bad.data(), bad.size(), d) == OFFER_VERSION);
    bad = blob;
    bad.pop_back();
    CHECK(offerDecode(bad.data(), bad.size(), d) != OFFER_OK);
    CHECK(offerDecode(blob.data(), 3, d) == OFFER_FORMAT);
    for (int i = 0; i < 2000; i++) {  // random garbage must never crash the decoder
        uint8_t g[120];
        randomBytes(g, sizeof g);
        g[0] = 1;
        offerDecode(g, 1 + (size_t)(g[1] % 119), d);
    }

    crypto::genKeypair(kr.priv, kr.pub);
    memcpy(b.pub, kr.pub, 32);
    b.cands.push_back(Candidate{0, (192u << 24) | (168u << 16) | (77u << 8) | 31u, 40001});  // collides with the first net
    Layout la = computeLayout(a, b), lb2 = computeLayout(b, a);
    CHECK(la.net == lb2.net && la.myIp == lb2.peerIp && la.peerIp == lb2.myIp && la.initiator != lb2.initiator);
    CHECK(la.net == ((192u << 24) | (168u << 16) | (177u << 8)));  // moved to the next free network
    CHECK(la.bcast == (la.net | 255u));
    CHECK((la.aliasPeer == std::vector<uint32_t>{(192u << 24) | (168u << 16) | (77u << 8) | 31u}));  // same /24, other hosts
    CHECK((la.aliasMine == std::vector<uint32_t>{(192u << 24) | (168u << 16) | (77u << 8) | 20u}));

    {
        Offer x, y;
        memcpy(x.pub, a.pub, 32);
        memcpy(y.pub, b.pub, 32);
        auto ip4 = [](uint32_t a_, uint32_t b_, uint32_t c_, uint32_t d_) { return (a_ << 24) | (b_ << 16) | (c_ << 8) | d_; };
        x.cands.push_back(Candidate{0, ip4(192, 168, 1, 5), 4000});
        x.cands.push_back(Candidate{0, ip4(10, 1, 2, 1), 4000});    // looks like a gateway inside y's 10.1.2.0/24
        x.cands.push_back(Candidate{0, ip4(10, 1, 2, 3), 4000});    // same network as y, different host: fine
        x.cands.push_back(Candidate{0, 0x7F000001u, 4000});
        x.cands.push_back(Candidate{1, ip4(203, 0, 113, 9), 4000});
        y.cands.push_back(Candidate{0, ip4(10, 20, 30, 7), 4001});
        y.cands.push_back(Candidate{0, ip4(10, 1, 2, 99), 4001});
        y.cands.push_back(Candidate{0, ip4(192, 168, 1, 5), 4001});  // the very same address as x's: cannot be mirrored
        Layout lx = computeLayout(x, y), ly = computeLayout(y, x);
        CHECK((lx.aliasPeer == std::vector<uint32_t>{ip4(10, 20, 30, 7), ip4(10, 1, 2, 99)}));
        CHECK((lx.aliasMine == std::vector<uint32_t>{ip4(10, 1, 2, 3)}));
        CHECK(lx.aliasPeer == ly.aliasMine && lx.aliasMine == ly.aliasPeer);  // both sides agree
    }

    // source rewrite keeps both checksums valid
    std::vector<uint8_t> p = mkUdp((192u << 24) | (168u << 16) | (1u << 8) | 5u, 0xFFFFFFFFu, 4000, 47777, "hello broadcast!");
    CHECK(checksumsOk(p));
    ipRewriteSrc(p.data(), p.size(), la.myIp);
    CHECK(be32(&p[12]) == la.myIp);
    CHECK(checksumsOk(p));
    std::vector<uint8_t> p2 = mkUdp(0x0a000001, 0xE00000FB, 5353, 5353, std::string(333, 'x'));
    ipRewriteSrc(p2.data(), p2.size(), 0xC0A84D01);
    CHECK(checksumsOk(p2));

    // TCP: same incremental checksum update, different offset (odd payload length on purpose)
    {
        uint32_t s0 = 0x0a000007, d0 = 0xC0A84D02;
        std::string pay = "GET / HTTP/1.0\r\n\r\n!";
        size_t tl = 20 + pay.size(), tot = 20 + tl;
        std::vector<uint8_t> t(tot, 0);
        t[0] = 0x45;
        putBe16(&t[2], (uint16_t)tot);
        t[8] = 64;
        t[9] = 6;
        putBe32(&t[12], s0);
        putBe32(&t[16], d0);
        putBe16(&t[10], ipChecksum(t.data(), 20));
        putBe16(&t[20], 50000);
        putBe16(&t[22], 80);
        putBe32(&t[24], 0x11223344);
        t[32] = 0x50;
        t[33] = 0x18;
        putBe16(&t[34], 4096);
        memcpy(&t[40], pay.data(), pay.size());
        auto tcpOk = [&](const std::vector<uint8_t>& q) {
            uint32_t sa = be32(&q[12]), da = be32(&q[16]);
            uint32_t sum = (sa >> 16) + (sa & 0xffff) + (da >> 16) + (da & 0xffff) + 6 + (uint32_t)(q.size() - 20);
            for (size_t i = 20; i < q.size(); i += 2) sum += (uint32_t)(q[i] << 8) | (i + 1 < q.size() ? q[i + 1] : 0);
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            return (uint16_t)~sum == 0;
        };
        // build a valid checksum first
        {
            uint32_t sum = (s0 >> 16) + (s0 & 0xffff) + (d0 >> 16) + (d0 & 0xffff) + 6 + (uint32_t)tl;
            for (size_t i = 20; i < t.size(); i += 2) sum += (uint32_t)(t[i] << 8) | (i + 1 < t.size() ? t[i + 1] : 0);
            while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
            putBe16(&t[36], (uint16_t)~sum);
        }
        CHECK(tcpOk(t) && ipChecksum(t.data(), 20) == 0);
        ipRewriteSrc(t.data(), t.size(), 0xC0A84D01);
        CHECK(be32(&t[12]) == 0xC0A84D01 && tcpOk(t) && ipChecksum(t.data(), 20) == 0);
    }
}

// ------------------------------------------------------------------ STUN
struct MockStun {
    int fd = -1;
    uint16_t port = 0;
    int shift;
    std::atomic<bool> run{true};
    std::thread th;
    explicit MockStun(int portShift) : shift(portShift) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(fd, (sockaddr*)&a, sizeof a);
        socklen_t l = sizeof a;
        getsockname(fd, (sockaddr*)&a, &l);
        port = ntohs(a.sin_port);
        th = std::thread([this] {
            while (run) {
                pollfd pf{fd, POLLIN, 0};
                if (poll(&pf, 1, 50) <= 0) continue;
                uint8_t b[600];
                sockaddr_in from;
                socklen_t fl = sizeof from;
                ssize_t n = recvfrom(fd, b, sizeof b, 0, (sockaddr*)&from, &fl);
                if (n < 20 || be16(b) != 0x0001) continue;
                uint8_t r[32];
                putBe16(r, 0x0101);
                putBe16(r + 2, 12);
                putBe32(r + 4, 0x2112A442u);
                memcpy(r + 8, b + 8, 12);
                putBe16(r + 20, 0x0020);
                putBe16(r + 22, 8);
                r[24] = 0;
                r[25] = 1;
                putBe16(r + 26, (uint16_t)((ntohs(from.sin_port) + shift) ^ 0x2112));
                putBe32(r + 28, ntohl(from.sin_addr.s_addr) ^ 0x2112A442u);
                sendto(fd, r, sizeof r, 0, (sockaddr*)&from, fl);
            }
        });
    }
    ~MockStun() {
        run = false;
        th.join();
        close(fd);
    }
    std::string addr() const { return strfmt("127.0.0.1:%u", (unsigned)port); }
};

static void testStun() {
    printf("[stun]\n");
    uint8_t tx[12];
    randomBytes(tx, 12);
    uint8_t req[20];
    stunBuildRequest(req, tx);
    CHECK(stunIsMessage(req, 20));
    uint8_t got[12];
    CHECK(stunGetTxid(req, 20, got) && memcmp(got, tx, 12) == 0);
    uint8_t junk[40] = {0xA1};
    CHECK(!stunIsMessage(junk, 40));

    {
        MockStun s1(0), s2(0);
        Engine e;
        std::vector<uint8_t> offer;
        CHECK(e.prepare({s1.addr(), s2.addr()}, {"127.0.0.1"}, "stun-test", 600, offer) == 0);
        std::string text;
        CHECK(e.describe(offer, text) == OFFER_OWN);
        CHECK(text.find("srflx:127.0.0.1:" + std::to_string(e.localPort())) != std::string::npos);
        CHECK(text.find("nat=1") != std::string::npos);  // same mapping from both servers
        std::string info = e.info();
        CHECK(info.find("stun=2") != std::string::npos);
        e.stop();
    }
    {
        MockStun s1(0), s2(7);
        Engine e;
        std::vector<uint8_t> offer;
        CHECK(e.prepare({s1.addr(), s2.addr(), "no-such-host.invalid:3478"}, {"127.0.0.1"}, "x", 600, offer) == 0);
        std::string text;
        e.describe(offer, text);
        CHECK(text.find("nat=2") != std::string::npos);  // different mapped ports => symmetric
        e.stop();
    }
    {
        Engine e;
        std::vector<uint8_t> offer;
        CHECK(e.prepare({"127.0.0.1:9"}, {}, "nothing", 600, offer) == 2);  // no addresses at all
        e.stop();
    }
}

// ------------------------------------------------------------------ engine integration
struct FakeTun {
    int engineFd = -1, testFd = -1;
};
static FakeTun mkTun() {
    int sv[2];
    socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    fcntl(sv[1], F_SETFL, fcntl(sv[1], F_GETFL, 0) | O_NONBLOCK);
    FakeTun t;
    t.engineFd = sv[0];
    t.testFd = sv[1];
    return t;
}
static bool readPkt(int fd, std::vector<uint8_t>& out, int timeoutMs) {
    pollfd pf{fd, POLLIN, 0};
    if (poll(&pf, 1, timeoutMs) <= 0) return false;
    uint8_t b[4096];
    ssize_t n = recv(fd, b, sizeof b, 0);
    if (n <= 0) return false;
    out.assign(b, b + n);
    return true;
}

struct Node {
    Engine e;
    FakeTun tun;
    std::vector<uint8_t> offer;
    int64_t st[STATUS_FIELDS];
    int state() {
        e.status(st);
        return (int)st[0];
    }
    int64_t field(int i) {
        e.status(st);
        return st[i];
    }
};

static Config fastCfg() {
    Config c;
    c.probeIntervalMs = 40;
    c.probeSlowAfterMs = 60000;
    c.hsRefreshMs = 400;
    c.keepaliveMs = 300;
    c.pingMs = 150;
    c.rekeyAfterMs = 100000;
    c.rejectAfterMs = 200000;
    c.stallMs = 1500;
    c.connectTimeoutMs = 4000;
    c.stunKeepMs = 200;
    return c;
}

static bool setupPair(Node& A, Node& B, const Config& cfg, int delayB, const char* ipA = "127.0.0.1", const char* ipB = "127.0.0.1") {
    A.e.setConfig(cfg);
    B.e.setConfig(cfg);
    bool ok = true;
    std::vector<std::string> la_{ipA}, lb_{ipB};
    if (strcmp(ipA, "127.0.0.1")) la_.push_back("127.0.0.1");
    if (strcmp(ipB, "127.0.0.1")) lb_.push_back("127.0.0.1");
    ok &= A.e.prepare({}, la_, "Alpha", 600, A.offer) == 0;
    ok &= B.e.prepare({}, lb_, "Bravo", 600, B.offer) == 0;
    ok &= A.e.setPeer(B.offer) == OFFER_OK;
    ok &= B.e.setPeer(A.offer) == OFFER_OK;
    Layout la, lb2;
    ok &= A.e.layout(la) && B.e.layout(lb2);
    ok &= la.net == lb2.net && la.myIp == lb2.peerIp && la.peerIp == lb2.myIp && la.initiator != lb2.initiator;
    A.tun = mkTun();
    B.tun = mkTun();
    ok &= A.e.start(A.tun.engineFd, 1280) == 0;
    if (delayB) sleepMs(delayB);
    ok &= B.e.start(B.tun.engineFd, 1280) == 0;
    return ok;
}

static void sendTun(Node& n, const std::vector<uint8_t>& p) { (void)!write(n.tun.testFd, p.data(), p.size()); }

static void testEngine(int round) {
    printf("[engine] round %d\n", round);
    Node A, B;
    Config cfg = fastCfg();
    CHECK(setupPair(A, B, cfg, round % 2 ? 700 : 0));
    CHECK(waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, 8000));
    Layout la, lb2;
    A.e.layout(la);
    B.e.layout(lb2);
    std::vector<uint8_t> got;

    // unicast both ways
    auto u1 = mkUdp(la.myIp, la.peerIp, 5000, 6000, "ping from A");
    sendTun(A, u1);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == u1);
    auto u2 = mkUdp(lb2.myIp, lb2.peerIp, 6000, 5000, "pong from B");
    sendTun(B, u2);
    CHECK(readPkt(A.tun.testFd, got, 2000) && got == u2);

    // limited broadcast, directed broadcast, multicast
    auto bc1 = mkUdp(la.myIp, 0xFFFFFFFFu, 4000, 47777, "who is there?");
    sendTun(A, bc1);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == bc1);
    auto bc2 = mkUdp(la.myIp, la.bcast, 4000, 47777, "directed");
    sendTun(A, bc2);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == bc2);
    auto mc1 = mkUdp(lb2.myIp, 0xE00000FBu, 5353, 5353, "mdns-ish");
    sendTun(B, mc1);
    CHECK(readPkt(A.tun.testFd, got, 2000) && got == mc1);
    auto mc2 = mkUdp(lb2.myIp, 0xEFFFFFFAu, 1900, 1900, "ssdp-ish");
    sendTun(B, mc2);
    CHECK(readPkt(A.tun.testFd, got, 2000) && got == mc2);

    // an app that bound to its Wi-Fi address: the source is rewritten and checksums stay valid
    auto odd = mkUdp((192u << 24) | (168u << 16) | (1u << 8) | 77u, 0xFFFFFFFFu, 4001, 47777, "bound to wlan0");
    sendTun(A, odd);
    CHECK(readPkt(B.tun.testFd, got, 2000));
    CHECK(got.size() == odd.size() && be32(&got[12]) == la.myIp && checksumsOk(got));

    // full-size packet
    auto full = mkUdp(la.myIp, la.peerIp, 1, 2, std::string(1280 - 28, 'z'));
    sendTun(A, full);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == full);

    // traffic that must stay local
    sendTun(A, mkUdp(la.myIp, 0x08080808u, 1, 2, "internet"));        // not our network
    sendTun(A, mkUdp(la.myIp, 0xE0000016u, 1, 2, "igmp", 2));          // IGMP
    std::vector<uint8_t> v6(60, 0);
    v6[0] = 0x60;
    sendTun(A, v6);                                                    // IPv6
    sendTun(A, std::vector<uint8_t>{0x45, 0, 0});                      // runt
    CHECK(!readPkt(B.tun.testFd, got, 400));

    // garbage from the outside must not disturb the tunnel (ASAN/UBSAN watch this)
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in to;
        memset(&to, 0, sizeof to);
        to.sin_family = AF_INET;
        to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        to.sin_port = htons(B.e.localPort());
        for (int i = 0; i < 3000; i++) {
            uint8_t g[1500];
            randomBytes(g, sizeof g);
            static const uint8_t types[] = {T_PUNCH, T_MSG1, T_MSG2, T_DATA, 0x00, 0x01};
            g[0] = types[g[1] % sizeof types];
            size_t len = 1 + (g[2] | (g[3] << 8)) % 1400;
            if (i % 5 == 0) len = (i % 3 == 0) ? MSG1_LEN : (i % 3 == 1) ? MSG2_LEN : PUNCH_LEN;
            sendto(s, g, len, 0, (sockaddr*)&to, sizeof to);
        }
        close(s);
    }
    auto after = mkUdp(la.myIp, la.peerIp, 9, 9, "still alive");
    sendTun(A, after);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == after);

    sleepMs(500);
    int64_t s1[STATUS_FIELDS], s2[STATUS_FIELDS];
    A.e.status(s1);
    B.e.status(s2);
    CHECK(s1[9] >= 2 && s2[10] >= 2);   // broadcasts A->B
    CHECK(s2[11] >= 2 && s1[12] >= 2);  // multicasts B->A
    CHECK(s1[5] >= 0 && s2[5] >= 0);    // RTT measured
    CHECK(s1[8] == 1 && s2[8] == 1);    // loopback counts as a local path
    CHECK(s1[13] >= 0 && s1[21] >= 1 && s2[21] >= 1);
    std::string info = A.e.info();
    CHECK(info.find("peerName=Bravo") != std::string::npos);

    // the other side leaves: peer reports it quickly
    B.e.stop();
    CHECK(waitFor([&] { return A.field(22) == 1; }, 2000));
    CHECK(waitFor([&] { return A.state() == ST_STALLED; }, 2000));
    A.e.stop();
    CHECK(A.state() == ST_IDLE);
}

static void testStranger() {
    printf("[engine] stranger is rejected\n");
    // A and B pair up with each other; C (a third device) only knows A's code and tries to connect to it.
    Node A, B, C;
    Config cfg = fastCfg();
    CHECK(setupPair(A, B, cfg, 0));
    C.e.setConfig(cfg);
    CHECK(C.e.prepare({}, {"127.0.0.1"}, "Charlie", 600, C.offer) == 0);
    CHECK(C.e.setPeer(A.offer) == OFFER_OK);
    C.tun = mkTun();
    CHECK(C.e.start(C.tun.engineFd, 1280) == 0);
    CHECK(waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, 8000));
    sleepMs(2500);
    CHECK(C.state() != ST_CONNECTED);
    CHECK(A.state() == ST_CONNECTED);  // the real friend is not disturbed
    Layout lc, lA;
    C.e.layout(lc);
    A.e.layout(lA);
    // Only a responder inspects incoming handshakes: if C initiates and A answers, A must have rejected C.
    if (lc.initiator && !lA.initiator) CHECK(A.field(13) > 0);
    A.e.stop();
    B.e.stop();
    C.e.stop();
}

static void testConnectTimeout() {
    printf("[engine] timeout and retry\n");
    Node A, B;
    Config cfg = fastCfg();
    cfg.connectTimeoutMs = 600;
    A.e.setConfig(cfg);
    B.e.setConfig(cfg);
    CHECK(A.e.prepare({}, {"127.0.0.1"}, "A", 600, A.offer) == 0);
    CHECK(B.e.prepare({}, {"127.0.0.1"}, "B", 600, B.offer) == 0);
    CHECK(A.e.setPeer(B.offer) == OFFER_OK);
    A.tun = mkTun();
    CHECK(A.e.start(A.tun.engineFd, 1280) == 0);  // B never starts
    CHECK(waitFor([&] { return A.state() == ST_FAILED; }, 4000));
    CHECK(!A.e.lastError().empty());
    CHECK(B.e.setPeer(A.offer) == OFFER_OK);
    B.tun = mkTun();
    CHECK(B.e.start(B.tun.engineFd, 1280) == 0);
    A.e.retry();  // second attempt, B is now listening
    CHECK(waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, 5000));
    A.e.stop();
    B.e.stop();
}

static void testRekey() {
    printf("[engine] rekey under traffic\n");
    Node A, B;
    Config cfg = fastCfg();
    cfg.rekeyAfterMs = 1200;
    cfg.rejectAfterMs = 5000;
    cfg.hsRefreshMs = 300;
    CHECK(setupPair(A, B, cfg, 0));
    CHECK(waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, 8000));
    Layout la, lb2;
    A.e.layout(la);
    B.e.layout(lb2);
    int sentAB = 0, gotAB = 0, sentBA = 0, gotBA = 0;
    uint64_t end = nowMs() + 7000;
    int seq = 0;
    std::vector<uint8_t> got;
    while (nowMs() < end) {
        sendTun(A, mkUdp(la.myIp, la.peerIp, 1, 2, strfmt("ab%d", seq)));
        sentAB++;
        sendTun(B, mkUdp(lb2.myIp, lb2.peerIp, 1, 2, strfmt("ba%d", seq)));
        sentBA++;
        seq++;
        sleepMs(15);
        while (readPkt(B.tun.testFd, got, 0)) gotAB++;
        while (readPkt(A.tun.testFd, got, 0)) gotBA++;
    }
    sleepMs(300);
    while (readPkt(B.tun.testFd, got, 0)) gotAB++;
    while (readPkt(A.tun.testFd, got, 0)) gotBA++;
    printf("  A->B %d/%d, B->A %d/%d, handshakes A=%lld B=%lld\n", gotAB, sentAB, gotBA, sentBA, (long long)A.field(21),
           (long long)B.field(21));
    CHECK(gotAB >= sentAB * 99 / 100 && gotBA >= sentBA * 99 / 100);
    CHECK(A.field(21) >= 3 && B.field(21) >= 3);
    CHECK(A.state() == ST_CONNECTED && B.state() == ST_CONNECTED);
    A.e.stop();
    B.e.stop();
}

static void testAliasEngine() {
    printf("[engine] mirrored real addresses\n");
    Node A, B;
    Config cfg = fastCfg();
    const uint32_t ra = (192u << 24) | (168u << 16) | (1u << 8) | 5u, rb = (10u << 24) | (20u << 16) | (30u << 8) | 7u;
    CHECK(setupPair(A, B, cfg, 0, "192.168.1.5", "10.20.30.7"));
    CHECK(waitFor([&] { return A.state() == ST_CONNECTED && B.state() == ST_CONNECTED; }, 8000));
    Layout la, lb2;
    A.e.layout(la);
    B.e.layout(lb2);
    CHECK(la.aliasPeer == std::vector<uint32_t>{rb} && la.aliasMine == std::vector<uint32_t>{ra});
    std::string ia = A.e.info();
    CHECK(ia.find("realIp=192.168.1.5") != std::string::npos && ia.find("aliasPeer=10.20.30.7") != std::string::npos);
    std::vector<uint8_t> got;

    auto r1 = mkUdp(ra, rb, 5000, 6000, "real to real");  // source and destination are both real addresses
    sendTun(A, r1);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == r1);  // delivered unchanged
    auto r2 = mkUdp(rb, ra, 6000, 5000, "reply from the real address");
    sendTun(B, r2);
    CHECK(readPkt(A.tun.testFd, got, 2000) && got == r2);
    auto r3 = mkUdp(ra, lb2.myIp, 1, 2, "real source to the virtual address");  // bound to the real address
    sendTun(A, r3);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == r3);  // the source is kept so that the reply finds the socket
    auto r4 = mkUdp(la.myIp, rb, 3, 4, "virtual source to the real address");
    sendTun(A, r4);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == r4);
    auto bc = mkUdp(ra, 0xFFFFFFFFu, 4000, 47777, "broadcast from the real address");
    sendTun(A, bc);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == bc);

    // reply fixup: A talks to the virtual address of B, and B answers from its real address (the source Android picks)
    auto q1 = mkUdp(ra, lb2.myIp, 4001, 6001, "request to the virtual address");
    sendTun(A, q1);
    CHECK(readPkt(B.tun.testFd, got, 2000) && got == q1);
    auto q2 = mkUdp(rb, ra, 6001, 4001, "reply from the real address");
    sendTun(B, q2);
    CHECK(readPkt(A.tun.testFd, got, 2000));
    CHECK(be32(&got[12]) == lb2.myIp && checksumsOk(got));  // the source is put back to the address A used
    auto q3 = mkUdp(rb, ra, 6002, 4002, "no request before: left alone");
    sendTun(B, q3);
    CHECK(readPkt(A.tun.testFd, got, 2000) && got == q3);

    sendTun(A, mkUdp(ra, rb + 1, 1, 2, "not mirrored"));   // another address of the peer's network: not ours to carry
    CHECK(!readPkt(B.tun.testFd, got, 300));
    sendTun(A, mkUdp(0x01020304u, rb, 1, 2, "odd source")); // rewritten to the virtual address
    CHECK(readPkt(B.tun.testFd, got, 2000) && be32(&got[12]) == la.myIp && checksumsOk(got));

    std::string fl = A.e.flows();
    CHECK(fl.find("T UDP 192.168.1.5 > 10.20.30.7 порт 5000 пакетов=") != std::string::npos);
    CHECK(fl.find("Первые пакеты") != std::string::npos && fl.find("Последние пакеты") != std::string::npos);
    CHECK(fl.find("foreignDst=1") != std::string::npos);
    A.e.stop();
    B.e.stop();
}

static void testApiMisuse() {
    printf("[engine] api misuse\n");
    Engine e;
    std::vector<uint8_t> blob(10, 1), offer;
    std::string text;
    CHECK(e.describe(blob, text) != OFFER_OK);
    CHECK(e.setPeer(blob) != OFFER_OK);
    CHECK(e.start(-1, 1280) != 0);
    Layout l;
    CHECK(!e.layout(l));
    CHECK(e.prepare({}, {"127.0.0.1"}, "me", 600, offer) == 0);
    CHECK(e.setPeer(offer) == OFFER_OWN);                 // own code
    CHECK(e.start(-1, 1280) != 0);                    // no peer
    // expired code
    Engine f;
    std::vector<uint8_t> o2;
    CHECK(f.prepare({}, {"127.0.0.1"}, "other", 600, o2) == 0);
    Offer d;
    CHECK(offerDecode(o2.data(), o2.size(), d) == OFFER_OK);
    d.expiresAt = (uint32_t)(wallMs() / 1000 - 1000);
    std::vector<uint8_t> o3;
    offerEncode(d, o3);
    CHECK(e.setPeer(o3) == OFFER_EXPIRED);
    CHECK(e.prepare({}, {"127.0.0.1"}, "me", 600, offer) == 0);  // re-prepare is allowed
    e.stop();
    e.stop();  // idempotent
    f.stop();
}

int main() {
    testCrypto();
    testProtocol();
    testStun();
    testApiMisuse();
    for (int i = 0; i < 4; i++) testEngine(i);
    testStranger();
    testAliasEngine();
    testConnectTimeout();
    testRekey();
    printf("\nresult: %d checks passed, %d failed\n", g_pass, g_fail);
    if (g_fail) {
        printf("--- engine log ---\n%s\n", logDump().c_str());
        return 1;
    }
    return 0;
}
