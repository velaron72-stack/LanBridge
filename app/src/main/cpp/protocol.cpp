#include "protocol.h"

#include <cstring>

#include "crypto.h"
#include "util.h"

namespace lb {

using namespace crypto;

static const char CONSTRUCTION[] = "Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
static const char IDENTIFIER[] = "LanBridge v1 p2p lan tunnel";

void HsInit::wipe() {
    crypto::wipe(this, sizeof *this);
}

void Session::clear() {
    crypto::wipe(sendKey, sizeof sendKey);
    crypto::wipe(recvKey, sizeof recvKey);
    valid = false;
    confirmed = false;
    sendCtr = 0;
    localIdx = remoteIdx = 0;
    createdMs = lastRxMs = 0;
    replay.reset();
}

static void initialState(uint8_t C[32], uint8_t H[32], const uint8_t Si[32], const uint8_t Sr[32]) {
    blake2s(C, 32, nullptr, 0, (const uint8_t*)CONSTRUCTION, strlen(CONSTRUCTION));
    hash2(H, C, 32, IDENTIFIER, strlen(IDENTIFIER));
    hash2(H, H, 32, Si, 32);
    hash2(H, H, 32, Sr, 32);
}

static void macKey(uint8_t key[32], const uint8_t pub[32]) {
    hash2(key, "mac1----", 8, pub, 32);
}

static void mac16(uint8_t out[16], const uint8_t key[32], const uint8_t* data, size_t n) {
    blake2s(out, 16, key, 32, data, n);
}

bool hsCreateInitiation(HsInit& st, const KeyPair& me, const uint8_t Sr[32], uint64_t ts, uint32_t localIdx) {
    uint8_t C[32], H[32], e[32], E[32], dh[32], k[32];
    initialState(C, H, me.pub, Sr);
    genKeypair(e, E);
    kdf1(C, C, E, 32);
    hash2(H, H, 32, E, 32);
    if (!x25519(dh, e, Sr)) return false;  // es
    kdf2(C, k, C, dh, 32);
    if (!x25519(dh, me.priv, Sr)) return false;  // ss
    kdf2(C, k, C, dh, 32);
    uint8_t tsb[12];
    memset(tsb, 0, sizeof tsb);
    putBe64(tsb, ts);
    uint8_t enc[12 + AEAD_TAG];
    aeadEncrypt(enc, k, 0, H, 32, tsb, 12);
    hash2(H, H, 32, enc, sizeof enc);

    uint8_t* m = st.msg1;
    m[0] = T_MSG1;
    putLe32(m + 1, localIdx);
    memcpy(m + 5, E, 32);
    memcpy(m + 37, enc, 28);
    uint8_t mk[32];
    macKey(mk, Sr);
    mac16(m + 65, mk, m, 65);

    st.active = true;
    st.localIdx = localIdx;
    memcpy(st.ePriv, e, 32);
    memcpy(st.C, C, 32);
    memcpy(st.H, H, 32);
    st.ts = ts;
    wipe(e, 32);
    wipe(k, 32);
    wipe(dh, 32);
    wipe(C, 32);
    return true;
}

bool hsConsumeInitiation(const uint8_t* msg, size_t n, const KeyPair& me, const uint8_t Si[32], HsRespIn& out) {
    if (n != MSG1_LEN || msg[0] != T_MSG1) return false;
    uint8_t mk[32], mac[16];
    macKey(mk, me.pub);
    mac16(mac, mk, msg, 65);
    if (!ctEqual(mac, msg + 65, 16)) return false;

    uint8_t C[32], H[32], dh[32], k[32];
    const uint8_t* E = msg + 5;
    initialState(C, H, Si, me.pub);
    kdf1(C, C, E, 32);
    hash2(H, H, 32, E, 32);
    if (!x25519(dh, me.priv, E)) return false;  // es
    kdf2(C, k, C, dh, 32);
    if (!x25519(dh, me.priv, Si)) return false;  // ss
    kdf2(C, k, C, dh, 32);
    uint8_t tsb[12];
    if (!aeadDecrypt(tsb, k, 0, H, 32, msg + 37, 28)) return false;
    hash2(H, H, 32, msg + 37, 28);

    memcpy(out.C, C, 32);
    memcpy(out.H, H, 32);
    memcpy(out.Ei, E, 32);
    out.senderIdx = le32(msg + 1);
    out.ts = be64(tsb);
    wipe(k, 32);
    wipe(dh, 32);
    wipe(C, 32);
    return true;
}

bool hsCreateResponse(const HsRespIn& in, const KeyPair& me, const uint8_t Si[32], const uint8_t psk[32],
                      uint32_t localIdx, uint8_t* msg2, TransportKeys& keys) {
    (void)me;
    uint8_t C[32], H[32], e[32], E[32], dh[32], tau[32], k[32];
    memcpy(C, in.C, 32);
    memcpy(H, in.H, 32);
    genKeypair(e, E);
    kdf1(C, C, E, 32);
    hash2(H, H, 32, E, 32);
    if (!x25519(dh, e, in.Ei)) return false;  // ee
    kdf1(C, C, dh, 32);
    if (!x25519(dh, e, Si)) return false;  // se
    kdf1(C, C, dh, 32);
    kdf3(C, tau, k, C, psk, 32);
    hash2(H, H, 32, tau, 32);
    uint8_t enc[AEAD_TAG];
    aeadEncrypt(enc, k, 0, H, 32, nullptr, 0);
    hash2(H, H, 32, enc, sizeof enc);

    msg2[0] = T_MSG2;
    putLe32(msg2 + 1, localIdx);
    putLe32(msg2 + 5, in.senderIdx);
    memcpy(msg2 + 9, E, 32);
    memcpy(msg2 + 41, enc, 16);
    uint8_t mk[32];
    macKey(mk, Si);
    mac16(msg2 + 57, mk, msg2, 57);

    uint8_t tir[32], tri[32];
    kdf2(tir, tri, C, nullptr, 0);
    memcpy(keys.send, tri, 32);  // responder sends with the responder->initiator key
    memcpy(keys.recv, tir, 32);
    wipe(e, 32);
    wipe(dh, 32);
    wipe(tau, 32);
    wipe(k, 32);
    wipe(C, 32);
    wipe(tir, 32);
    wipe(tri, 32);
    return true;
}

bool hsConsumeResponse(HsInit& st, const uint8_t* msg, size_t n, const KeyPair& me, const uint8_t psk[32],
                       uint32_t& remoteIdx, TransportKeys& keys) {
    if (!st.active || n != MSG2_LEN || msg[0] != T_MSG2) return false;
    if (le32(msg + 5) != st.localIdx) return false;
    uint8_t mk[32], mac[16];
    macKey(mk, me.pub);
    mac16(mac, mk, msg, 57);
    if (!ctEqual(mac, msg + 57, 16)) return false;

    uint8_t C[32], H[32], dh[32], tau[32], k[32];
    const uint8_t* Er = msg + 9;
    memcpy(C, st.C, 32);
    memcpy(H, st.H, 32);
    kdf1(C, C, Er, 32);
    hash2(H, H, 32, Er, 32);
    if (!x25519(dh, st.ePriv, Er)) return false;  // ee
    kdf1(C, C, dh, 32);
    if (!x25519(dh, me.priv, Er)) return false;  // se
    kdf1(C, C, dh, 32);
    kdf3(C, tau, k, C, psk, 32);
    hash2(H, H, 32, tau, 32);
    if (!aeadDecrypt(nullptr, k, 0, H, 32, msg + 41, 16)) return false;

    remoteIdx = le32(msg + 1);
    uint8_t tir[32], tri[32];
    kdf2(tir, tri, C, nullptr, 0);
    memcpy(keys.send, tir, 32);
    memcpy(keys.recv, tri, 32);
    wipe(dh, 32);
    wipe(tau, 32);
    wipe(k, 32);
    wipe(C, 32);
    wipe(tir, 32);
    wipe(tri, 32);
    st.wipe();
    return true;
}

void deriveSid(uint8_t sid[8], const uint8_t pubA[32], const uint8_t pubB[32]) {
    const uint8_t* lo = pubA;
    const uint8_t* hi = pubB;
    if (memcmp(pubA, pubB, 32) > 0) {
        lo = pubB;
        hi = pubA;
    }
    Blake2s h(32);
    h.update("LanBridge sid", 13);
    h.update(lo, 32);
    h.update(hi, 32);
    uint8_t full[32];
    h.final(full);
    memcpy(sid, full, 8);
}

void derivePsk(uint8_t psk[32], const char* password, size_t len, const uint8_t sid[8]) {
    if (len == 0) {
        memset(psk, 0, 32);
        return;
    }
    uint8_t h[32];
    {
        Blake2s b(32);
        b.update("LanBridge psk v1", 16);
        b.update(sid, 8);
        b.update(password, len);
        b.final(h);
    }
    for (int i = 0; i < 50000; i++) {
        Blake2s c(32);
        c.update(h, 32);
        c.update(password, len);
        c.final(h);
    }
    memcpy(psk, h, 32);
    crypto::wipe(h, sizeof h);
}

bool ReplayWindow::check(uint64_t c) const {
    if (!any) return true;
    if (c > top) return true;
    if (top - c >= N) return false;
    return ((bm[(c >> 6) & (W - 1)] >> (c & 63)) & 1ull) == 0;
}

void ReplayWindow::update(uint64_t c) {
    if (!any) {
        memset(bm, 0, sizeof bm);
        any = true;
        top = c;
    } else if (c > top) {
        uint64_t diff = c - top;
        if (diff >= N) {
            memset(bm, 0, sizeof bm);
        } else {
            for (uint64_t i = top + 1; i <= c; i++) bm[(i >> 6) & (W - 1)] &= ~(1ull << (i & 63));
        }
        top = c;
    }
    bm[(c >> 6) & (W - 1)] |= (1ull << (c & 63));
}

uint16_t ipChecksum(const uint8_t* p, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (len & 1) sum += (uint32_t)(p[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

void ipRewriteSrc(uint8_t* p, size_t total, uint32_t newSrc) {
    size_t ihl = (size_t)(p[0] & 15) * 4;
    uint32_t oldSrc = be32(p + 12);
    putBe32(p + 12, newSrc);
    p[10] = p[11] = 0;
    putBe16(p + 10, ipChecksum(p, ihl));
    if ((be16(p + 6) & 0x1FFF) != 0) return;  // not the first fragment: no L4 header here
    uint8_t proto = p[9];
    size_t coff = 0;
    if (proto == 6 && total >= ihl + 18) coff = ihl + 16;
    else if (proto == 17 && total >= ihl + 8) coff = ihl + 6;
    if (!coff) return;
    uint16_t oc = be16(p + coff);
    if (proto == 17 && oc == 0) return;  // UDP checksum not used
    uint32_t sum = (~(uint32_t)oc) & 0xffff;
    sum += (~(oldSrc >> 16)) & 0xffff;
    sum += (~oldSrc) & 0xffff;
    sum += newSrc >> 16;
    sum += newSrc & 0xffff;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t nc = (uint16_t)~sum;
    if (proto == 17 && nc == 0) nc = 0xffff;
    putBe16(p + coff, nc);
}

}  // namespace lb
