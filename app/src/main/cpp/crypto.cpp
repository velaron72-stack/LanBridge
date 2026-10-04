#include "crypto.h"

#include <cstring>

#include "util.h"

namespace lb {
namespace crypto {

void wipe(void* p, size_t n) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
}

bool ctEqual(const void* a, const void* b, size_t n) {
    const uint8_t* x = (const uint8_t*)a;
    const uint8_t* y = (const uint8_t*)b;
    uint8_t r = 0;
    for (size_t i = 0; i < n; i++) r |= (uint8_t)(x[i] ^ y[i]);
    return r == 0;
}

// =====================================================================
// BLAKE2s
// =====================================================================
static const uint32_t B2S_IV[8] = {0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
                                   0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u};

static const uint8_t B2S_SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define B2S_G(a, b, c, d, x, y)                         \
    do {                                                \
        v[a] = v[a] + v[b] + (x);                       \
        v[d] = rotr32(v[d] ^ v[a], 16);                 \
        v[c] = v[c] + v[d];                             \
        v[b] = rotr32(v[b] ^ v[c], 12);                 \
        v[a] = v[a] + v[b] + (y);                       \
        v[d] = rotr32(v[d] ^ v[a], 8);                  \
        v[c] = v[c] + v[d];                             \
        v[b] = rotr32(v[b] ^ v[c], 7);                  \
    } while (0)

void Blake2s::compress(bool last) {
    uint32_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = le32(buf_ + 4 * i);
    for (int i = 0; i < 8; i++) {
        v[i] = h_[i];
        v[i + 8] = B2S_IV[i];
    }
    v[12] ^= t_[0];
    v[13] ^= t_[1];
    if (last) v[14] = ~v[14];
    for (int r = 0; r < 10; r++) {
        const uint8_t* s = B2S_SIGMA[r];
        B2S_G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        B2S_G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        B2S_G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        B2S_G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        B2S_G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        B2S_G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        B2S_G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        B2S_G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; i++) h_[i] ^= v[i] ^ v[i + 8];
}

Blake2s::Blake2s(size_t outlen, const uint8_t* key, size_t keylen) {
    if (outlen < 1 || outlen > 32) outlen = 32;
    if (keylen > 32) keylen = 32;
    memcpy(h_, B2S_IV, sizeof h_);
    h_[0] ^= 0x01010000u ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    t_[0] = t_[1] = 0;
    buflen_ = 0;
    outlen_ = outlen;
    memset(buf_, 0, sizeof buf_);
    if (keylen > 0) {
        uint8_t block[64];
        memset(block, 0, sizeof block);
        memcpy(block, key, keylen);
        update(block, 64);
        wipe(block, sizeof block);
    }
}

void Blake2s::update(const void* data, size_t len) {
    const uint8_t* in = (const uint8_t*)data;
    while (len > 0) {
        if (buflen_ == 64) {  // buffer is full and more data follows: it is not the last block
            t_[0] += 64;
            if (t_[0] < 64) t_[1]++;
            compress(false);
            buflen_ = 0;
        }
        size_t take = 64 - buflen_;
        if (take > len) take = len;
        memcpy(buf_ + buflen_, in, take);
        buflen_ += take;
        in += take;
        len -= take;
    }
}

void Blake2s::final(uint8_t* out) {
    t_[0] += (uint32_t)buflen_;
    if (t_[0] < (uint32_t)buflen_) t_[1]++;
    memset(buf_ + buflen_, 0, 64 - buflen_);
    compress(true);
    uint8_t full[32];
    for (int i = 0; i < 8; i++) putLe32(full + 4 * i, h_[i]);
    memcpy(out, full, outlen_);
    wipe(full, sizeof full);
}

void blake2s(uint8_t* out, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* in, size_t inlen) {
    Blake2s b(outlen, key, keylen);
    b.update(in, inlen);
    b.final(out);
}

void hash2(uint8_t out[32], const void* a, size_t alen, const void* b, size_t blen) {
    Blake2s h(32);
    h.update(a, alen);
    h.update(b, blen);
    h.final(out);
}

void hmac(uint8_t out[32], const uint8_t* key, size_t keylen, const uint8_t* in, size_t inlen) {
    uint8_t k[64];
    memset(k, 0, sizeof k);
    if (keylen > 64) {
        blake2s(k, 32, nullptr, 0, key, keylen);
    } else if (keylen > 0) {
        memcpy(k, key, keylen);
    }
    uint8_t ipad[64], opad[64], inner[32];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(k[i] ^ 0x36);
        opad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    Blake2s a(32);
    a.update(ipad, 64);
    a.update(in, inlen);
    a.final(inner);
    Blake2s b(32);
    b.update(opad, 64);
    b.update(inner, 32);
    b.final(out);
    wipe(k, sizeof k);
    wipe(ipad, sizeof ipad);
    wipe(opad, sizeof opad);
    wipe(inner, sizeof inner);
}

void kdf1(uint8_t t0[32], const uint8_t key[32], const uint8_t* in, size_t inlen) {
    uint8_t tau[32];
    hmac(tau, key, 32, in, inlen);
    const uint8_t one = 1;
    hmac(t0, tau, 32, &one, 1);
    wipe(tau, sizeof tau);
}

void kdf2(uint8_t t0[32], uint8_t t1[32], const uint8_t key[32], const uint8_t* in, size_t inlen) {
    uint8_t tau[32], buf[33];
    hmac(tau, key, 32, in, inlen);
    const uint8_t one = 1;
    hmac(t0, tau, 32, &one, 1);
    memcpy(buf, t0, 32);
    buf[32] = 2;
    hmac(t1, tau, 32, buf, 33);
    wipe(tau, sizeof tau);
    wipe(buf, sizeof buf);
}

void kdf3(uint8_t t0[32], uint8_t t1[32], uint8_t t2[32], const uint8_t key[32], const uint8_t* in, size_t inlen) {
    uint8_t tau[32], buf[33];
    hmac(tau, key, 32, in, inlen);
    const uint8_t one = 1;
    hmac(t0, tau, 32, &one, 1);
    memcpy(buf, t0, 32);
    buf[32] = 2;
    hmac(t1, tau, 32, buf, 33);
    memcpy(buf, t1, 32);
    buf[32] = 3;
    hmac(t2, tau, 32, buf, 33);
    wipe(tau, sizeof tau);
    wipe(buf, sizeof buf);
}

// =====================================================================
// X25519 (TweetNaCl-style field arithmetic, portable to 32-bit ARM)
// =====================================================================
typedef int64_t gf[16];
static const uint8_t X_BASE[32] = {9};
static const gf X_121665 = {0xDB41, 1};

#define FOR(i, n) for (i = 0; i < (n); ++i)

static void car25519(gf o) {
    int i;
    int64_t c;
    FOR(i, 16) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c * 65536LL;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t, i, c = ~((int64_t)b - 1);
    FOR(i, 16) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t* o, const gf n) {
    int i, j, b;
    gf m, t;
    FOR(i, 16) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    FOR(j, 2) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    FOR(i, 16) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t* n) {
    int i;
    FOR(i, 16) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fA(gf o, const gf a, const gf b) {
    int i;
    FOR(i, 16) o[i] = a[i] + b[i];
}
static void fZ(gf o, const gf a, const gf b) {
    int i;
    FOR(i, 16) o[i] = a[i] - b[i];
}
static void fM(gf o, const gf a, const gf b) {
    int64_t i, j, t[31];
    FOR(i, 31) t[i] = 0;
    FOR(i, 16) FOR(j, 16) t[i + j] += a[i] * b[j];
    FOR(i, 15) t[i] += 38 * t[i + 16];
    FOR(i, 16) o[i] = t[i];
    car25519(o);
    car25519(o);
}
static void fS(gf o, const gf a) { fM(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    int a;
    FOR(a, 16) c[a] = i[a];
    for (a = 253; a >= 0; a--) {
        fS(c, c);
        if (a != 2 && a != 4) fM(c, c, i);
    }
    FOR(a, 16) o[a] = c[a];
}

static void scalarmult(uint8_t* q, const uint8_t* n, const uint8_t* p) {
    uint8_t z[32];
    int64_t x[80], r, i;
    gf a, b, c, d, e, f;
    FOR(i, 31) z[i] = n[i];
    z[31] = (uint8_t)((n[31] & 127) | 64);
    z[0] &= 248;
    unpack25519(x, p);
    FOR(i, 16) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
        fA(e, a, c);
        fZ(a, a, c);
        fA(c, b, d);
        fZ(b, b, d);
        fS(d, e);
        fS(f, a);
        fM(a, c, a);
        fM(c, b, e);
        fA(e, a, c);
        fZ(a, a, c);
        fS(b, a);
        fZ(c, d, f);
        fM(a, c, X_121665);
        fA(a, a, d);
        fM(c, c, a);
        fM(a, d, f);
        fM(d, b, x);
        fS(b, e);
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }
    FOR(i, 16) {
        x[i + 16] = a[i];
        x[i + 32] = c[i];
        x[i + 48] = b[i];
        x[i + 64] = d[i];
    }
    inv25519(x + 32, x + 32);
    fM(x + 16, x + 16, x + 32);
    pack25519(q, x + 16);
    wipe(z, sizeof z);
}

bool x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    scalarmult(out, scalar, point);
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    return acc != 0;
}

void x25519Base(uint8_t out[32], const uint8_t scalar[32]) { scalarmult(out, scalar, X_BASE); }

void genKeypair(uint8_t priv[32], uint8_t pub[32]) {
    randomBytes(priv, 32);
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    x25519Base(pub, priv);
}

// =====================================================================
// ChaCha20
// =====================================================================
#define CC_QR(a, b, c, d)  \
    a += b;                \
    d ^= a;                \
    d = rotl32(d, 16);     \
    c += d;                \
    b ^= c;                \
    b = rotl32(b, 12);     \
    a += b;                \
    d ^= a;                \
    d = rotl32(d, 8);      \
    c += d;                \
    b ^= c;                \
    b = rotl32(b, 7);

static void chacha20Block(uint8_t out[64], const uint8_t key[32], uint32_t counter, const uint8_t nonce[12]) {
    uint32_t s[16], x[16];
    s[0] = 0x61707865u;
    s[1] = 0x3320646eu;
    s[2] = 0x79622d32u;
    s[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) s[4 + i] = le32(key + 4 * i);
    s[12] = counter;
    s[13] = le32(nonce);
    s[14] = le32(nonce + 4);
    s[15] = le32(nonce + 8);
    memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; i++) {
        CC_QR(x[0], x[4], x[8], x[12])
        CC_QR(x[1], x[5], x[9], x[13])
        CC_QR(x[2], x[6], x[10], x[14])
        CC_QR(x[3], x[7], x[11], x[15])
        CC_QR(x[0], x[5], x[10], x[15])
        CC_QR(x[1], x[6], x[11], x[12])
        CC_QR(x[2], x[7], x[8], x[13])
        CC_QR(x[3], x[4], x[9], x[14])
    }
    for (int i = 0; i < 16; i++) putLe32(out + 4 * i, x[i] + s[i]);
}

void chacha20Xor(uint8_t* out, const uint8_t* in, size_t len, const uint8_t key[32], uint32_t counter,
                 const uint8_t nonce[12]) {
    uint8_t block[64];
    while (len > 0) {
        chacha20Block(block, key, counter++, nonce);
        size_t n = len < 64 ? len : 64;
        for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(in[i] ^ block[i]);
        in += n;
        out += n;
        len -= n;
    }
    wipe(block, sizeof block);
}

// =====================================================================
// Poly1305 (26-bit limb implementation)
// =====================================================================
struct Poly1305 {
    uint32_t r[5], h[5], pad[4];
    size_t leftover;
    uint8_t buffer[16];
    bool fin;

    void init(const uint8_t key[32]) {
        r[0] = le32(key + 0) & 0x3ffffff;
        r[1] = (le32(key + 3) >> 2) & 0x3ffff03;
        r[2] = (le32(key + 6) >> 4) & 0x3ffc0ff;
        r[3] = (le32(key + 9) >> 6) & 0x3f03fff;
        r[4] = (le32(key + 12) >> 8) & 0x00fffff;
        for (int i = 0; i < 5; i++) h[i] = 0;
        for (int i = 0; i < 4; i++) pad[i] = le32(key + 16 + 4 * i);
        leftover = 0;
        fin = false;
    }

    void blocks(const uint8_t* m, size_t bytes) {
        const uint32_t hibit = fin ? 0 : (1u << 24);
        uint32_t r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
        uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        while (bytes >= 16) {
            h0 += le32(m + 0) & 0x3ffffff;
            h1 += (le32(m + 3) >> 2) & 0x3ffffff;
            h2 += (le32(m + 6) >> 4) & 0x3ffffff;
            h3 += (le32(m + 9) >> 6) & 0x3ffffff;
            h4 += (le32(m + 12) >> 8) | hibit;

            uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
            uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
            uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
            uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
            uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

            uint32_t c = (uint32_t)(d0 >> 26);
            h0 = (uint32_t)d0 & 0x3ffffff;
            d1 += c;
            c = (uint32_t)(d1 >> 26);
            h1 = (uint32_t)d1 & 0x3ffffff;
            d2 += c;
            c = (uint32_t)(d2 >> 26);
            h2 = (uint32_t)d2 & 0x3ffffff;
            d3 += c;
            c = (uint32_t)(d3 >> 26);
            h3 = (uint32_t)d3 & 0x3ffffff;
            d4 += c;
            c = (uint32_t)(d4 >> 26);
            h4 = (uint32_t)d4 & 0x3ffffff;
            h0 += c * 5;
            c = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += c;

            m += 16;
            bytes -= 16;
        }
        h[0] = h0;
        h[1] = h1;
        h[2] = h2;
        h[3] = h3;
        h[4] = h4;
    }

    void update(const uint8_t* m, size_t bytes) {
        if (leftover) {
            size_t want = 16 - leftover;
            if (want > bytes) want = bytes;
            memcpy(buffer + leftover, m, want);
            bytes -= want;
            m += want;
            leftover += want;
            if (leftover < 16) return;
            blocks(buffer, 16);
            leftover = 0;
        }
        if (bytes >= 16) {
            size_t want = bytes & ~(size_t)15;
            blocks(m, want);
            m += want;
            bytes -= want;
        }
        if (bytes) {
            memcpy(buffer + leftover, m, bytes);
            leftover += bytes;
        }
    }

    void finish(uint8_t mac[16]) {
        if (leftover) {
            size_t i = leftover;
            buffer[i++] = 1;
            for (; i < 16; i++) buffer[i] = 0;
            fin = true;
            blocks(buffer, 16);
        }
        uint32_t h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4];
        uint32_t c = h1 >> 26;
        h1 &= 0x3ffffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ffffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ffffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ffffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        uint32_t g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x3ffffff;
        uint32_t g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        uint32_t g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        uint32_t g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        uint32_t g4 = h4 + c - (1u << 26);

        uint32_t mask = (g4 >> 31) - 1;
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        h0 = (h0 | (h1 << 26)) & 0xffffffff;
        h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
        h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
        h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

        uint64_t f = (uint64_t)h0 + pad[0];
        h0 = (uint32_t)f;
        f = (uint64_t)h1 + pad[1] + (f >> 32);
        h1 = (uint32_t)f;
        f = (uint64_t)h2 + pad[2] + (f >> 32);
        h2 = (uint32_t)f;
        f = (uint64_t)h3 + pad[3] + (f >> 32);
        h3 = (uint32_t)f;

        putLe32(mac + 0, h0);
        putLe32(mac + 4, h1);
        putLe32(mac + 8, h2);
        putLe32(mac + 12, h3);
        wipe(this, sizeof *this);
    }
};

void poly1305(uint8_t tag[16], const uint8_t key[32], const uint8_t* msg, size_t len) {
    Poly1305 p;
    p.init(key);
    p.update(msg, len);
    p.finish(tag);
}

// =====================================================================
// AEAD ChaCha20-Poly1305
// =====================================================================
static void makeNonce(uint8_t nonce[12], uint64_t ctr) {
    memset(nonce, 0, 4);
    putLe64(nonce + 4, ctr);
}

static void aeadTag(uint8_t tag[16], const uint8_t otk[32], const uint8_t* ad, size_t adlen, const uint8_t* ct,
                    size_t ctlen) {
    static const uint8_t zeros[16] = {0};
    Poly1305 p;
    p.init(otk);
    if (adlen) p.update(ad, adlen);
    if (adlen % 16) p.update(zeros, 16 - adlen % 16);
    if (ctlen) p.update(ct, ctlen);
    if (ctlen % 16) p.update(zeros, 16 - ctlen % 16);
    uint8_t lens[16];
    putLe64(lens, adlen);
    putLe64(lens + 8, ctlen);
    p.update(lens, 16);
    p.finish(tag);
}

void aeadEncrypt(uint8_t* out, const uint8_t key[32], uint64_t counter, const uint8_t* ad, size_t adlen,
                 const uint8_t* in, size_t len) {
    uint8_t nonce[12], block0[64];
    makeNonce(nonce, counter);
    chacha20Block(block0, key, 0, nonce);
    if (len) chacha20Xor(out, in, len, key, 1, nonce);
    aeadTag(out + len, block0, ad, adlen, out, len);
    wipe(block0, sizeof block0);
}

bool aeadDecrypt(uint8_t* out, const uint8_t key[32], uint64_t counter, const uint8_t* ad, size_t adlen,
                 const uint8_t* in, size_t len) {
    if (len < 16) return false;
    size_t ctlen = len - 16;
    uint8_t nonce[12], block0[64], tag[16];
    makeNonce(nonce, counter);
    chacha20Block(block0, key, 0, nonce);
    aeadTag(tag, block0, ad, adlen, in, ctlen);
    wipe(block0, sizeof block0);
    if (!ctEqual(tag, in + ctlen, 16)) return false;
    if (ctlen) chacha20Xor(out, in, ctlen, key, 1, nonce);
    return true;
}

}  // namespace crypto
}  // namespace lb
