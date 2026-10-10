// LanBridge native core: self-contained crypto primitives.
//   X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439), BLAKE2s (RFC 7693),
//   HMAC-BLAKE2s and the WireGuard-style KDF built on it.
#pragma once

#include <cstddef>
#include <cstdint>

namespace lb {
namespace crypto {

void wipe(void* p, size_t n);
bool ctEqual(const void* a, const void* b, size_t n);

// ---- BLAKE2s ----
class Blake2s {
public:
    explicit Blake2s(size_t outlen = 32, const uint8_t* key = nullptr, size_t keylen = 0);
    void update(const void* data, size_t len);
    void final(uint8_t* out);  // writes outlen bytes

private:
    uint32_t h_[8];
    uint32_t t_[2];
    uint8_t buf_[64];
    size_t buflen_;
    size_t outlen_;
    void compress(bool last);
};

void blake2s(uint8_t* out, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* in, size_t inlen);
void hash2(uint8_t out[32], const void* a, size_t alen, const void* b, size_t blen);  // BLAKE2s-256(a || b)

void hmac(uint8_t out[32], const uint8_t* key, size_t keylen, const uint8_t* in, size_t inlen);
void kdf1(uint8_t t0[32], const uint8_t key[32], const uint8_t* in, size_t inlen);
void kdf2(uint8_t t0[32], uint8_t t1[32], const uint8_t key[32], const uint8_t* in, size_t inlen);
void kdf3(uint8_t t0[32], uint8_t t1[32], uint8_t t2[32], const uint8_t key[32], const uint8_t* in, size_t inlen);

// ---- X25519 ----
// Returns false when the result is the all-zero point (low-order input).
bool x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519Base(uint8_t out[32], const uint8_t scalar[32]);
void genKeypair(uint8_t priv[32], uint8_t pub[32]);

// ---- ChaCha20-Poly1305 (IETF, 96-bit nonce = 32 zero bits || 64-bit LE counter) ----
// out must hold len + 16 bytes (ciphertext || tag).
void aeadEncrypt(uint8_t* out, const uint8_t key[32], uint64_t counter, const uint8_t* ad, size_t adlen,
                 const uint8_t* in, size_t len);
// in holds ciphertext || tag (len includes the 16-byte tag); out receives len - 16 bytes.
bool aeadDecrypt(uint8_t* out, const uint8_t key[32], uint64_t counter, const uint8_t* ad, size_t adlen,
                 const uint8_t* in, size_t len);

// Raw building blocks, exposed for tests.
void chacha20Xor(uint8_t* out, const uint8_t* in, size_t len, const uint8_t key[32], uint32_t counter,
                 const uint8_t nonce[12]);
void poly1305(uint8_t tag[16], const uint8_t key[32], const uint8_t* msg, size_t len);

}  // namespace crypto
}  // namespace lb
