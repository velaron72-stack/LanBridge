// LanBridge native core: wire protocol, handshake (Noise KK + PSK, WireGuard-style), sessions, IP helpers.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace lb {

// Packet types. The two top bits are 10, so they can never be mistaken for STUN (top bits 00).
enum : uint8_t { T_PUNCH = 0xA1, T_MSG1 = 0xA2, T_MSG2 = 0xA3, T_DATA = 0xA4 };

constexpr size_t PUNCH_LEN = 13;  // type | sid[8] | random[4]
constexpr size_t MSG1_LEN = 81;   // type | idx[4] | E[32] | enc_ts[28] | mac1[16]
constexpr size_t MSG2_LEN = 73;   // type | idx[4] | recvIdx[4] | E[32] | enc_empty[16] | mac1[16]
constexpr size_t DATA_HDR = 13;   // type | recvIdx[4] | counter[8]
constexpr size_t AEAD_TAG = 16;
constexpr size_t MAX_PLAIN = 2048;

// Inner frame kinds (first plaintext byte; empty plaintext = keepalive)
enum : uint8_t { K_IP = 1, K_CTRL = 2, K_BYE = 3 };
enum : uint8_t { C_PING = 1, C_PONG = 2 };

struct KeyPair {
    uint8_t priv[32];
    uint8_t pub[32];
};

struct HsInit {  // initiator-side pending handshake
    bool active = false;
    uint32_t localIdx = 0;
    uint8_t ePriv[32];
    uint8_t C[32];
    uint8_t H[32];
    uint64_t ts = 0;
    uint64_t createdMs = 0;
    uint8_t msg1[MSG1_LEN];
    void wipe();
};

struct HsRespIn {  // responder-side state between consuming msg1 and creating msg2
    uint8_t C[32];
    uint8_t H[32];
    uint8_t Ei[32];
    uint32_t senderIdx = 0;
    uint64_t ts = 0;
};

struct TransportKeys {
    uint8_t send[32];
    uint8_t recv[32];
};

// Initiator: me = initiator static key pair, Sr = responder static public key.
bool hsCreateInitiation(HsInit& st, const KeyPair& me, const uint8_t Sr[32], uint64_t ts, uint32_t localIdx);
bool hsConsumeResponse(HsInit& st, const uint8_t* msg, size_t n, const KeyPair& me, const uint8_t psk[32],
                       uint32_t& remoteIdx, TransportKeys& keys);
// Responder: me = responder static key pair, Si = initiator static public key.
bool hsConsumeInitiation(const uint8_t* msg, size_t n, const KeyPair& me, const uint8_t Si[32], HsRespIn& out);
bool hsCreateResponse(const HsRespIn& in, const KeyPair& me, const uint8_t Si[32], const uint8_t psk[32],
                      uint32_t localIdx, uint8_t* msg2, TransportKeys& keys);

void derivePsk(uint8_t psk[32], const char* password, size_t len, const uint8_t sid[8]);
void deriveSid(uint8_t sid[8], const uint8_t pubA[32], const uint8_t pubB[32]);

struct ReplayWindow {
    static constexpr unsigned N = 2048;
    static constexpr unsigned W = N / 64;
    uint64_t bm[W];
    uint64_t top;
    bool any;
    void reset() {
        memset(bm, 0, sizeof bm);
        top = 0;
        any = false;
    }
    bool check(uint64_t c) const;  // true if counter has not been seen and is inside the window
    void update(uint64_t c);       // call only after the packet authenticated
};

struct Session {
    bool valid = false;
    bool confirmed = false;
    bool initiator = false;
    uint32_t localIdx = 0, remoteIdx = 0;
    uint8_t sendKey[32];
    uint8_t recvKey[32];
    uint64_t sendCtr = 0;
    ReplayWindow replay;
    uint64_t createdMs = 0;
    uint64_t lastRxMs = 0;
    void clear();
};

// ---- IPv4 helpers ----
uint16_t ipChecksum(const uint8_t* p, size_t len);
// Replaces the IPv4 source address and fixes IP and TCP/UDP checksums (incremental update).
void ipRewriteSrc(uint8_t* pkt, size_t total, uint32_t newSrcHostOrder);

}  // namespace lb
