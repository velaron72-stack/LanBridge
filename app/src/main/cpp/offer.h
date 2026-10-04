// LanBridge native core: connection code ("offer") format and virtual-network layout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lb {

struct Candidate {
    uint8_t type;   // 0 = host (local interface address), 1 = server reflexive (public address from STUN)
    uint32_t ip;    // host byte order
    uint16_t port;
};

struct Offer {
    uint8_t version = 1;
    uint32_t expiresAt = 0;  // unix seconds
    uint8_t pub[32] = {0};   // one-time static public key (X25519)
    uint8_t nat = 0;         // 0 unknown, 1 endpoint-independent mapping, 2 endpoint-dependent (symmetric)
    std::string name;        // device name, at most 24 bytes
    std::vector<Candidate> cands;
};

enum OfferError {
    OFFER_OK = 0,
    OFFER_FORMAT = 1,
    OFFER_CHECKSUM = 2,
    OFFER_EXPIRED = 3,
    OFFER_OWN = 4,
    OFFER_VERSION = 5,
    OFFER_NOT_READY = 6,
    OFFER_NO_CANDIDATES = 7,
    OFFER_OWN_EXPIRED = 8
};

bool offerEncode(const Offer& o, std::vector<uint8_t>& out);
int offerDecode(const uint8_t* p, size_t n, Offer& o);

// Virtual network shared by both peers. Computed from the two offers only, so both sides get the same answer.
struct Layout {
    uint32_t net = 0, myIp = 0, peerIp = 0, bcast = 0;
    int prefix = 24;
    bool initiator = false;  // the peer with the lower public key initiates handshakes and gets .1
};
Layout computeLayout(const Offer& mine, const Offer& peer);

}  // namespace lb
