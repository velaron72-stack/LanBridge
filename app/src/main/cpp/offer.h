// LanBridge native core: connection code ("offer") format and virtual-network layout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ipv6.h"

namespace lb {

constexpr uint8_t kOfferVersion = 3;  // 3: adds IPv6 addresses; codes of older versions are rejected

struct Candidate {
    uint8_t type;   // 0 = host (local interface address), 1 = server reflexive (public address from STUN)
    uint32_t ip;    // host byte order
    uint16_t port;
};

struct Offer {
    uint8_t version = 3;
    uint32_t expiresAt = 0;  // unix seconds
    uint8_t pub[32] = {0};   // one-time static public key (X25519)
    uint8_t nat = 0;         // 0 unknown, 1 endpoint-independent mapping, 2 endpoint-dependent (symmetric)
    std::string name;        // device name, at most 24 bytes
    std::vector<Candidate> cands;
    std::vector<Ip6> v6;     // global/ULA IPv6 addresses of the device (at most 3), mirrored like the real IPv4 ones
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
    // Real (interface) addresses mirrored through the tunnel, so that apps which bind to, or advertise, the real
    // address of a device still work. Both sides derive the same lists from the two offers.
    std::vector<uint32_t> aliasPeer;  // peer's real addresses: routed into the TUN, forwarded to the peer unchanged
    std::vector<uint32_t> aliasMine;  // our real addresses that the peer routes to us: kept as packet source
    // IPv6 runs inside the same tunnel at the same time: a unique-local /64 derived from both public keys, plus the
    // mirrored real global/ULA addresses (link-local addresses are carried as they are).
    Ip6 net6{}, myIp6{}, peerIp6{};
    int prefix6 = 64;
    std::vector<Ip6> aliasPeer6;
    std::vector<Ip6> aliasMine6;
};
Layout computeLayout(const Offer& mine, const Offer& peer);

}  // namespace lb
