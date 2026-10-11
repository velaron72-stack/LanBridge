// LanBridge native core: connection code ("offer") format and virtual-network layout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "addr.h"
#include "ipv6.h"

namespace lb {

// 3: adds IPv6 addresses (for the tunnel inside); 4: the tunnel itself runs over IPv6 as well (IPv6 candidates and
// the IPv6 port). Codes of other versions are rejected.
constexpr uint8_t kOfferVersion = 4;

struct Candidate {
    uint8_t type;   // 0 = host (local interface address), 1 = server reflexive (public address from STUN)
    uint32_t ip;    // IPv4, host byte order (unused when v6)
    uint16_t port;
    bool v6 = false;
    Ip6 ip6{};      // IPv6 address (when v6)
};

struct Offer {
    uint8_t version = 4;
    uint32_t expiresAt = 0;  // unix seconds
    uint8_t pub[32] = {0};   // one-time static public key (X25519)
    uint8_t nat = 0;         // 0 unknown, 1 endpoint-independent mapping, 2 endpoint-dependent (symmetric)
    std::string name;        // device name, at most 24 bytes
    std::vector<Candidate> cands;  // explicit candidates, IPv4 and IPv6 (at most 12)
    std::vector<Ip6> v6;     // global/ULA IPv6 addresses of the device (at most 3), mirrored like the real IPv4 ones
    // Port of the device's IPv6 socket (0: no IPv6 socket). Every address of `v6` together with this port is an
    // implicit IPv6 host candidate, so these addresses do not have to be written twice into the code.
    uint16_t port6 = 0;
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

// Every endpoint the device can be reached at: the explicit candidates plus the implicit IPv6 host candidates,
// without addresses that cannot be a destination (see addrUsablePeer). Each address appears once, unless
// `unique` is false: then explicit candidates that repeat an address (a host and a server reflexive one are the
// same when the device has a public address) are all kept, for display.
std::vector<Candidate> offerCandidates(const Offer& o, bool unique = true);
inline Addr candAddr(const Candidate& c) { return c.v6 ? addr6(c.ip6, c.port) : addr4(c.ip, c.port); }
// Families the device can be reached over: bit 0 IPv4, bit 1 IPv6.
int offerFamilies(const Offer& o);

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
