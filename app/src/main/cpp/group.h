// LanBridge native core: groups ("rooms" of up to 8 devices). Everything that does not need the engine's state:
// keys derived from the group secret, the group's addresses, the member-list view of the network, and the formats of
// the inner messages (join, member list, relay, profile).
//
// How a group works, in short:
//  * The creator makes a group code (an offer with the group fields). Anybody who has the code can join until it expires.
//  * A newcomer proves that it knows the code by running the usual handshake with a *guest key pair* that everybody
//    derives from the group secret (groupGuestKeys). Over that short-lived "door" session it sends K_JOIN (its own code:
//    key and addresses); the creator answers K_WELCOME (the slot, i.e. the host number in the virtual network) or K_REJECT.
//  * After that the newcomer and the creator are ordinary peers with their real keys. The creator tells every member
//    about every other member (K_MEMBER), and the members connect to each other directly (full mesh). When two members
//    cannot reach each other, their packets go through the creator inside K_RELAY (still end-to-end encrypted).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "ipv6.h"
#include "offer.h"
#include "protocol.h"

namespace lb {

constexpr int kGroupMax = 8;
constexpr size_t kProfileNameMax = 40;  // bytes of UTF-8
constexpr size_t kAvatarMax = 12288;    // bytes (a small JPEG)
constexpr size_t kAvatarChunk = 1000;
constexpr int kAvatarMaxChunks = (int)((kAvatarMax + kAvatarChunk - 1) / kAvatarChunk);

enum RejectReason : uint8_t { REJ_FULL = 1, REJ_CLOSED = 2, REJ_BAD = 3, REJ_TIMEOUT = 9 };

// ---- derived values ----
void groupGuestKeys(const uint8_t secret[32], KeyPair& kp);
Ip6 groupNet6(const uint8_t secret[32]);  // fdXX:XXXX:XXXX::/64
// The third octet of the group network 192.168.X.0/24: derived from the secret (100..249), moved on while it clashes
// with one of `hostIps` (addresses of the creator's own interfaces).
uint8_t groupPickThird(const uint8_t secret[32], const std::vector<uint32_t>& hostIps);
inline uint32_t groupNet4(uint8_t third) { return (192u << 24) | (168u << 16) | ((uint32_t)third << 8); }
// Removes control characters and cuts at a UTF-8 character boundary, at most maxBytes bytes.
std::string utf8Trunc(const std::string& s, size_t maxBytes);

// ---- the network as seen from one member ----
struct MemberNet {
    int slot = 0;
    uint32_t ip4 = 0;  // virtual address
    Ip6 ip6{};
    std::vector<uint32_t> aliasPeer, aliasMine;  // like Layout: the member's real addresses I route / mine that it routes
    std::vector<Ip6> aliasPeer6, aliasMine6;
};
struct GroupMemberRef {
    int slot;
    const Offer* offer;
};
struct GroupNets {
    int mySlot = 0;
    uint32_t net4 = 0, myIp4 = 0;
    Ip6 net6{}, myIp6{};
    std::vector<MemberNet> peers;                    // in the order of `others`
    std::vector<uint32_t> realMine, realPeer;        // unions over all members (for the routes and addresses of the TUN)
    std::vector<Ip6> realMine6, realPeer6;
};
// A real address is mirrored only if it passes aliasUsable4/6 and exactly one member of the group announces it (two
// phones on 192.168.0.x networks of their own both have 192.168.0.100: that address means nothing across the tunnel).
GroupNets computeGroupNets(uint32_t net4, const Ip6& net6, int mySlot, const Offer& me,
                           const std::vector<GroupMemberRef>& others);

// ---- inner messages. `p` always points at the kind byte; builders return the whole plaintext ----
std::vector<uint8_t> msgJoin(const std::vector<uint8_t>& offerBlob);
bool parseJoin(const uint8_t* p, size_t n, std::vector<uint8_t>& offerBlob);

// `others`: how many members there are besides the creator and the newcomer (the newcomer learns about them from
// K_MEMBER and knows when its list is complete).
std::vector<uint8_t> msgWelcome(uint8_t slot, uint8_t maxMembers, uint8_t others);
bool parseWelcome(const uint8_t* p, size_t n, uint8_t& slot, uint8_t& maxMembers, uint8_t& others);

std::vector<uint8_t> msgReject(uint8_t reason);
bool parseReject(const uint8_t* p, size_t n, uint8_t& reason);

struct MemberMsg {
    uint8_t slot = 0;
    bool present = false;  // false: the member has left
    uint16_t ver = 0;      // version of this entry (changes whenever the entry changes)
    std::vector<uint8_t> offer;  // the member's code (key, addresses, name); empty when not present
};
std::vector<uint8_t> msgMember(const MemberMsg& m);
bool parseMember(const uint8_t* p, size_t n, MemberMsg& m);

std::vector<uint8_t> msgMemberAck(uint8_t slot, uint16_t ver);
bool parseMemberAck(const uint8_t* p, size_t n, uint8_t& slot, uint16_t& ver);

// Profile: the name travels in K_PROFILE together with the avatar's size, the avatar in K_AVATAR chunks of
// kAvatarChunk bytes; K_PROFILE_ACK says what has arrived.
std::vector<uint8_t> msgProfile(uint16_t ver, const std::string& name, uint16_t avatarLen);
bool parseProfile(const uint8_t* p, size_t n, uint16_t& ver, std::string& name, uint16_t& avatarLen);
std::vector<uint8_t> msgAvatar(uint16_t ver, uint8_t idx, uint8_t cnt, const uint8_t* data, size_t len);
bool parseAvatar(const uint8_t* p, size_t n, uint16_t& ver, uint8_t& idx, uint8_t& cnt, const uint8_t*& data, size_t& len);
std::vector<uint8_t> msgProfileAck(uint16_t ver, bool haveMeta, uint16_t mask);
bool parseProfileAck(const uint8_t* p, size_t n, uint16_t& ver, bool& haveMeta, uint16_t& mask);

// Chunk count for an avatar of `len` bytes.
inline int avatarChunks(size_t len) { return (int)((len + kAvatarChunk - 1) / kAvatarChunk); }
inline bool verNewer(uint16_t a, uint16_t b) { return (int16_t)(uint16_t)(a - b) > 0; }  // a is later than b (wrapping)

}  // namespace lb
