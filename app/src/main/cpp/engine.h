// LanBridge native core: tunnel engine (UDP sockets for IPv4 and IPv6, STUN, hole punching, handshake, TUN <-> network pump).
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "offer.h"
#include "udpio.h"

namespace lb {

enum State {
    ST_IDLE = 0,
    ST_PREPARING = 1,
    ST_READY = 2,
    ST_CONNECTING = 3,
    ST_CONNECTED = 4,
    ST_STALLED = 5,
    ST_FAILED = 6
};

struct Config {
    int probeIntervalMs = 300;
    int probeSlowAfterMs = 20000;
    int probeSlowIntervalMs = 1000;
    int hsRefreshMs = 2000;
    int keepaliveMs = 15000;
    int pingMs = 3000;
    int rekeyAfterMs = 120000;
    int rejectAfterMs = 240000;
    int stallMs = 40000;
    int connectTimeoutMs = 180000;
    int stunKeepMs = 10000;
    int stunTimeoutMs = 3000;
    // groups
    int syncMs = 700;          // member-list entries are repeated this often until acknowledged
    int memberReapMs = 90000;  // the creator drops a member it has not heard from for this long
    int joinTimeoutMs = 30000; // a newcomer gives up when the creator does not let it in
    int joinGraceS = 120;      // the creator still admits newcomers this long after the code's expiry (clock skew)
    // false: the code of this device asks the others not to mirror its real addresses (see Offer::noMirror).
    bool mirrorReal = true;
};

// Layout of the int64 array returned by Engine::status()
//  0 state            1 rxBytes          2 txBytes        3 rxPkts        4 txPkts
//  5 rttMs (-1)       6 sinceRxMs (-1)   7 connectedSec   8 pathLocal(-1/0/1)
//  9 bcastTx         10 bcastRx         11 mcastTx       12 mcastRx
// 13 authFail        14 punchRx         15 hsRx          16 dropped      17 mappingChanged
// 18 myNat           19 peerNat         20 myExpiresAt   21 handshakes   22 peerLeft
// 23 layoutVersion (changes when addresses or routes of the TUN must be re-established)
// 24 members (other devices in the network)   25 members connected   26 groupRole (0 direct, 1 creator, 2 member)
// 27 joinState (0 none, 1 joining, 2 admitted, 3 refused)   28 mySlot   29 joinUntil (unix s, creator)
// 30 packets relayed through the creator (forwarded by it / sent through it)   31 memberListSettled (0/1)
// Aggregates (rtt, path, rx/tx ...) are taken over all members; the per-member numbers are in members().
constexpr int STATUS_FIELDS = 32;

struct EngineTestAccess;

class Engine {
public:
    Engine();
    ~Engine();

    void setConfig(const Config& c);
    // Replaces how the UDP sockets are created (tests put a simulated network under the engine). Call before prepare().
    void setSocketFactory(UdpFactory f);

    // Opens the UDP sockets (IPv4 and IPv6; one of them may be unavailable), asks STUN servers for the public
    // addresses and creates a one-time identity.
    // Returns 0 and fills offerOut on success; 1 socket error, 2 no usable address, 3 busy.
    int prepare(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                const std::string& deviceName, int ttlSec, std::vector<uint8_t>& offerOut);

    // Like prepare(), but the code is a group code: anybody who has it can join the creator's group (up to 8 devices)
    // until it expires. The creator is READY at once and takes members in without a TUN; start() attaches the TUN.
    int prepareGroup(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                     const std::string& deviceName, int ttlSec, std::vector<uint8_t>& codeOut);
    // Creator: a fresh code for the same group with a new expiry; joining stays open until then. 0 = ok.
    int renewGroup(int ttlSec, std::vector<uint8_t>& codeOut);
    // Newcomer (after prepare()): joins the group of a group code. Returns an OfferError code; admission itself
    // happens in the background (status[27]).
    int joinGroup(const std::vector<uint8_t>& blob);

    // Decodes a friend's code; returns an OfferError code and fills "key=value" lines.
    int describe(const std::vector<uint8_t>& blob, std::string& textOut);
    int setPeer(const std::vector<uint8_t>& blob);
    bool layout(Layout& out);  // direct mode only
    // The virtual network as "key=value" lines (both modes); empty while there is none (no friend yet / not admitted).
    std::string netLayout();

    // Takes ownership of tunFd (closed on failure). 0 = started.
    int start(int tunFd, int mtu);
    // Replaces the TUN of a running tunnel (after addresses or routes changed); the old one is closed. 0 = ok.
    int swapTun(int newFd);
    void retry();
    void stop();

    // My name and avatar (a small JPEG, at most 12 KB) for the other members; sent to everybody and re-sent on change.
    bool setProfile(const std::string& name, const std::vector<uint8_t>& avatar);
    // One line per member ("M" + TAB-separated fields, see engine_group.cpp), first the line of this device ("S").
    std::string members();
    bool memberAvatar(int slot, std::vector<uint8_t>& out);

    // Optional "mailbox" help for creators behind a strict NAT. A newcomer's first packets are dropped by such a NAT
    // until the creator has sent something to the newcomer's address, and the creator only learns that address from
    // the newcomer. The app can carry a small sealed note through any public message board: hintTopic() is the name of
    // the board (derived from the group code), sealHint() the note of a newcomer, openHint() is called by the creator
    // for every note it reads. Everything is encrypted with a key derived from the group code.
    std::string hintTopic();
    bool sealHint(std::vector<uint8_t>& out);
    // Returns the number of addresses that will be poked, or -1 (not a creator / bad or stale note).
    int openHint(const std::vector<uint8_t>& note);

    void status(int64_t out[STATUS_FIELDS]);
    std::string info();
    // Diagnostics: drop reasons and the busiest flows crossing the tunnel (text, one item per line).
    std::string flows();
    void resetFlows();
    std::string lastError();
    int socketFd();   // IPv4 socket, -1 when there is none; the VPN service must protect() it
    int socketFd6();  // IPv6 socket, -1 when there is none; must be protected as well
    uint16_t localPort();
    uint16_t localPort6();

    struct Impl;  // internals, see engine_impl.h

private:
    friend struct EngineTestAccess;  // the self-tests play a misbehaving member
    std::unique_ptr<Impl> p_;
    void stopInternal();
    int prepareCommon(bool group, const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                      const std::string& deviceName, int ttlSec, std::vector<uint8_t>& offerOut);
};

}  // namespace lb
