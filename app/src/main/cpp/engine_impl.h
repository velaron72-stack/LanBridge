// LanBridge native core: internals of the tunnel engine, shared by engine*.cpp. Not a public header.
//
// The engine is a set of "peers" (the other devices of the virtual network) plus one UDP socket per address family
// and an optional TUN. A direct connection is a network of two (one peer); a group is a network of up to 8 where every
// member has a session with every other one (mesh) and the creator may forward packets between members that cannot
// reach each other. All Impl methods run with Impl::mu held.
#pragma once

#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "addr.h"
#include "crypto.h"
#include "engine.h"
#include "frag.h"
#include "group.h"
#include "ipv6.h"
#include "offer.h"
#include "protocol.h"
#include "stun.h"
#include "udpio.h"
#include "util.h"

namespace lb {

constexpr int kMaxSessions = 4;
constexpr size_t kMaxGuests = 16;
constexpr size_t kMaxLl = 64;

bool offerExpired(const Offer& o);
const char* stateName(int s);

// Where a datagram came from / goes to. Normally a UDP address; `relay >= 0` means "through the group creator, from or
// to the member with this slot".
struct Route {
    Addr addr;
    int relay = -1;
    bool viaRelay() const { return relay >= 0; }
    static Route direct(const Addr& a) {
        Route r;
        r.addr = a;
        return r;
    }
    static Route relayed(int slot) {
        Route r;
        r.relay = slot;
        return r;
    }
};

// Addresses of one peer inside the virtual network.
struct PeerNet {
    uint32_t ip4 = 0;
    Ip6 ip6{};
    std::vector<uint32_t> aliasPeer, aliasMine;  // see Layout
    std::vector<Ip6> aliasPeer6, aliasMine6;
};

struct ProfileOut {  // delivery of my profile to one peer
    uint16_t ver = 0;
    bool metaAcked = false;
    uint16_t ackMask = 0;
    uint64_t nextMs = 0;
    uint8_t tries = 0;
    bool done = false;
};
struct ProfileIn {  // profile data of a peer that is still arriving
    uint16_t ver = 0;
    bool haveMeta = false;
    std::string name;
    uint16_t avLen = 0;
    uint8_t cnt = 0;
    uint16_t mask = 0;
    std::vector<uint8_t> buf;
    uint64_t lastAckMs = 0;
};

struct Peer {
    int slot = 0;  // host number in the virtual network (1..8)
    Offer offer;   // its code (a direct friend's code, a member's code from the member list, or the group code)
    std::vector<uint8_t> blob;
    PeerNet net;
    bool initiator = false;  // the lower public key initiates handshakes
    bool isCreator = false;  // this peer is the creator of the group we are in
    bool guestMode = false;  // newcomer -> creator before admission: handshake with the shared guest key
    uint8_t sid[8];
    std::vector<Addr> cands;  // every address it can be tried at (both families)

    Session sess[kMaxSessions];
    HsInit pend;
    bool haveLast = false;
    uint8_t lastMsg1[MSG1_LEN];
    uint8_t lastMsg2[MSG2_LEN];
    uint64_t lastTsSent = 0, lastInitTs = 0;
    uint8_t ss[32];    // static-static DH with this peer (for the key pair in ssMe), computed once
    uint8_t ssMe[32];  // public key of the pair the cached value belongs to
    bool ssOk = false;

    Addr addr;  // the direct path in use
    bool addrValid = false;
    uint64_t addrMs = 0, pathLogMs = 0;
    std::vector<Addr> punchSeen;

    uint64_t addedMs = 0, startMs = 0, nextProbeMs = 0, nextPingMs = 0, nextRekeyMs = 0;
    uint64_t lastTxMs = 0, lastRxMs = 0, lastDirectRxMs = 0, lastRelayRxMs = 0, connectedSinceMs = 0;
    uint64_t directEchoMs = 0, relayEchoMs = 0;  // last answers to pings that took the direct / the relayed path
    bool everConnected = false, left = false, connected = false;
    int64_t rttMs = -1;
    uint64_t rxBytes = 0, txBytes = 0;
    FragReassembler reasm;

    // profile
    std::string profName;
    std::vector<uint8_t> avatar;
    uint16_t profVer = 0;  // version of the completed incoming profile (0: none yet)
    ProfileIn pin;
    ProfileOut pout;

    // creator side: which entries of the member list this peer has acknowledged
    std::map<int, uint16_t> synced;
    uint64_t nextSyncMs = 0;

    Peer() {
        memset(sid, 0, sizeof sid);
        memset(lastMsg1, 0, sizeof lastMsg1);
        memset(lastMsg2, 0, sizeof lastMsg2);
        memset(ss, 0, sizeof ss);
        memset(ssMe, 0, sizeof ssMe);
    }
};

// A newcomer's session with the creator over the guest key, before it has a slot.
struct GuestSess {
    Session s;
    Addr addr;
    uint64_t createdMs = 0, lastRxMs = 0;
    uint8_t msg1[MSG1_LEN];
    uint8_t msg2[MSG2_LEN];
    bool joined = false;  // K_JOIN processed
    int slot = 0;
    uint8_t others = 0;
};

struct GroupState {
    int role = 0;  // 0 direct pair, 1 creator, 2 member
    uint8_t secret[32];
    KeyPair guest;
    uint8_t guestSs[32];   // DH(own static, guest key) for the door, with the keys it belongs to in guestSsTag
    uint8_t guestSsTag[64];
    bool guestSsOk = false;
    uint8_t third = 0;
    uint32_t net4 = 0;
    Ip6 net6{};
    int maxMembers = kGroupMax;
    int mySlot = 0;  // 0 until admitted
    uint64_t joinUntilS = 0;  // creator: joins are accepted until this unix time
    // newcomer
    int joinState = 0;  // 0 none, 1 joining, 2 admitted, 3 refused
    int rejectReason = 0;
    uint64_t joinStartMs = 0, nextJoinMs = 0;
    int expectOthers = 0;  // members besides the creator and me, as announced by K_WELCOME
    // creator
    uint16_t rosterVer = 0;
    struct Entry {
        bool used = false, present = false;
        uint8_t pub[32];
        std::vector<uint8_t> blob;
        uint16_t ver = 0;
    };
    Entry roster[kGroupMax + 1];
    // member: newest applied version of every entry of the member list
    uint16_t seenVer[kGroupMax + 1];
    bool seen[kGroupMax + 1];
    std::vector<GuestSess> guests;
    uint64_t relayFwd = 0, relayTx = 0;
    GroupState() {
        memset(secret, 0, sizeof secret);
        memset(&guest, 0, sizeof guest);
        memset(seenVer, 0, sizeof seenVer);
        memset(seen, 0, sizeof seen);
    }
};

// The virtual network seen from this device (what the TUN has to be set up with).
struct NetView {
    bool valid = false;
    bool group = false;
    int mySlot = 0;
    uint32_t net = 0, myIp = 0, bcast = 0;
    int prefix = 24;
    Ip6 net6{}, myIp6{};
    int prefix6 = 64;
    bool initiator = false;  // direct mode
    std::vector<uint32_t> realMine, realPeer;
    std::vector<Ip6> realMine6, realPeer6;
};

struct Engine::Impl {
    Config cfg;
    std::mutex mu;      // protects every field below
    std::mutex lifeMu;  // serialises prepare()/stop()
    std::atomic<int> state{ST_IDLE};
    std::string lastErr;

    // The tunnel's own transport: one UDP socket per address family (either may be missing, e.g. a host without
    // IPv6). Both are protected from the VPN by the caller and polled by the engine thread.
    UdpFactory factory;
    std::unique_ptr<UdpSocket> s4, s6;
    std::string sockErr4, sockErr6;
    uint64_t txErr4 = 0, txErr6 = 0, noRoute = 0;
    int lastTxErrno[2] = {0, 0};
    int wakeFd[2] = {-1, -1};
    std::thread th;
    std::atomic<bool> running{false};

    // identity (one per code)
    bool haveIdentity = false;
    KeyPair kp;
    Offer myOffer;
    int myNat = 0;
    std::vector<StunServer> stun;
    bool mappingChanged = false;
    uint64_t nextStunMs = 0;
    struct StunPend {
        uint8_t txid[12];
        size_t srv;
        uint64_t sentMs;
    };
    std::vector<StunPend> stunPend;

    // peers
    std::vector<std::unique_ptr<Peer>> peers;
    std::vector<int> doomed;  // slots of peers to remove once the current event is handled
    bool havePeer = false;    // direct mode: the friend's code is set (peers[0])
    Layout lay;               // direct mode
    uint8_t psk[32];          // always zero: peers authenticate each other with the keys from the codes
    GroupState grp;
    NetView view;
    std::string viewKey;
    uint32_t layoutVer = 0;
    std::string profName;  // my own profile
    std::vector<uint8_t> avatar;
    uint16_t profVer = 0;
    struct LlEntry {  // link-local IPv6 neighbours learned from received packets
        Ip6 a;
        int slot;
        uint64_t ms;
    };
    std::vector<LlEntry> ll6;
    struct Poke {  // creator: addresses of newcomers that get a few empty datagrams to open the creator's NAT for them
        Addr a;
        uint64_t until = 0, next = 0;
    };
    std::vector<Poke> pokes;

    // runtime
    int tunFd = -1;
    int mtu = 1280;
    uint64_t connectStartMs = 0, connectedSinceMs = 0;
    uint64_t nextTickMs = 0;
    uint64_t lastTxMs = 0, lastRxMs = 0;  // over all peers
    uint64_t lastAuthLogMs = 0;

    // statistics
    uint64_t rxBytes = 0, txBytes = 0, rxPkts = 0, txPkts = 0;
    uint64_t bcastTx = 0, bcastRx = 0, mcastTx = 0, mcastRx = 0;
    uint64_t authFail = 0, punchRx = 0, hsRx = 0, dropped = 0, handshakes = 0, dupDropped = 0;

    // diagnostics
    uint64_t dropForeignDst = 0, dropNoSession = 0, dropBadHdr = 0, dropRxSrc = 0, dropRxDst = 0, tunWriteErr = 0;
    uint64_t udpQueued = 0, udpDropped = 0;
    uint16_t fragSeq = 0;
    uint64_t fragSent = 0, fragRecv = 0, dropTooBig = 0, mssClamped = 0;
    uint64_t v6Tx = 0, v6Rx = 0;
    // Flows are aggregated by (direction, protocol, addresses, service port) so that many short-lived connections of
    // one service share one entry. T: forwarded to a peer, R: delivered to the TUN, X/Y: dropped (TUN / peer side).
    struct Flow {
        char dir;
        uint8_t proto;
        bool v6;
        uint32_t sip, dip;
        Ip6 s6, d6;
        uint16_t svc;
        uint64_t pkts, bytes;
        uint16_t maxLen;
        uint32_t syn, synack, rst, fin, frags;
        uint64_t firstMs, lastMs;
    };
    struct PktRec {
        uint32_t tMs;
        char dir;
        uint8_t proto, tcpFlags, ipFlags;
        bool v6;
        uint32_t sip, dip;
        Ip6 s6, d6;
        uint16_t sport, dport, len;
    };
    std::vector<Flow> flowTab;
    uint64_t flowOverflow = 0;
    uint64_t selftestPkts = 0;
    uint64_t flowEpochMs = 0;
    std::vector<PktRec> headRing;
    PktRec tailRing[96];
    size_t tailCount = 0;

    // UDP source fixup (what IP_PKTINFO would give a server): a reply must come from the very address the peer used.
    struct UdpAssoc {
        uint32_t local;
        uint64_t lastMs;
    };
    std::unordered_map<uint64_t, UdpAssoc> udpAssoc;
    struct FragFix {
        uint32_t src, dst, newSrc;
        uint16_t id;
        uint64_t expMs;
    };
    std::vector<FragFix> fragFix;
    uint64_t lastAssocGcMs = 0;
    uint64_t udpFixups = 0;

    // outgoing datagrams that did not fit into the socket buffer yet
    struct OutPkt {
        Addr to;
        uint16_t len;
        uint8_t data[2048];
    };
    std::deque<OutPkt> outq;

    Impl() {
        memset(&kp, 0, sizeof kp);
        memset(psk, 0, sizeof psk);
    }

    // ---------------------------------------------------------------- engine.cpp: lifecycle, loop
    void setState(int s);
    void wake();
    void drainWake();
    UdpSocket* sockFor(const Addr& a) { return a.v6 ? s6.get() : s4.get(); }
    bool haveSocket() const { return s4 || s6; }
    bool openSocketLocked();
    void resetFragStatsLocked();
    void closeTunLocked();
    void resetRuntimeLocked();
    void startThreadLocked();
    void stopThread();
    void failLocked(const std::string& why);
    void failTunLocked(const std::string& why);
    void loop();
    void tick(uint64_t now);
    void stunKeepalive(uint64_t now);
    void onStun(const uint8_t* b, size_t n);
    bool engineActive() const;  // packets from the network are processed
    bool tunAttached() const { return tunFd >= 0; }
    void sendPokes(uint64_t now);

    // ---------------------------------------------------------------- engine_net.cpp: sessions, sending, handshakes
    uint32_t newIdx();
    struct Found {
        Peer* peer = nullptr;
        GuestSess* guest = nullptr;
        Session* sess = nullptr;
    };
    Found findSession(uint32_t idx);
    Session* bestSession(Peer* p, uint64_t now);
    Session* allocSession(Peer* p);
    void expireSessions(Peer* p, uint64_t now);
    bool pathFresh(const Peer* p, uint64_t now) const { return p->addrValid && now - p->addrMs < 30000; }
    // What the pings (see sendPing) have shown about the two ways to a member: the direct one answered recently
    // ("fresh": at most one answer missing), the direct one answered not long ago, the one through the creator answered.
    uint64_t pathOkMs() const { return (uint64_t)cfg.pingMs * 3; }
    uint64_t pathFreshMs() const { return (uint64_t)cfg.pingMs * 2 + 400; }
    bool directFresh(const Peer* p, uint64_t now) const { return p->directEchoMs && now - p->directEchoMs < pathFreshMs(); }
    bool directOk(const Peer* p, uint64_t now) const { return p->directEchoMs && now - p->directEchoMs < pathOkMs(); }
    bool relayOk(const Peer* p, uint64_t now) const { return p->relayEchoMs && now - p->relayEchoMs < pathOkMs(); }
    const KeyPair& keyFor(const Peer* p) const { return p->guestMode ? grp.guest : kp; }
    // static-static DH of `me` and the peer's key, computed once per pair (null when the DH fails)
    const uint8_t* sharedStatic(Peer* p, const KeyPair& me);

    bool wouldBlock(int e) const;
    void noteTxError(const Addr& to, int e);
    void sendRaw(const Addr& to, const uint8_t* b, size_t n);
    void flushOut();
    void sendCands(Peer* p, const uint8_t* b, size_t n, const Addr* skip);
    void sendDirect(Peer* p, const uint8_t* b, size_t n, uint64_t now, bool control);
    bool canRelay(Peer* p, uint64_t now);
    void sendViaCreator(Peer* p, const uint8_t* b, size_t n, uint64_t now);
    void routeOut(Peer* p, const uint8_t* b, size_t n, uint64_t now, bool control);
    void reply(Peer* p, const Route& to, const uint8_t* b, size_t n, uint64_t now);  // answer on the path a request took
    size_t seal(Session* s, const uint8_t* plain, size_t plen, uint8_t* out);
    void sendTransport(Peer* p, Session* s, const uint8_t* plain, size_t plen, uint64_t now, bool control = false);
    void sendKeepalive(Peer* p, Session* s, uint64_t now);
    void sendPing(Peer* p, Session* s, uint64_t now);
    void sendBye(uint64_t now);
    void sendPunch(Peer* p, uint64_t now);
    void sendHandshake(Peer* p, const uint8_t* b, size_t n, uint64_t now);
    void updatePath(Peer* p, const Route& src, uint64_t now);
    void newInitiation(Peer* p, uint64_t now);
    void probe(Peer* p, uint64_t now);
    void rekey(Peer* p, Session* cur, uint64_t now);
    void peerTick(Peer* p, uint64_t now, uint64_t& due);
    void authFailed(const char* what, uint64_t now);

    void readUdp(UdpSocket* us, uint64_t now);
    void onUdp(const uint8_t* b, size_t n, const Addr& src, uint64_t now);
    void onDatagram(const uint8_t* b, size_t n, const Route& src, uint64_t now, bool nested);
    void onPunch(const uint8_t* b, size_t n, const Route& src);
    void onMsg1(const uint8_t* b, size_t n, const Route& src, uint64_t now);
    bool onMsg1Peer(Peer* p, const uint8_t* b, size_t n, const uint8_t* es, const Route& src, uint64_t now);
    bool onMsg1Guest(const uint8_t* b, size_t n, const uint8_t* es, const Route& src, uint64_t now);
    const uint8_t* guestShared();
    void onMsg2(const uint8_t* b, size_t n, const Route& src, uint64_t now);
    void onData(const uint8_t* b, size_t n, const Route& src, uint64_t now, bool nested);
    void handlePlain(Peer* p, Session* s, const uint8_t* plain, size_t n, const Route& src, uint64_t now, bool nested);
    void markConnected(Peer* p, const Route& src, uint64_t now);

    // ---------------------------------------------------------------- engine_group.cpp: peers, groups, relay, profile
    Peer* peerBySlot(int slot);
    Peer* peerByPub(const uint8_t* pub);
    Peer* peerBySid(const uint8_t* sid);
    Peer* creatorPeer();
    Peer* addPeer(int slot, const Offer& o, const std::vector<uint8_t>& blob, uint64_t now);
    void removePeer(int slot, const char* why);
    void sweepDoomed();
    void filterCands(Peer* p);
    void rebuildNets();
    std::string layoutText() const;
    Peer* ownerOf4(uint32_t ip);
    Peer* ownerOf6(const Ip6& a);
    bool isMyAddr(const Peer* p, uint32_t ip) const;
    bool isMyAddr6(const Peer* p, const Ip6& a) const;
    bool isPeerAddr(const Peer* p, uint32_t ip) const;
    bool isPeerAddr6(const Peer* p, const Ip6& a) const;
    bool memberListSettled() const;
    int presentPeers() const;
    int connectedPeers(uint64_t now, uint64_t freshMs) const;

    void groupTick(uint64_t now);
    void sendJoin(uint64_t now);
    void onJoin(GuestSess* g, const uint8_t* plain, size_t n, uint64_t now);
    void sendGuest(GuestSess* g, const std::vector<uint8_t>& plain, uint64_t now);
    void onWelcome(Peer* p, const uint8_t* plain, size_t n, uint64_t now);
    void onReject(Peer* p, const uint8_t* plain, size_t n);
    void onMember(Peer* p, const uint8_t* plain, size_t n, uint64_t now);
    void onMemberAck(Peer* p, const uint8_t* plain, size_t n);
    void onRelay(Peer* p, const uint8_t* plain, size_t n, uint64_t now, bool nested);
    void syncTick(Peer* p, Session* cur, uint64_t now);
    void bumpEntry(int slot, bool present, const uint8_t* pub, const std::vector<uint8_t>& blob);
    void profileTick(Peer* p, Session* cur, uint64_t now);
    void onProfile(Peer* p, Session* s, const uint8_t* plain, size_t n, uint64_t now);
    void onAvatar(Peer* p, Session* s, const uint8_t* plain, size_t n, uint64_t now);
    void onProfileAck(Peer* p, const uint8_t* plain, size_t n);
    void resetProfileOut();
    std::string membersText();
    std::string displayName(const Peer* p) const;
    void learnLl6(const Ip6& a, int slot, uint64_t now);
    Peer* lookupLl6(const Ip6& a, uint64_t now);

    // ---------------------------------------------------------------- engine_tun.cpp: TUN side, flows
    static bool inVec(const std::vector<uint32_t>& v, uint32_t x);
    static bool inVec6(const std::vector<Ip6>& v, const Ip6& x);
    static Ip6 srcOf6(const uint8_t* ip);
    static Ip6 dstOf6(const uint8_t* ip);
    void resetFlowsLocked();
    static uint16_t serviceOf(uint16_t a, uint16_t b) { return a < b ? a : b; }
    void recordFlow(PktRec r, uint16_t svc, bool isFrag, size_t tot);
    void noteFlow(char dir, const uint8_t* ip, size_t tot);
    void noteFlow6(char dir, const uint8_t* ip, size_t tot);
    static uint64_t assocKey(uint16_t lport, uint32_t rip, uint16_t rport);
    void noteUdpIn(Peer* from, const uint8_t* ip, size_t tot);
    void fixUdpOut(uint8_t* ip, size_t tot, uint64_t now);
    void gcAssoc(uint64_t now);
    bool writeTun(const uint8_t* ip, size_t tot);
    void deliverIp(Peer* from, const uint8_t* ip, size_t len);
    void deliverIp6(Peer* from, const uint8_t* ip, size_t len);
    void readTun(uint64_t now, short revents);
    static constexpr unsigned kMssCap = 1240;
    void clampMss(uint8_t* p, size_t tot, size_t l4);
    bool sendIp(Peer* to, Session* cur, const uint8_t* p, size_t tot, uint64_t now);
    void onTunPacket(uint8_t* p, size_t n, uint64_t now);
    void onTunPacket6(uint8_t* p, size_t n, uint64_t now);
    // Sends one packet from the TUN to one peer (source rewriting, MSS clamp, statistics).
    bool toPeer4(Peer* to, const uint8_t* pkt, size_t tot, size_t ihl, bool unicast, uint64_t now);
    bool toPeer6(Peer* to, const uint8_t* pkt, size_t tot, const Ip6Info& in, uint64_t now);
};

}  // namespace lb
