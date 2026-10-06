// LanBridge native core: tunnel engine (UDP socket, STUN, hole punching, handshake, TUN <-> network pump).
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "offer.h"

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
};

// Layout of the int64 array returned by Engine::status()
//  0 state            1 rxBytes          2 txBytes        3 rxPkts        4 txPkts
//  5 rttMs (-1)       6 sinceRxMs (-1)   7 connectedSec   8 pathLocal(-1/0/1)
//  9 bcastTx         10 bcastRx         11 mcastTx       12 mcastRx
// 13 authFail        14 punchRx         15 hsRx          16 dropped      17 mappingChanged
// 18 myNat           19 peerNat         20 myExpiresAt   21 handshakes   22 peerLeft
constexpr int STATUS_FIELDS = 24;

class Engine {
public:
    Engine();
    ~Engine();

    void setConfig(const Config& c);

    // Opens the UDP socket, asks STUN servers for the public address and creates a one-time identity.
    // Returns 0 and fills offerOut on success; 1 socket error, 2 no usable address, 3 busy.
    int prepare(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                const std::string& deviceName, int ttlSec, std::vector<uint8_t>& offerOut);

    // Decodes a friend's code; returns an OfferError code and fills "key=value" lines.
    int describe(const std::vector<uint8_t>& blob, std::string& textOut);
    int setPeer(const std::vector<uint8_t>& blob);
    bool layout(Layout& out);

    // Takes ownership of tunFd (closed on failure). 0 = started.
    int start(int tunFd, int mtu);
    void retry();
    void stop();

    void status(int64_t out[STATUS_FIELDS]);
    std::string info();
    // Diagnostics: drop reasons and the busiest flows crossing the tunnel (text, one item per line).
    std::string flows();
    std::string lastError();
    int socketFd();
    uint16_t localPort();

private:
    struct Impl;
    std::unique_ptr<Impl> p_;
    void stopInternal();
};

}  // namespace lb
