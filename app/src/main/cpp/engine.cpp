#include "engine.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <deque>
#include <unordered_map>
#include <cstring>
#include <mutex>
#include <thread>

#include "crypto.h"
#include "protocol.h"
#include "stun.h"
#include "util.h"

namespace lb {

namespace {

const int kMaxSessions = 4;

sockaddr_in mkAddr(uint32_t ipHost, uint16_t port) {
    sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(ipHost);
    return a;
}

bool sameAddr(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

std::string addrStr(const sockaddr_in& a) {
    return strfmt("%s:%u", ipStr(ntohl(a.sin_addr.s_addr)).c_str(), (unsigned)ntohs(a.sin_port));
}

bool offerExpired(const Offer& o) { return wallMs() / 1000 > (uint64_t)o.expiresAt + 120; }

const char* stateName(int s) {
    switch (s) {
        case ST_IDLE: return "IDLE";
        case ST_PREPARING: return "PREPARING";
        case ST_READY: return "READY";
        case ST_CONNECTING: return "CONNECTING";
        case ST_CONNECTED: return "CONNECTED";
        case ST_STALLED: return "STALLED";
        case ST_FAILED: return "FAILED";
    }
    return "?";
}

}  // namespace

struct Engine::Impl {
    Config cfg;
    std::mutex mu;      // protects every field below
    std::mutex lifeMu;  // serialises prepare()/stop()
    std::atomic<int> state{ST_IDLE};
    std::string lastErr;

    int sock = -1;
    uint16_t localPort = 0;
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

    // peer
    bool havePeer = false;
    Offer peer;
    Layout lay;
    bool initiator = false;
    uint8_t sid[8];
    uint8_t psk[32];  // always zero: peers authenticate each other with the keys from the exchanged codes

    // runtime
    int tunFd = -1;
    int mtu = 1280;
    uint64_t connectStartMs = 0, connectedSinceMs = 0;
    uint64_t nextTickMs = 0, nextProbeMs = 0, nextPingMs = 0, nextRekeyMs = 0;
    uint64_t lastTxMs = 0, lastRxMs = 0;
    uint64_t lastTsSent = 0, lastInitTs = 0;
    Session sess[kMaxSessions];
    HsInit pend;
    bool haveLast = false;
    uint8_t lastMsg1[MSG1_LEN];
    uint8_t lastMsg2[MSG2_LEN];
    sockaddr_in peerAddr;
    bool peerAddrValid = false;
    uint64_t peerAddrMs = 0;
    bool peerLeft = false;
    std::vector<sockaddr_in> punchSeen;
    uint64_t lastAuthLogMs = 0;

    // statistics
    uint64_t rxBytes = 0, txBytes = 0, rxPkts = 0, txPkts = 0;
    uint64_t bcastTx = 0, bcastRx = 0, mcastTx = 0, mcastRx = 0;
    uint64_t authFail = 0, punchRx = 0, hsRx = 0, dropped = 0, handshakes = 0;
    int64_t rttMs = -1;

    // diagnostics
    uint64_t dropForeignDst = 0, dropNoSession = 0, dropBadHdr = 0, dropRxSrc = 0, dropRxDst = 0, tunWriteErr = 0;
    uint64_t udpQueued = 0, udpDropped = 0;
    // Flows are aggregated by (direction, protocol, addresses, service port) so that many short-lived connections of
    // one service share one entry. T: forwarded to the peer, R: delivered to the TUN, X/Y: dropped (TUN / peer side).
    struct Flow {
        char dir;
        uint8_t proto;
        uint32_t sip, dip;
        uint16_t svc;  // TCP/UDP: the lower port of the pair; ICMP: the type
        uint64_t pkts, bytes;
        uint16_t maxLen;
        uint32_t syn, synack, rst, fin, frags;
        uint64_t firstMs, lastMs;  // relative to flowEpochMs
    };
    struct PktRec {
        uint32_t tMs;
        char dir;
        uint8_t proto, tcpFlags, ipFlags;
        uint32_t sip, dip;
        uint16_t sport, dport, len;
    };
    std::vector<Flow> flowTab;
    uint64_t flowOverflow = 0;
    uint64_t selftestPkts = 0;  // the app's own "Проверка LAN" traffic (port 41377) is counted but not listed
    uint64_t flowEpochMs = 0;
    std::vector<PktRec> headRing;  // the first packets after a reset
    PktRec tailRing[96];           // the most recent packets
    size_t tailCount = 0;

    // UDP source fixup (what IP_PKTINFO would give a server): the system picks the first address of the TUN as the
    // source of everything that leaves through it, but a reply must come from the very address the peer used. So the
    // engine remembers, per (local port, peer address, peer port), which of our addresses a datagram was sent to and
    // puts that address on the replies.
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
        sockaddr_in to;
        uint16_t len;
        uint8_t data[2048];
    };
    std::deque<OutPkt> outq;

    Impl() {
        memset(&kp, 0, sizeof kp);
        memset(sid, 0, sizeof sid);
        memset(psk, 0, sizeof psk);
        memset(&peerAddr, 0, sizeof peerAddr);
        memset(lastMsg1, 0, sizeof lastMsg1);
        memset(lastMsg2, 0, sizeof lastMsg2);
    }

    // ------------------------------------------------------------ helpers
    void setState(int s) {
        int old = state.exchange(s);
        if (old != s) LBLOG("состояние: %s -> %s", stateName(old), stateName(s));
    }

    void wake() {
        if (wakeFd[1] >= 0) {
            uint8_t b = 1;
            ssize_t r = write(wakeFd[1], &b, 1);
            (void)r;
        }
    }

    void drainWake() {
        uint8_t b[64];
        while (read(wakeFd[0], b, sizeof b) > 0) {
        }
    }

    bool openSocketLocked() {
        if (sock >= 0) return true;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            lastErr = strfmt("socket: %s", strerror(errno));
            return false;
        }
        int fl = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, fl | O_NONBLOCK);
        fcntl(s, F_SETFD, FD_CLOEXEC);
        int buf = 4 << 20;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
        setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
        sockaddr_in a = mkAddr(0, 0);
        if (bind(s, (const sockaddr*)&a, sizeof a) < 0) {
            lastErr = strfmt("bind: %s", strerror(errno));
            close(s);
            return false;
        }
        socklen_t al = sizeof a;
        getsockname(s, (sockaddr*)&a, &al);
        localPort = ntohs(a.sin_port);
        if (wakeFd[0] < 0) {
            if (pipe(wakeFd) < 0) {
                lastErr = strfmt("pipe: %s", strerror(errno));
                close(s);
                wakeFd[0] = wakeFd[1] = -1;
                return false;
            }
            for (int i = 0; i < 2; i++) {
                fcntl(wakeFd[i], F_SETFL, fcntl(wakeFd[i], F_GETFL, 0) | O_NONBLOCK);
                fcntl(wakeFd[i], F_SETFD, FD_CLOEXEC);
            }
        }
        sock = s;
        return true;
    }

    void closeTunLocked() {
        if (tunFd >= 0) {
            close(tunFd);
            tunFd = -1;
        }
    }

    void resetRuntimeLocked() {
        for (Session& s : sess) s.clear();
        pend.wipe();
        havePeer = false;
        peerAddrValid = false;
        peerLeft = false;
        haveLast = false;
        lastInitTs = lastTsSent = 0;
        punchSeen.clear();
        rxBytes = txBytes = rxPkts = txPkts = 0;
        bcastTx = bcastRx = mcastTx = mcastRx = 0;
        authFail = punchRx = hsRx = dropped = handshakes = 0;
        dropForeignDst = dropNoSession = dropBadHdr = dropRxSrc = dropRxDst = tunWriteErr = 0;
        udpQueued = udpDropped = 0;
        resetFlowsLocked();
        outq.clear();
        udpAssoc.clear();
        fragFix.clear();
        udpFixups = 0;
        rttMs = -1;
        lastRxMs = lastTxMs = 0;
        connectStartMs = connectedSinceMs = 0;
        nextProbeMs = nextPingMs = nextRekeyMs = 0;
        closeTunLocked();
    }

    void startThreadLocked() {
        if (th.joinable()) return;
        running = true;
        th = std::thread([this] { loop(); });
    }

    void stopThread() {  // must be called without holding mu
        if (!th.joinable()) return;
        running = false;
        wake();
        th.join();
    }

    uint32_t newIdx() {
        for (;;) {
            uint32_t v;
            randomBytes(&v, sizeof v);
            if (v == 0) continue;
            bool used = pend.active && pend.localIdx == v;
            for (const Session& s : sess)
                if (s.valid && s.localIdx == v) used = true;
            if (!used) return v;
        }
    }

    Session* findSession(uint32_t idx) {
        for (Session& s : sess)
            if (s.valid && s.localIdx == idx) return &s;
        return nullptr;
    }

    Session* bestSession(uint64_t now) {
        Session* best = nullptr;
        for (Session& s : sess) {
            if (!s.valid || !s.confirmed) continue;
            if (now - s.createdMs >= (uint64_t)cfg.rejectAfterMs) continue;
            if (!best || s.createdMs > best->createdMs) best = &s;
        }
        return best;
    }

    Session* allocSession() {
        for (Session& s : sess)
            if (!s.valid) return &s;
        Session* oldest = &sess[0];
        for (Session& s : sess)
            if (s.createdMs < oldest->createdMs) oldest = &s;
        oldest->clear();
        return oldest;
    }

    void expireSessions(uint64_t now) {
        for (Session& s : sess)
            if (s.valid && now - s.createdMs >= (uint64_t)cfg.rejectAfterMs) s.clear();
    }

    bool pathFresh(uint64_t now) const { return peerAddrValid && now - peerAddrMs < 30000; }

    void failLocked(const std::string& why) {
        lastErr = why;
        LBLOG("ошибка: %s", why.c_str());
        setState(ST_FAILED);
    }

    void failTunLocked(const std::string& why) {
        closeTunLocked();
        failLocked(why);
    }

    // ------------------------------------------------------------ sending
    void sendRaw(const sockaddr_in& to, const uint8_t* b, size_t n) {
        if (sock < 0 || n > sizeof(OutPkt::data)) return;
        if (outq.empty()) {
            ssize_t r = sendto(sock, b, n, MSG_DONTWAIT, (const sockaddr*)&to, sizeof to);
            if (r >= 0) return;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS) return;
        }
        if (outq.size() >= 2048) {
            udpDropped++;
            return;
        }
        OutPkt p;
        p.to = to;
        p.len = (uint16_t)n;
        memcpy(p.data, b, n);
        outq.push_back(p);
        udpQueued++;
    }

    void flushOut() {
        while (!outq.empty()) {
            const OutPkt& p = outq.front();
            ssize_t r = sendto(sock, p.data, p.len, MSG_DONTWAIT, (const sockaddr*)&p.to, sizeof p.to);
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) break;
            outq.pop_front();
        }
    }

    void sendToCands(const uint8_t* b, size_t n, const sockaddr_in* skip) {
        for (const Candidate& c : peer.cands) {
            sockaddr_in a = mkAddr(c.ip, c.port);
            if (skip && sameAddr(a, *skip)) continue;
            sendRaw(a, b, n);
        }
    }

    void sendToPeer(const uint8_t* b, size_t n, uint64_t now) {
        bool fresh = pathFresh(now);
        if (fresh) sendRaw(peerAddr, b, n);
        if (!fresh || !lastRxMs || now - lastRxMs > 8000) sendToCands(b, n, fresh ? &peerAddr : nullptr);
    }

    void sendHandshake(const uint8_t* b, size_t n) {
        sendToCands(b, n, peerAddrValid ? &peerAddr : nullptr);
        if (peerAddrValid) sendRaw(peerAddr, b, n);
    }

    void sendPunch() {
        uint8_t p[PUNCH_LEN];
        p[0] = T_PUNCH;
        memcpy(p + 1, sid, 8);
        randomBytes(p + 9, 4);
        sendHandshake(p, PUNCH_LEN);
    }

    void sendTransport(Session* s, const uint8_t* plain, size_t plen, uint64_t now) {
        if (plen > MAX_PLAIN) return;
        uint8_t out[DATA_HDR + MAX_PLAIN + AEAD_TAG];
        out[0] = T_DATA;
        putLe32(out + 1, s->remoteIdx);
        putLe64(out + 5, s->sendCtr);
        crypto::aeadEncrypt(out + DATA_HDR, s->sendKey, s->sendCtr, nullptr, 0, plain, plen);
        s->sendCtr++;
        sendToPeer(out, DATA_HDR + plen + AEAD_TAG, now);
        lastTxMs = now;
    }

    void sendKeepalive(Session* s, uint64_t now) { sendTransport(s, nullptr, 0, now); }

    void sendPing(Session* s, uint64_t now) {
        uint8_t p[10];
        p[0] = K_CTRL;
        p[1] = C_PING;
        putBe64(p + 2, now);
        sendTransport(s, p, sizeof p, now);
    }

    void sendBye(uint64_t now) {
        Session* s = bestSession(now);
        if (!s) return;
        uint8_t b = K_BYE;
        sendTransport(s, &b, 1, now);
        sendTransport(s, &b, 1, now);
    }

    void updatePath(const sockaddr_in& src, uint64_t now) {
        if (!peerAddrValid || !sameAddr(src, peerAddr)) {
            LBLOG("путь до друга: %s", addrStr(src).c_str());
            peerAddr = src;
        }
        peerAddrValid = true;
        peerAddrMs = now;
    }

    // ------------------------------------------------------------ handshake driving
    void newInitiation(uint64_t now) {
        uint64_t ts = wallMs();
        if (ts <= lastTsSent) ts = lastTsSent + 1;
        lastTsSent = ts;
        pend.wipe();
        uint32_t idx = newIdx();
        if (!hsCreateInitiation(pend, kp, peer.pub, ts, idx)) {
            pend.active = false;
            LBLOG("handshake: не удалось создать запрос");
            return;
        }
        pend.createdMs = now;
    }

    void probe(uint64_t now) {
        if (now < nextProbeMs) return;
        uint64_t el = now - connectStartMs;
        nextProbeMs = now + (uint64_t)(el < (uint64_t)cfg.probeSlowAfterMs ? cfg.probeIntervalMs : cfg.probeSlowIntervalMs);
        if (initiator) {
            if (!pend.active || now - pend.createdMs >= (uint64_t)cfg.hsRefreshMs) newInitiation(now);
            if (pend.active) sendHandshake(pend.msg1, MSG1_LEN);
        } else {
            sendPunch();
        }
    }

    void rekey(Session* cur, uint64_t now) {
        if (now - cur->createdMs < (uint64_t)cfg.rekeyAfterMs) return;
        if (now < nextRekeyMs) return;
        nextRekeyMs = now + 1000;
        if (!pend.active || now - pend.createdMs >= (uint64_t)cfg.hsRefreshMs) newInitiation(now);
        if (pend.active) sendToPeer(pend.msg1, MSG1_LEN, now);
    }

    void stunKeepalive(uint64_t now) {
        stunPend.erase(std::remove_if(stunPend.begin(), stunPend.end(),
                                      [now](const StunPend& p) { return now - p.sentMs > 8000; }),
                       stunPend.end());
        int sent = 0;
        for (size_t i = 0; i < stun.size() && sent < 2; i++) {
            if (!stun[i].ok) continue;
            StunPend p;
            randomBytes(p.txid, 12);
            p.srv = i;
            p.sentMs = now;
            uint8_t req[20];
            stunBuildRequest(req, p.txid);
            sendRaw(stun[i].addr, req, sizeof req);
            stunPend.push_back(p);
            sent++;
        }
    }

    // ------------------------------------------------------------ main loop
    void loop() {
        while (running.load()) {
            int timeout;
            int tfd;
            bool wantOut = false;
            {
                std::lock_guard<std::mutex> g(mu);
                wantOut = !outq.empty();
                int64_t t = (int64_t)nextTickMs - (int64_t)nowMs();
                if (t < 0) t = 0;
                if (t > 1000) t = 1000;
                timeout = (int)t;
                tfd = tunFd;
            }
            pollfd fds[3];
            int nf = 0, ti = -1;
            fds[nf++] = pollfd{sock, (short)(POLLIN | (wantOut ? POLLOUT : 0)), 0};
            fds[nf++] = pollfd{wakeFd[0], POLLIN, 0};
            if (tfd >= 0) {
                ti = nf;
                fds[nf++] = pollfd{tfd, POLLIN, 0};
            }
            int r = poll(fds, (nfds_t)nf, timeout);
            if (r < 0 && errno != EINTR) usleep(10000);
            std::lock_guard<std::mutex> g(mu);
            if (!running.load()) break;
            uint64_t now = nowMs();
            if (r > 0) {
                if (fds[1].revents & POLLIN) drainWake();
                if (fds[0].revents & POLLOUT) flushOut();
                if (fds[0].revents & POLLIN) readUdp(now);
                if (ti >= 0 && tunFd == tfd && fds[ti].revents) readTun(now, fds[ti].revents);
            }
            if (!outq.empty()) flushOut();
            tick(now);
        }
    }

    void tick(uint64_t now) {
        gcAssoc(now);
        uint64_t due = now + 1000;
        int st = state.load();
        if (st == ST_READY) {
            if (now >= nextStunMs) {
                stunKeepalive(now);
                nextStunMs = now + (uint64_t)cfg.stunKeepMs;
            }
            due = nextStunMs;
        } else if (st == ST_CONNECTING || st == ST_CONNECTED || st == ST_STALLED) {
            expireSessions(now);
            Session* cur = bestSession(now);
            if (!cur) {
                if (st != ST_CONNECTING) {
                    setState(ST_CONNECTING);
                    connectStartMs = now;
                    nextProbeMs = 0;
                }
                if (now - connectStartMs >= (uint64_t)cfg.connectTimeoutMs) {
                    failLocked("друг не ответил за отведённое время");
                } else {
                    probe(now);
                    due = std::min(due, std::max(nextProbeMs, now + 1));
                }
            } else {
                bool fresh = lastRxMs && now - lastRxMs < (uint64_t)cfg.stallMs;
                if (!fresh && st == ST_CONNECTED) setState(ST_STALLED);
                if (now - lastTxMs >= (uint64_t)cfg.keepaliveMs) sendKeepalive(cur, now);
                if (now >= nextPingMs) {
                    sendPing(cur, now);
                    nextPingMs = now + (uint64_t)cfg.pingMs;
                }
                if (initiator) rekey(cur, now);
                if (lastRxMs && now - lastRxMs > 8000 && now >= nextProbeMs) {
                    sendPunch();
                    nextProbeMs = now + 3000;
                }
                due = now + 500;
            }
        }
        nextTickMs = due;
    }

    // ------------------------------------------------------------ receiving: UDP
    void readUdp(uint64_t now) {
        uint8_t buf[2600];
        for (int i = 0; i < 256; i++) {
            sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t n = recvfrom(sock, buf, sizeof buf, MSG_DONTWAIT, (sockaddr*)&from, &fl);
            if (n < 0) break;
            if (n == 0) continue;
            onUdp(buf, (size_t)n, from, now);
        }
    }

    void onUdp(const uint8_t* b, size_t n, const sockaddr_in& src, uint64_t now) {
        if (stunIsMessage(b, n)) {
            onStun(b, n);
            return;
        }
        int st = state.load();
        if (st < ST_CONNECTING || st > ST_STALLED) return;
        switch (b[0]) {
            case T_PUNCH: onPunch(b, n, src); break;
            case T_MSG1: onMsg1(b, n, src, now); break;
            case T_MSG2: onMsg2(b, n, src, now); break;
            case T_DATA: onData(b, n, src, now); break;
            default: break;
        }
    }

    void onStun(const uint8_t* b, size_t n) {
        if (state.load() != ST_READY) return;
        uint8_t tx[12];
        if (!stunGetTxid(b, n, tx)) return;
        for (size_t i = 0; i < stunPend.size(); i++) {
            if (memcmp(stunPend[i].txid, tx, 12) != 0) continue;
            size_t si = stunPend[i].srv;
            stunPend.erase(stunPend.begin() + (long)i);
            StunAddr m;
            if (si < stun.size() && stunParseResponse(b, n, tx, m)) {
                StunServer& s = stun[si];
                if (s.ok && (s.mapped.ip != m.ip || s.mapped.port != m.port)) {
                    mappingChanged = true;
                    LBLOG("STUN: внешний адрес изменился %s:%u -> %s:%u", ipStr(s.mapped.ip).c_str(),
                          (unsigned)s.mapped.port, ipStr(m.ip).c_str(), (unsigned)m.port);
                    s.mapped = m;
                }
            }
            return;
        }
    }

    void onPunch(const uint8_t* b, size_t n, const sockaddr_in& src) {
        if (!havePeer || n != PUNCH_LEN || memcmp(b + 1, sid, 8) != 0) return;
        punchRx++;
        bool seen = false;
        for (const sockaddr_in& a : punchSeen)
            if (sameAddr(a, src)) seen = true;
        if (!seen && punchSeen.size() < 8) {
            punchSeen.push_back(src);
            LBLOG("получен пробный пакет от %s", addrStr(src).c_str());
        }
        if (initiator && pend.active && !bestSession(nowMs())) sendRaw(src, pend.msg1, MSG1_LEN);
    }

    void authFailed(const char* what, uint64_t now) {
        authFail++;
        if (now - lastAuthLogMs > 3000) {
            lastAuthLogMs = now;
            LBLOG("пакет не прошёл проверку (%s): пароль или код не совпадают", what);
        }
    }

    void onMsg1(const uint8_t* b, size_t n, const sockaddr_in& src, uint64_t now) {
        if (!havePeer || initiator || n != MSG1_LEN) return;
        if (haveLast && memcmp(b, lastMsg1, MSG1_LEN) == 0) {  // retransmission: repeat the same answer
            sendRaw(src, lastMsg2, MSG2_LEN);
            return;
        }
        HsRespIn in;
        if (!hsConsumeInitiation(b, n, kp, peer.pub, in)) {
            authFailed("запрос", now);
            return;
        }
        if (in.ts <= lastInitTs) {
            dropped++;
            return;
        }
        lastInitTs = in.ts;
        uint32_t idx = newIdx();
        TransportKeys keys;
        uint8_t m2[MSG2_LEN];
        if (!hsCreateResponse(in, kp, peer.pub, psk, idx, m2, keys)) return;
        Session* s = allocSession();
        s->clear();
        s->valid = true;
        s->confirmed = false;
        s->initiator = false;
        s->localIdx = idx;
        s->remoteIdx = in.senderIdx;
        memcpy(s->sendKey, keys.send, 32);
        memcpy(s->recvKey, keys.recv, 32);
        s->createdMs = now;
        s->lastRxMs = now;
        crypto::wipe(&keys, sizeof keys);
        memcpy(lastMsg1, b, MSG1_LEN);
        memcpy(lastMsg2, m2, MSG2_LEN);
        haveLast = true;
        hsRx++;
        updatePath(src, now);
        sendRaw(src, m2, MSG2_LEN);
        LBLOG("получен запрос соединения от %s", addrStr(src).c_str());
    }

    void onMsg2(const uint8_t* b, size_t n, const sockaddr_in& src, uint64_t now) {
        if (!havePeer || !initiator || !pend.active || n != MSG2_LEN) return;
        uint32_t myIdx = pend.localIdx;
        uint32_t remoteIdx = 0;
        TransportKeys keys;
        if (!hsConsumeResponse(pend, b, n, kp, psk, remoteIdx, keys)) {
            if (le32(b + 5) == myIdx) authFailed("ответ", now);
            return;
        }
        Session* s = allocSession();
        s->clear();
        s->valid = true;
        s->confirmed = true;
        s->initiator = true;
        s->localIdx = myIdx;
        s->remoteIdx = remoteIdx;
        memcpy(s->sendKey, keys.send, 32);
        memcpy(s->recvKey, keys.recv, 32);
        s->createdMs = now;
        s->lastRxMs = now;
        crypto::wipe(&keys, sizeof keys);
        hsRx++;
        handshakes++;
        lastRxMs = now;
        updatePath(src, now);
        if (state.load() != ST_CONNECTED) {
            if (!connectedSinceMs) connectedSinceMs = now;
            setState(ST_CONNECTED);
            LBLOG("соединение установлено (%s)", addrStr(src).c_str());
        }
        peerLeft = false;
        sendKeepalive(s, now);  // confirms the new keys to the responder
    }

    void onData(const uint8_t* b, size_t n, const sockaddr_in& src, uint64_t now) {
        if (n < DATA_HDR + AEAD_TAG) return;
        Session* s = findSession(le32(b + 1));
        if (!s) {
            dropped++;
            return;
        }
        uint64_t ctr = le64(b + 5);
        if (!s->replay.check(ctr)) {
            dropped++;
            return;
        }
        size_t plen = n - DATA_HDR - AEAD_TAG;
        if (plen > MAX_PLAIN) return;
        uint8_t plain[MAX_PLAIN + 1];
        if (!crypto::aeadDecrypt(plain, s->recvKey, ctr, nullptr, 0, b + DATA_HDR, n - DATA_HDR)) {
            authFailed("данные", now);
            return;
        }
        s->replay.update(ctr);
        s->lastRxMs = now;
        lastRxMs = now;
        if (!s->confirmed) {
            s->confirmed = true;
            handshakes++;
        }
        updatePath(src, now);
        peerLeft = false;
        if (state.load() != ST_CONNECTED) {
            if (!connectedSinceMs) connectedSinceMs = now;
            setState(ST_CONNECTED);
            LBLOG("соединение установлено (%s)", addrStr(src).c_str());
        }
        handlePlain(s, plain, plen, now);
    }

    void handlePlain(Session* s, const uint8_t* p, size_t n, uint64_t now) {
        if (n == 0) return;  // keepalive
        switch (p[0]) {
            case K_IP: deliverIp(p + 1, n - 1); break;
            case K_CTRL:
                if (n >= 10 && p[1] == C_PING) {
                    uint8_t r[10];
                    memcpy(r, p, 10);
                    r[1] = C_PONG;
                    sendTransport(s, r, sizeof r, now);
                } else if (n >= 10 && p[1] == C_PONG) {
                    uint64_t t = be64(p + 2);
                    if (t <= now && now - t < 60000) rttMs = (int64_t)(now - t);
                }
                break;
            case K_BYE:
                peerLeft = true;
                if (state.load() == ST_CONNECTED) setState(ST_STALLED);
                LBLOG("друг отключился");
                break;
            default: break;
        }
    }

    // ------------------------------------------------------------ TUN side
    static bool inVec(const std::vector<uint32_t>& v, uint32_t x) {
        for (uint32_t y : v)
            if (y == x) return true;
        return false;
    }
    bool isPeerAddr(uint32_t ip) const { return ip == lay.peerIp || inVec(lay.aliasPeer, ip); }
    bool isMyAddr(uint32_t ip) const { return ip == lay.myIp || inVec(lay.aliasMine, ip); }

    void resetFlowsLocked() {
        flowTab.clear();
        flowOverflow = 0;
        selftestPkts = 0;
        headRing.clear();
        tailCount = 0;
        flowEpochMs = nowMs();
    }

    static uint16_t serviceOf(uint16_t a, uint16_t b) { return a < b ? a : b; }

    void noteFlow(char dir, const uint8_t* ip, size_t tot) {
        if (tot < 20) return;
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        uint8_t proto = ip[9];
        uint16_t fragField = be16(ip + 6);
        bool firstFrag = (fragField & 0x1FFF) == 0;
        bool isFrag = (fragField & 0x1FFF) != 0 || (fragField & 0x2000) != 0;
        uint16_t sp = 0, dp = 0, svc = 0;
        uint8_t tcpFlags = 0;
        if (firstFrag && (proto == 6 || proto == 17) && tot >= ihl + 4) {
            sp = be16(ip + ihl);
            dp = be16(ip + ihl + 2);
            if (sp == 41377 || dp == 41377) {
                selftestPkts++;
                return;
            }
            svc = serviceOf(sp, dp);
            if (proto == 6 && tot >= ihl + 14) tcpFlags = ip[ihl + 13];
        } else if (firstFrag && proto == 1 && tot >= ihl + 2) {
            svc = ip[ihl];
        }
        uint32_t s = be32(ip + 12), d = be32(ip + 16);
        uint64_t rel = nowMs() - flowEpochMs;

        PktRec r{(uint32_t)rel, dir, proto, tcpFlags, (uint8_t)(fragField >> 13), s, d, sp, dp, (uint16_t)(tot > 65535 ? 65535 : tot)};
        if (headRing.size() < 120) headRing.push_back(r);
        tailRing[tailCount % (sizeof tailRing / sizeof tailRing[0])] = r;
        tailCount++;

        Flow* f = nullptr;
        for (Flow& x : flowTab) {
            if (x.dir == dir && x.proto == proto && x.sip == s && x.dip == d && x.svc == svc) {
                f = &x;
                break;
            }
        }
        if (!f) {
            if (flowTab.size() >= 256) {
                // evict the smallest entry so that busy flows are never lost
                size_t victim = 0;
                for (size_t k = 1; k < flowTab.size(); k++)
                    if (flowTab[k].pkts < flowTab[victim].pkts) victim = k;
                flowTab.erase(flowTab.begin() + (long)victim);
                flowOverflow++;
            }
            flowTab.push_back(Flow{dir, proto, s, d, svc, 0, 0, 0, 0, 0, 0, 0, 0, rel, rel});
            f = &flowTab.back();
        }
        f->pkts++;
        f->bytes += tot;
        if (tot > f->maxLen) f->maxLen = (uint16_t)(tot > 65535 ? 65535 : tot);
        f->lastMs = rel;
        if (isFrag) f->frags++;
        if (proto == 6) {
            if ((tcpFlags & 0x02) && !(tcpFlags & 0x10)) f->syn++;
            else if ((tcpFlags & 0x02) && (tcpFlags & 0x10)) f->synack++;
            if (tcpFlags & 0x04) f->rst++;
            if (tcpFlags & 0x01) f->fin++;
        }
    }

    static uint64_t assocKey(uint16_t lport, uint32_t rip, uint16_t rport) {
        return ((uint64_t)lport << 48) | ((uint64_t)rport << 32) | rip;
    }

    // Incoming unicast UDP: remember which of our addresses the peer sent it to.
    void noteUdpIn(const uint8_t* ip, size_t tot) {
        if (ip[9] != 17) return;
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        if ((be16(ip + 6) & 0x1FFF) != 0 || tot < ihl + 8) return;
        uint32_t src = be32(ip + 12), dst = be32(ip + 16);
        if (!isMyAddr(dst)) return;
        uint64_t now = nowMs();
        if (udpAssoc.size() > 4096) udpAssoc.clear();
        udpAssoc[assocKey(be16(ip + ihl + 2), src, be16(ip + ihl))] = UdpAssoc{dst, now};
    }

    // Outgoing unicast UDP: make a reply come from the address the peer used (see udpAssoc).
    void fixUdpOut(uint8_t* ip, size_t tot, uint64_t now) {
        if (ip[9] != 17) return;
        uint16_t fragField = be16(ip + 6);
        uint32_t src = be32(ip + 12), dst = be32(ip + 16);
        if ((fragField & 0x1FFF) != 0) {  // a later fragment follows the decision taken for the first one
            uint16_t id = be16(ip + 4);
            for (const FragFix& f : fragFix) {
                if (f.expMs > now && f.src == src && f.dst == dst && f.id == id) {
                    ipRewriteSrc(ip, tot, f.newSrc);
                    return;
                }
            }
            return;
        }
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        if (tot < ihl + 8) return;
        auto it = udpAssoc.find(assocKey(be16(ip + ihl), dst, be16(ip + ihl + 2)));
        if (it == udpAssoc.end() || now - it->second.lastMs > 180000) return;
        uint32_t want = it->second.local;
        if (want == src) return;
        if (fragField & 0x2000) {
            if (fragFix.size() >= 64) fragFix.erase(fragFix.begin());
            fragFix.push_back(FragFix{src, dst, want, be16(ip + 4), now + 10000});
        }
        ipRewriteSrc(ip, tot, want);
        udpFixups++;
    }

    void gcAssoc(uint64_t now) {
        if (now - lastAssocGcMs < 30000) return;
        lastAssocGcMs = now;
        for (auto it = udpAssoc.begin(); it != udpAssoc.end();) {
            if (now - it->second.lastMs > 180000) it = udpAssoc.erase(it);
            else ++it;
        }
        fragFix.erase(std::remove_if(fragFix.begin(), fragFix.end(), [now](const FragFix& f) { return f.expMs <= now; }),
                      fragFix.end());
    }

    void deliverIp(const uint8_t* ip, size_t len) {
        if (tunFd < 0) return;
        if (len < 20 || (ip[0] >> 4) != 4) {
            dropped++;
            dropBadHdr++;
            return;
        }
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        size_t tot = be16(ip + 2);
        if (ihl < 20 || ihl > len || tot < ihl || tot > len) {
            dropped++;
            dropBadHdr++;
            return;
        }
        uint32_t src = be32(ip + 12), dst = be32(ip + 16);
        if (!isPeerAddr(src)) {
            dropped++;
            dropRxSrc++;
            noteFlow('Y', ip, tot);
            return;
        }
        bool bc = dst == 0xFFFFFFFFu || dst == lay.bcast;
        bool mc = (dst >> 28) == 0xE;
        if (!(isMyAddr(dst) || bc || mc)) {
            dropped++;
            dropRxDst++;
            noteFlow('Y', ip, tot);
            return;
        }
        noteUdpIn(ip, tot);
        ssize_t w = write(tunFd, ip, tot);
        if (w < 0) {
            dropped++;
            tunWriteErr++;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EINVAL && errno != EMSGSIZE &&
                errno != ENOBUFS)
                failTunLocked(strfmt("TUN write: %s", strerror(errno)));
            return;
        }
        noteFlow('R', ip, tot);
        rxPkts++;
        rxBytes += tot;
        if (bc) bcastRx++;
        if (mc) mcastRx++;
    }

    void readTun(uint64_t now, short revents) {
        uint8_t buf[4096];
        for (int i = 0; i < 256; i++) {
            ssize_t n = read(tunFd, buf, sizeof buf);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                failTunLocked(strfmt("TUN read: %s", strerror(errno)));
                return;
            }
            if (n == 0) {
                failTunLocked("TUN закрыт");
                return;
            }
            onTunPacket(buf, (size_t)n, now);
            if (tunFd < 0) return;
        }
        if ((revents & (POLLERR | POLLHUP | POLLNVAL)) && !(revents & POLLIN)) failTunLocked("TUN закрыт");
    }

    void onTunPacket(uint8_t* p, size_t n, uint64_t now) {
        if (n < 20 || (p[0] >> 4) != 4) return;  // IPv6 etc. is not routed into the tunnel
        size_t ihl = (size_t)(p[0] & 15) * 4;
        size_t tot = be16(p + 2);
        if (ihl < 20 || ihl > n || tot < ihl || tot > n) {
            dropBadHdr++;
            return;
        }
        if (p[9] == 2) return;  // IGMP stays local
        uint32_t dst = be32(p + 16);
        enum { UC, BC, MC } kind;
        if (isPeerAddr(dst)) kind = UC;
        else if (dst == 0xFFFFFFFFu || dst == lay.bcast) kind = BC;
        else if ((dst >> 28) == 0xE) kind = MC;
        else {
            dropped++;
            dropForeignDst++;
            noteFlow('X', p, tot);
            return;
        }
        Session* cur = bestSession(now);
        if (!cur) {
            dropped++;
            dropNoSession++;
            return;
        }
        // Packets keep their source when it is our virtual or a mirrored real address (replies then match what the
        // application expects); anything else is rewritten to the virtual address.
        if (!isMyAddr(be32(p + 12))) ipRewriteSrc(p, tot, lay.myIp);
        if (kind == UC) fixUdpOut(p, tot, now);
        uint8_t plain[MAX_PLAIN];
        if (tot + 1 > sizeof plain) return;
        plain[0] = K_IP;
        memcpy(plain + 1, p, tot);
        noteFlow('T', p, tot);
        sendTransport(cur, plain, tot + 1, now);
        txPkts++;
        txBytes += tot;
        if (kind == BC) bcastTx++;
        if (kind == MC) mcastTx++;
    }
};

// =====================================================================
// Public API
// =====================================================================

Engine::Engine() : p_(new Impl()) {}

Engine::~Engine() { stop(); }

void Engine::setConfig(const Config& c) {
    std::lock_guard<std::mutex> g(p_->mu);
    p_->cfg = c;
}

int Engine::prepare(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                    const std::string& deviceName, int ttlSec, std::vector<uint8_t>& offerOut) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> life(s.lifeMu);
    int st = s.state.load();
    if (st == ST_CONNECTING || st == ST_CONNECTED || st == ST_STALLED) return 3;
    if (st == ST_FAILED) stopInternal();

    s.stopThread();
    {
        std::lock_guard<std::mutex> g(s.mu);
        s.setState(ST_PREPARING);
        s.resetRuntimeLocked();
        s.haveIdentity = false;
        s.mappingChanged = false;
        s.stun.clear();
        s.stunPend.clear();
        s.lastErr.clear();
        if (!s.openSocketLocked()) {
            s.setState(ST_IDLE);
            return 1;
        }
    }

    std::vector<StunServer> servers = stunResolveAll(stunServers, 2500);
    int answered = stunGather(s.sock, servers, s.cfg.stunTimeoutMs);
    LBLOG("STUN: ответили %d из %d (запрошено %d)", answered, (int)servers.size(), (int)stunServers.size());

    std::lock_guard<std::mutex> g(s.mu);
    s.stun.clear();
    for (const StunServer& sv : servers)
        if (sv.ok) s.stun.push_back(sv);
    std::vector<StunAddr> distinct;
    for (const StunServer& sv : s.stun) {
        bool dup = false;
        for (const StunAddr& a : distinct)
            if (a.ip == sv.mapped.ip && a.port == sv.mapped.port) dup = true;
        if (!dup) distinct.push_back(sv.mapped);
    }
    int nat = 0;
    if (s.stun.size() >= 2) nat = distinct.size() == 1 ? 1 : 2;
    s.myNat = nat;
    for (const StunAddr& a : distinct) LBLOG("внешний адрес: %s:%u", ipStr(a.ip).c_str(), (unsigned)a.port);
    LBLOG("тип NAT: %s", nat == 1 ? "конусный (EIM)" : nat == 2 ? "симметричный (EDM)" : "не определён");

    Offer o;
    o.version = kOfferVersion;
    o.expiresAt = (uint32_t)(wallMs() / 1000 + (uint64_t)(ttlSec > 0 ? ttlSec : 600));
    o.nat = (uint8_t)nat;
    o.name = sanitize(deviceName, 24);
    std::vector<uint32_t> seen;
    for (const std::string& t : localIps) {
        uint32_t ip;
        if (!parseIp(t, ip) || ip == 0) continue;
        if (std::find(seen.begin(), seen.end(), ip) != seen.end()) continue;
        if (seen.size() >= 4) break;
        seen.push_back(ip);
        o.cands.push_back(Candidate{0, ip, s.localPort});
    }
    for (size_t i = 0; i < distinct.size() && i < 2; i++) o.cands.push_back(Candidate{1, distinct[i].ip, distinct[i].port});
    if (o.cands.empty()) {
        s.lastErr = "нет сетевых адресов";
        s.setState(ST_IDLE);
        return 2;
    }
    crypto::genKeypair(s.kp.priv, s.kp.pub);
    memcpy(o.pub, s.kp.pub, 32);
    if (!offerEncode(o, offerOut)) {
        s.lastErr = "не удалось сформировать код";
        s.setState(ST_IDLE);
        return 2;
    }
    s.myOffer = o;
    s.haveIdentity = true;
    s.nextStunMs = nowMs() + (uint64_t)s.cfg.stunKeepMs;
    s.nextTickMs = 0;
    s.setState(ST_READY);
    s.startThreadLocked();
    LBLOG("код создан: кандидатов %d, действует до %u", (int)o.cands.size(), (unsigned)o.expiresAt);
    return 0;
}

int Engine::describe(const std::vector<uint8_t>& blob, std::string& text) {
    Offer o;
    int rc = offerDecode(blob.data(), blob.size(), o);
    if (rc != OFFER_OK) {
        text = strfmt("code=%d\n", rc);
        return rc;
    }
    {
        std::lock_guard<std::mutex> g(p_->mu);
        if (p_->haveIdentity && memcmp(o.pub, p_->kp.pub, 32) == 0) rc = OFFER_OWN;
    }
    if (rc == OFFER_OK && offerExpired(o)) rc = OFFER_EXPIRED;
    std::string c;
    for (const Candidate& k : o.cands) {
        if (!c.empty()) c += ",";
        c += strfmt("%s:%s:%u", k.type == 0 ? "host" : "srflx", ipStr(k.ip).c_str(), (unsigned)k.port);
    }
    text = strfmt("code=%d\nname=%s\nexpires=%u\nnat=%d\ncands=%s\n", rc, o.name.c_str(), (unsigned)o.expiresAt,
                  (int)o.nat, c.c_str());
    return rc;
}

int Engine::setPeer(const std::vector<uint8_t>& blob) {
    Offer o;
    int rc = offerDecode(blob.data(), blob.size(), o);
    if (rc != OFFER_OK) return rc;
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.haveIdentity || s.state.load() != ST_READY) return OFFER_NOT_READY;
    if (offerExpired(s.myOffer)) return OFFER_OWN_EXPIRED;
    if (memcmp(o.pub, s.kp.pub, 32) == 0) return OFFER_OWN;
    if (offerExpired(o)) return OFFER_EXPIRED;
    s.peer = o;
    s.havePeer = true;
    s.lay = computeLayout(s.myOffer, s.peer);
    s.initiator = s.lay.initiator;
    deriveSid(s.sid, s.kp.pub, s.peer.pub);
    LBLOG("друг: \"%s\", кандидатов %d, NAT %d; сеть %s/%d, мой %s, друг %s, роль %s", s.peer.name.c_str(),
          (int)s.peer.cands.size(), (int)s.peer.nat, ipStr(s.lay.net).c_str(), s.lay.prefix, ipStr(s.lay.myIp).c_str(),
          ipStr(s.lay.peerIp).c_str(), s.initiator ? "инициатор" : "ответчик");
    return OFFER_OK;
}

bool Engine::layout(Layout& out) {
    std::lock_guard<std::mutex> g(p_->mu);
    if (!p_->havePeer) return false;
    out = p_->lay;
    return true;
}

int Engine::start(int tunFd, int mtu) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    auto fail = [&](int code, const char* msg) {
        if (tunFd >= 0) close(tunFd);
        s.lastErr = msg;
        LBLOG("старт отклонён: %s", msg);
        return code;
    };
    if (s.state.load() != ST_READY || !s.haveIdentity || !s.havePeer || s.sock < 0) return fail(1, "движок не готов к запуску");
    if (offerExpired(s.myOffer)) return fail(2, "ваш код истёк");
    if (offerExpired(s.peer)) return fail(3, "код друга истёк");
    if (tunFd < 0) return fail(4, "нет TUN-интерфейса");
    int fl = fcntl(tunFd, F_GETFL, 0);
    fcntl(tunFd, F_SETFL, fl | O_NONBLOCK);

    for (Session& x : s.sess) x.clear();
    s.pend.wipe();
    s.haveLast = false;
    s.lastInitTs = s.lastTsSent = 0;
    s.punchSeen.clear();
    s.peerAddrValid = false;
    s.peerLeft = false;
    s.rxBytes = s.txBytes = s.rxPkts = s.txPkts = 0;
    s.bcastTx = s.bcastRx = s.mcastTx = s.mcastRx = 0;
    s.authFail = s.punchRx = s.hsRx = s.dropped = s.handshakes = 0;
    s.rttMs = -1;
    s.lastRxMs = s.lastTxMs = 0;
    s.connectedSinceMs = 0;
    s.nextPingMs = s.nextRekeyMs = s.nextProbeMs = 0;

    memset(s.psk, 0, sizeof s.psk);
    s.dropForeignDst = s.dropNoSession = s.dropBadHdr = s.dropRxSrc = s.dropRxDst = s.tunWriteErr = 0;
    s.udpQueued = s.udpDropped = 0;
    s.resetFlowsLocked();
    s.udpAssoc.clear();
    s.fragFix.clear();
    s.udpFixups = 0;
    s.outq.clear();
    s.tunFd = tunFd;
    s.mtu = mtu;
    s.connectStartMs = nowMs();
    s.nextTickMs = 0;
    s.setState(ST_CONNECTING);
    s.startThreadLocked();
    s.wake();
    LBLOG("старт: TUN fd=%d, MTU %d", tunFd, mtu);
    return 0;
}

void Engine::retry() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.state.load() != ST_FAILED || s.tunFd < 0 || !s.havePeer) return;
    s.connectStartMs = nowMs();
    s.nextProbeMs = 0;
    s.nextTickMs = 0;
    s.lastErr.clear();
    s.setState(ST_CONNECTING);
    s.wake();
}

void Engine::stopInternal() {
    Impl& s = *p_;
    {
        std::lock_guard<std::mutex> g(s.mu);
        int st = s.state.load();
        if ((st == ST_CONNECTED || st == ST_STALLED) && s.sock >= 0) s.sendBye(nowMs());
    }
    s.stopThread();
    std::lock_guard<std::mutex> g(s.mu);
    s.resetRuntimeLocked();
    if (s.sock >= 0) {
        close(s.sock);
        s.sock = -1;
        s.localPort = 0;
    }
    for (int i = 0; i < 2; i++) {
        if (s.wakeFd[i] >= 0) close(s.wakeFd[i]);
        s.wakeFd[i] = -1;
    }
    crypto::wipe(&s.kp, sizeof s.kp);
    s.haveIdentity = false;
    s.myOffer = Offer();
    s.stun.clear();
    s.stunPend.clear();
    s.mappingChanged = false;
    if (s.state.load() != ST_IDLE) s.setState(ST_IDLE);
}

void Engine::stop() {
    std::lock_guard<std::mutex> life(p_->lifeMu);
    stopInternal();
}

void Engine::status(int64_t out[STATUS_FIELDS]) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    uint64_t now = nowMs();
    memset(out, 0, sizeof(int64_t) * STATUS_FIELDS);
    int st = s.state.load();
    out[0] = st;
    out[1] = (int64_t)s.rxBytes;
    out[2] = (int64_t)s.txBytes;
    out[3] = (int64_t)s.rxPkts;
    out[4] = (int64_t)s.txPkts;
    out[5] = s.rttMs;
    out[6] = s.lastRxMs ? (int64_t)(now - s.lastRxMs) : -1;
    out[7] = (s.connectedSinceMs && (st == ST_CONNECTED || st == ST_STALLED)) ? (int64_t)((now - s.connectedSinceMs) / 1000) : 0;
    out[8] = s.peerAddrValid ? (isPrivateIp(ntohl(s.peerAddr.sin_addr.s_addr)) ? 1 : 0) : -1;
    out[9] = (int64_t)s.bcastTx;
    out[10] = (int64_t)s.bcastRx;
    out[11] = (int64_t)s.mcastTx;
    out[12] = (int64_t)s.mcastRx;
    out[13] = (int64_t)s.authFail;
    out[14] = (int64_t)s.punchRx;
    out[15] = (int64_t)s.hsRx;
    out[16] = (int64_t)s.dropped;
    out[17] = s.mappingChanged ? 1 : 0;
    out[18] = s.myNat;
    out[19] = s.havePeer ? (int64_t)s.peer.nat : 0;
    out[20] = s.haveIdentity ? (int64_t)s.myOffer.expiresAt : 0;
    out[21] = (int64_t)s.handshakes;
    out[22] = s.peerLeft ? 1 : 0;
}

std::string Engine::info() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    std::string o;
    o += strfmt("path=%s\n", s.peerAddrValid ? addrStr(s.peerAddr).c_str() : "");
    if (s.havePeer) {
        o += strfmt("myIp=%s\npeerIp=%s\nnet=%s\nprefix=%d\nrole=%s\npeerName=%s\n", ipStr(s.lay.myIp).c_str(),
                    ipStr(s.lay.peerIp).c_str(), ipStr(s.lay.net).c_str(), s.lay.prefix,
                    s.initiator ? "initiator" : "responder", s.peer.name.c_str());
        std::string ra, ap;
        for (uint32_t x : s.lay.aliasMine) ra += (ra.empty() ? "" : ",") + ipStr(x);
        for (uint32_t x : s.lay.aliasPeer) ap += (ap.empty() ? "" : ",") + ipStr(x);
        o += "realIp=" + ra + "\naliasPeer=" + ap + "\n";
    }
    o += strfmt("localPort=%u\nstun=%d\nmtu=%d\n", (unsigned)s.localPort, (int)s.stun.size(), s.mtu);
    std::string m;
    for (const StunServer& sv : s.stun) {
        if (!m.empty()) m += ",";
        m += strfmt("%s:%u", ipStr(sv.mapped.ip).c_str(), (unsigned)sv.mapped.port);
    }
    o += "mapped=" + m + "\n";
    return o;
}

static const char* protoName(uint8_t p) {
    return p == 6 ? "TCP" : p == 17 ? "UDP" : p == 1 ? "ICMP" : p == 2 ? "IGMP" : "IP";
}

static std::string pktLine(const char* tag, uint32_t tMs, char dir, uint8_t proto, uint32_t sip, uint32_t dip,
                           uint16_t sp, uint16_t dp, uint16_t len, uint8_t tcpFlags, uint8_t ipFlags) {
    std::string a = ipStr(sip), b = ipStr(dip);
    if (proto == 6 || proto == 17) {
        if (sp || dp) {
            a += ":" + std::to_string(sp);
            b += ":" + std::to_string(dp);
        } else {
            a += " (фрагмент)";
        }
    }
    std::string fl;
    if (proto == 6) {
        if (tcpFlags & 0x02) fl += "S";
        if (tcpFlags & 0x10) fl += "A";
        if (tcpFlags & 0x08) fl += "P";
        if (tcpFlags & 0x01) fl += "F";
        if (tcpFlags & 0x04) fl += "R";
    }
    if (ipFlags & 0x2) fl += (fl.empty() ? "" : " ") + std::string("DF");
    if (ipFlags & 0x1) fl += (fl.empty() ? "" : " ") + std::string("MF");
    (void)tag;
    return strfmt("%7.3f %c %s %s > %s len=%u%s%s\n", tMs / 1000.0, dir, protoName(proto), a.c_str(), b.c_str(),
                  (unsigned)len, fl.empty() ? "" : " ", fl.c_str());
}

std::string Engine::flows() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    std::string o = strfmt(
        "drops foreignDst=%llu noSession=%llu badHeader=%llu rxSrc=%llu rxDst=%llu tunWrite=%llu udpQueued=%llu "
        "udpDropped=%llu\n",
        (unsigned long long)s.dropForeignDst, (unsigned long long)s.dropNoSession, (unsigned long long)s.dropBadHdr,
        (unsigned long long)s.dropRxSrc, (unsigned long long)s.dropRxDst, (unsigned long long)s.tunWriteErr,
        (unsigned long long)s.udpQueued, (unsigned long long)s.udpDropped);
    o += strfmt("проверка LAN (порт 41377, в списках не показана): %llu пакетов; вытеснено записей: %llu; с момента сброса: %.1f с\n",
                (unsigned long long)s.selftestPkts, (unsigned long long)s.flowOverflow,
                (nowMs() - s.flowEpochMs) / 1000.0);
    o += strfmt("подмен источника в ответах UDP: %llu; запомнено потоков UDP: %u\n", (unsigned long long)s.udpFixups,
                (unsigned)s.udpAssoc.size());
    std::vector<Impl::Flow> v = s.flowTab;
    std::sort(v.begin(), v.end(), [](const Impl::Flow& a, const Impl::Flow& b) { return a.bytes > b.bytes; });
    o += "\nПотоки (T: в туннель, R: из туннеля, X/Y: отброшено), порт = меньший из пары:\n";
    if (v.empty()) o += "(нет)\n";
    for (size_t i = 0; i < v.size() && i < 60; i++) {
        const Impl::Flow& f = v[i];
        std::string extra;
        if (f.proto == 6) extra = strfmt(" SYN=%u SYN-ACK=%u RST=%u FIN=%u", f.syn, f.synack, f.rst, f.fin);
        if (f.frags) extra += strfmt(" фрагментов=%u", f.frags);
        std::string port = (f.proto == 6 || f.proto == 17) ? strfmt(" порт %u", (unsigned)f.svc)
                           : f.proto == 1                  ? strfmt(" тип %u", (unsigned)f.svc)
                                                           : std::string();
        o += strfmt("%c %s %s > %s%s пакетов=%llu байт=%llu макс=%u %.1f..%.1f с%s\n", f.dir, protoName(f.proto),
                    ipStr(f.sip).c_str(), ipStr(f.dip).c_str(), port.c_str(), (unsigned long long)f.pkts,
                    (unsigned long long)f.bytes, (unsigned)f.maxLen, f.firstMs / 1000.0, f.lastMs / 1000.0,
                    extra.c_str());
    }
    o += strfmt("\nПервые пакеты (%u):\n", (unsigned)s.headRing.size());
    for (const Impl::PktRec& r : s.headRing)
        o += pktLine("h", r.tMs, r.dir, r.proto, r.sip, r.dip, r.sport, r.dport, r.len, r.tcpFlags, r.ipFlags);
    size_t cap = sizeof s.tailRing / sizeof s.tailRing[0];
    size_t n = s.tailCount < cap ? s.tailCount : cap;
    o += strfmt("\nПоследние пакеты (%u из %llu):\n", (unsigned)n, (unsigned long long)s.tailCount);
    for (size_t i = 0; i < n; i++) {
        const Impl::PktRec& r = s.tailRing[(s.tailCount - n + i) % cap];
        o += pktLine("t", r.tMs, r.dir, r.proto, r.sip, r.dip, r.sport, r.dport, r.len, r.tcpFlags, r.ipFlags);
    }
    return o;
}

void Engine::resetFlows() {
    std::lock_guard<std::mutex> g(p_->mu);
    p_->resetFlowsLocked();
}

std::string Engine::lastError() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->lastErr;
}

int Engine::socketFd() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->sock;
}

uint16_t Engine::localPort() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->localPort;
}

}  // namespace lb
