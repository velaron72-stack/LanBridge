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
    uint8_t psk[32];

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
        int buf = 1 << 20;
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
        rttMs = -1;
        lastRxMs = lastTxMs = 0;
        connectStartMs = connectedSinceMs = 0;
        nextProbeMs = nextPingMs = nextRekeyMs = 0;
        crypto::wipe(psk, sizeof psk);
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
        if (sock < 0) return;
        sendto(sock, b, n, MSG_DONTWAIT, (const sockaddr*)&to, sizeof to);
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
            {
                std::lock_guard<std::mutex> g(mu);
                int64_t t = (int64_t)nextTickMs - (int64_t)nowMs();
                if (t < 0) t = 0;
                if (t > 1000) t = 1000;
                timeout = (int)t;
                tfd = tunFd;
            }
            pollfd fds[3];
            int nf = 0, ti = -1;
            fds[nf++] = pollfd{sock, POLLIN, 0};
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
                if (fds[0].revents & POLLIN) readUdp(now);
                if (ti >= 0 && tunFd == tfd && fds[ti].revents) readTun(now, fds[ti].revents);
            }
            tick(now);
        }
    }

    void tick(uint64_t now) {
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
        for (int i = 0; i < 64; i++) {
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
    void deliverIp(const uint8_t* ip, size_t len) {
        if (tunFd < 0) return;
        if (len < 20 || (ip[0] >> 4) != 4) {
            dropped++;
            return;
        }
        size_t ihl = (size_t)(ip[0] & 15) * 4;
        size_t tot = be16(ip + 2);
        if (ihl < 20 || ihl > len || tot < ihl || tot > len) {
            dropped++;
            return;
        }
        uint32_t src = be32(ip + 12), dst = be32(ip + 16);
        if (src != lay.peerIp) {
            dropped++;
            return;
        }
        bool bc = dst == 0xFFFFFFFFu || dst == lay.bcast;
        bool mc = (dst >> 28) == 0xE;
        if (!(dst == lay.myIp || bc || mc)) {
            dropped++;
            return;
        }
        ssize_t w = write(tunFd, ip, tot);
        if (w < 0) {
            dropped++;
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EINVAL && errno != EMSGSIZE)
                failTunLocked(strfmt("TUN write: %s", strerror(errno)));
            return;
        }
        rxPkts++;
        rxBytes += tot;
        if (bc) bcastRx++;
        if (mc) mcastRx++;
    }

    void readTun(uint64_t now, short revents) {
        uint8_t buf[4096];
        for (int i = 0; i < 64; i++) {
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
        if (ihl < 20 || ihl > n || tot < ihl || tot > n) return;
        if (p[9] == 2) return;  // IGMP stays local
        uint32_t dst = be32(p + 16);
        enum { UC, BC, MC } kind;
        if (dst == lay.peerIp) kind = UC;
        else if (dst == 0xFFFFFFFFu || dst == lay.bcast) kind = BC;
        else if ((dst >> 28) == 0xE) kind = MC;
        else {
            dropped++;
            return;
        }
        Session* cur = bestSession(now);
        if (!cur) {
            dropped++;
            return;
        }
        if (be32(p + 12) != lay.myIp) ipRewriteSrc(p, tot, lay.myIp);
        uint8_t plain[MAX_PLAIN];
        if (tot + 1 > sizeof plain) return;
        plain[0] = K_IP;
        memcpy(plain + 1, p, tot);
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
    o.version = 1;
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

int Engine::start(int tunFd, const std::string& password, int mtu) {
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

    derivePsk(s.psk, password.data(), password.size(), s.sid);
    s.tunFd = tunFd;
    s.mtu = mtu;
    s.connectStartMs = nowMs();
    s.nextTickMs = 0;
    s.setState(ST_CONNECTING);
    s.startThreadLocked();
    s.wake();
    LBLOG("старт: TUN fd=%d, MTU %d, пароль %s", tunFd, mtu, password.empty() ? "нет" : "да");
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
