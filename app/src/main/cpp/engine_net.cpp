// LanBridge native core: engine, network side. Sessions, sending (direct and through the group creator), handshakes,
// receiving datagrams.
#include <errno.h>

#include <algorithm>
#include <cstring>

#include "engine_impl.h"

namespace lb {

using Impl = Engine::Impl;

// ============================================================ sessions

uint32_t Impl::newIdx() {
    for (;;) {
        uint32_t v;
        randomBytes(&v, sizeof v);
        if (v == 0) continue;
        bool used = false;
        for (const auto& p : peers) {
            if (p->pend.active && p->pend.localIdx == v) used = true;
            for (const Session& s : p->sess)
                if (s.valid && s.localIdx == v) used = true;
        }
        for (const GuestSess& g : grp.guests)
            if (g.s.valid && g.s.localIdx == v) used = true;
        if (!used) return v;
    }
}

Impl::Found Impl::findSession(uint32_t idx) {
    Found f;
    for (auto& p : peers) {
        for (Session& s : p->sess) {
            if (s.valid && s.localIdx == idx) {
                f.peer = p.get();
                f.sess = &s;
                return f;
            }
        }
    }
    for (GuestSess& g : grp.guests) {
        if (g.s.valid && g.s.localIdx == idx) {
            f.guest = &g;
            f.sess = &g.s;
            return f;
        }
    }
    return f;
}

Session* Impl::bestSession(Peer* p, uint64_t now) {
    Session* best = nullptr;
    for (Session& s : p->sess) {
        if (!s.valid || !s.confirmed) continue;
        if (now - s.createdMs >= (uint64_t)cfg.rejectAfterMs) continue;
        if (!best || s.createdMs > best->createdMs) best = &s;
    }
    return best;
}

Session* Impl::allocSession(Peer* p) {
    for (Session& s : p->sess)
        if (!s.valid) return &s;
    Session* oldest = &p->sess[0];
    for (Session& s : p->sess)
        if (s.createdMs < oldest->createdMs) oldest = &s;
    oldest->clear();
    return oldest;
}

void Impl::expireSessions(Peer* p, uint64_t now) {
    for (Session& s : p->sess)
        if (s.valid && now - s.createdMs >= (uint64_t)cfg.rejectAfterMs) s.clear();
}

// ============================================================ sending

bool Impl::wouldBlock(int e) const { return e == EAGAIN || e == EWOULDBLOCK || e == ENOBUFS; }

void Impl::noteTxError(const Addr& to, int e) {
    (to.v6 ? txErr6 : txErr4)++;
    int& last = lastTxErrno[to.v6 ? 1 : 0];
    if (last != e) LBLOG("отправка на %s: %s", addrStr(to).c_str(), strerror(e));
    last = e;
}

void Impl::sendRaw(const Addr& to, const uint8_t* b, size_t n) {
    UdpSocket* us = sockFor(to);
    if (!us || n > sizeof(OutPkt::data)) {
        if (!us) noRoute++;
        return;
    }
    if (outq.empty()) {
        ssize_t r = us->sendTo(to, b, n);
        if (r >= 0) return;
        if (!wouldBlock(errno)) {
            noteTxError(to, errno);
            return;
        }
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

void Impl::flushOut() {
    while (!outq.empty()) {
        const OutPkt& p = outq.front();
        UdpSocket* us = sockFor(p.to);
        if (us) {
            ssize_t r = us->sendTo(p.to, p.data, p.len);
            if (r < 0) {
                if (wouldBlock(errno)) break;
                noteTxError(p.to, errno);
            }
        }
        outq.pop_front();
    }
}

void Impl::sendCands(Peer* p, const uint8_t* b, size_t n, const Addr* skip) {
    for (const Addr& a : p->cands) {
        if (skip && a == *skip) continue;
        sendRaw(a, b, n);
    }
}

// A datagram straight to the peer. Data goes to the path in use (and to every candidate while that path is unknown or
// silent); control packets (handshakes, punches, path probes) always go to every candidate as well.
void Impl::sendDirect(Peer* p, const uint8_t* b, size_t n, uint64_t now, bool control) {
    if (control) {
        sendCands(p, b, n, p->addrValid ? &p->addr : nullptr);
        if (p->addrValid) sendRaw(p->addr, b, n);
        return;
    }
    bool fresh = pathFresh(p, now);
    if (fresh) sendRaw(p->addr, b, n);
    if (!fresh || !p->lastDirectRxMs || now - p->lastDirectRxMs > 8000) sendCands(p, b, n, fresh ? &p->addr : nullptr);
}

// Whether packets for this peer can also go through the group creator.
bool Impl::canRelay(Peer* p, uint64_t now) {
    if (grp.role != 2 || grp.joinState != 2 || p->isCreator || p->guestMode) return false;
    Peer* c = creatorPeer();
    return c && !c->guestMode && bestSession(c, now) != nullptr;
}

// Wraps a ready datagram for `p` into K_RELAY and sends it to the creator, who passes it on. The datagram is sealed
// for `p`, so the creator only sees ciphertext.
void Impl::sendViaCreator(Peer* p, const uint8_t* b, size_t n, uint64_t now) {
    Peer* c = creatorPeer();
    if (!c || c == p || n + 2 > MAX_PLAIN) return;
    Session* cs = bestSession(c, now);
    if (!cs) return;
    uint8_t plain[MAX_PLAIN];
    plain[0] = K_RELAY;
    plain[1] = (uint8_t)p->slot;
    memcpy(plain + 2, b, n);
    uint8_t out[DATA_HDR + MAX_PLAIN + AEAD_TAG];
    size_t m = seal(cs, plain, n + 2, out);
    routeOut(c, out, m, now, false);
    c->lastTxMs = now;
    grp.relayTx++;
}

void Impl::routeOut(Peer* p, const uint8_t* b, size_t n, uint64_t now, bool control) {
    bool relayable = canRelay(p, now);
    if (!relayable) {
        sendDirect(p, b, n, now, control);
        return;
    }
    // What pings have proven (see sendPing). Direct answers keep coming: direct only. One or two answers missing: both
    // ways (the receiver drops the copy that comes second). Direct is silent but the creator's way works: through the
    // creator only (pings and handshakes keep trying the direct one). Nothing known yet: both ways.
    if (directFresh(p, now)) {
        sendDirect(p, b, n, now, control);
        return;
    }
    if (directOk(p, now)) {
        sendDirect(p, b, n, now, control);
        sendViaCreator(p, b, n, now);
        return;
    }
    if (!control && relayOk(p, now)) {
        sendViaCreator(p, b, n, now);
        return;
    }
    sendDirect(p, b, n, now, control);
    sendViaCreator(p, b, n, now);
}

void Impl::reply(Peer* p, const Route& to, const uint8_t* b, size_t n, uint64_t now) {
    if (to.viaRelay()) {
        if (p) sendViaCreator(p, b, n, now);
        return;
    }
    sendRaw(to.addr, b, n);
}

size_t Impl::seal(Session* s, const uint8_t* plain, size_t plen, uint8_t* out) {
    out[0] = T_DATA;
    putLe32(out + 1, s->remoteIdx);
    putLe64(out + 5, s->sendCtr);
    crypto::aeadEncrypt(out + DATA_HDR, s->sendKey, s->sendCtr, nullptr, 0, plain, plen);
    s->sendCtr++;
    return DATA_HDR + plen + AEAD_TAG;
}

void Impl::sendTransport(Peer* p, Session* s, const uint8_t* plain, size_t plen, uint64_t now, bool control) {
    if (plen > MAX_PLAIN) return;
    uint8_t out[DATA_HDR + MAX_PLAIN + AEAD_TAG];
    size_t n = seal(s, plain, plen, out);
    routeOut(p, out, n, now, control);
    p->lastTxMs = now;
    lastTxMs = now;
}

void Impl::sendKeepalive(Peer* p, Session* s, uint64_t now) { sendTransport(p, s, nullptr, 0, now); }

// A ping carries a flag saying which way it travels: 0 straight to the peer, 1 through the creator. The answer echoes
// it, so the sender learns which of the two paths works. (Peers of build 20004 echo the 10-byte form: flag 0.)
void Impl::sendPing(Peer* p, Session* s, uint64_t now) {
    uint8_t pl[11];
    pl[0] = K_CTRL;
    pl[1] = C_PING;
    putBe64(pl + 2, now);
    pl[10] = 0;
    if (!canRelay(p, now)) {
        sendTransport(p, s, pl, 10, now);
        return;
    }
    uint8_t out[DATA_HDR + 11 + AEAD_TAG];
    size_t n = seal(s, pl, 11, out);
    sendDirect(p, out, n, now, true);
    pl[10] = 1;
    n = seal(s, pl, 11, out);
    sendViaCreator(p, out, n, now);
    p->lastTxMs = now;
    lastTxMs = now;
}

void Impl::sendBye(uint64_t now) {
    for (auto& p : peers) {
        if (p->guestMode) continue;
        Session* s = bestSession(p.get(), now);
        if (!s) continue;
        uint8_t b = K_BYE;
        sendTransport(p.get(), s, &b, 1, now);
        sendTransport(p.get(), s, &b, 1, now);
    }
}

void Impl::sendHandshake(Peer* p, const uint8_t* b, size_t n, uint64_t now) { routeOut(p, b, n, now, true); }

void Impl::sendPunch(Peer* p, uint64_t now) {
    uint8_t pk[PUNCH_LEN];
    pk[0] = T_PUNCH;
    memcpy(pk + 1, p->sid, 8);
    randomBytes(pk + 9, 4);
    sendDirect(p, pk, PUNCH_LEN, now, true);  // a punch has no use through the creator
}

void Impl::updatePath(Peer* p, const Route& src, uint64_t now) {
    if (src.viaRelay()) {
        p->lastRelayRxMs = now;
        return;
    }
    if ((!p->addrValid || src.addr != p->addr) && now - p->pathLogMs >= 3000) {  // both families may answer in turn
        p->pathLogMs = now;
        LBLOG("путь до %s: %s", displayName(p).c_str(), addrStr(src.addr).c_str());
    }
    p->addr = src.addr;
    p->addrValid = true;
    p->addrMs = now;
    p->lastDirectRxMs = now;
}

// ============================================================ handshake driving

const uint8_t* Impl::sharedStatic(Peer* p, const KeyPair& me) {
    if (!p->ssOk || memcmp(p->ssMe, me.pub, 32) != 0) {
        if (!crypto::x25519(p->ss, me.priv, p->offer.pub)) {
            p->ssOk = false;
            return nullptr;
        }
        memcpy(p->ssMe, me.pub, 32);
        p->ssOk = true;
    }
    return p->ss;
}

const uint8_t* Impl::guestShared() {
    uint8_t tag[64];
    memcpy(tag, grp.guest.pub, 32);
    memcpy(tag + 32, kp.pub, 32);
    if (!grp.guestSsOk || memcmp(grp.guestSsTag, tag, 64) != 0) {
        if (!crypto::x25519(grp.guestSs, kp.priv, grp.guest.pub)) {
            grp.guestSsOk = false;
            return nullptr;
        }
        memcpy(grp.guestSsTag, tag, 64);
        grp.guestSsOk = true;
    }
    return grp.guestSs;
}

void Impl::newInitiation(Peer* p, uint64_t now) {
    uint64_t ts = wallMs();
    if (ts <= p->lastTsSent) ts = p->lastTsSent + 1;
    p->lastTsSent = ts;
    p->pend.wipe();
    uint32_t idx = newIdx();
    if (!hsCreateInitiation(p->pend, keyFor(p), p->offer.pub, ts, idx, sharedStatic(p, keyFor(p)))) {
        p->pend.active = false;
        LBLOG("handshake: не удалось создать запрос");
        return;
    }
    p->pend.createdMs = now;
}

void Impl::probe(Peer* p, uint64_t now) {
    if (now < p->nextProbeMs) return;
    uint64_t el = now - p->startMs;
    p->nextProbeMs = now + (uint64_t)(el < (uint64_t)cfg.probeSlowAfterMs ? cfg.probeIntervalMs : cfg.probeSlowIntervalMs);
    if (p->initiator) {
        if (!p->pend.active || now - p->pend.createdMs >= (uint64_t)cfg.hsRefreshMs) newInitiation(p, now);
        if (p->pend.active) sendHandshake(p, p->pend.msg1, MSG1_LEN, now);
    } else {
        sendPunch(p, now);
    }
}

void Impl::rekey(Peer* p, Session* cur, uint64_t now) {
    if (now - cur->createdMs < (uint64_t)cfg.rekeyAfterMs) return;
    if (now < p->nextRekeyMs) return;
    p->nextRekeyMs = now + 1000;
    if (!p->pend.active || now - p->pend.createdMs >= (uint64_t)cfg.hsRefreshMs) newInitiation(p, now);
    if (p->pend.active) routeOut(p, p->pend.msg1, MSG1_LEN, now, false);
}

void Impl::authFailed(const char* what, uint64_t now) {
    authFail++;
    if (now - lastAuthLogMs > 3000) {
        lastAuthLogMs = now;
        LBLOG("пакет не прошёл проверку (%s): пароль или код не совпадают", what);
    }
}

// One peer's part of the periodic work. `due` is lowered to the time of the next thing that must happen.
void Impl::peerTick(Peer* p, uint64_t now, uint64_t& due) {
    expireSessions(p, now);
    Session* cur = bestSession(p, now);
    const bool group = grp.role != 0;
    if (p->guestMode && grp.joinState == 3) {  // refused or timed out: nothing more to try
        due = std::min(due, now + 1000);
        return;
    }
    if (!cur) {
        if (p->connected) {
            p->connected = false;
            if (group && !p->guestMode) LBLOG("%s: связи нет", displayName(p).c_str());
        }
        if (!group) {
            if (state.load() != ST_CONNECTING) {
                setState(ST_CONNECTING);
                connectStartMs = now;
                p->startMs = now;
                p->nextProbeMs = 0;
            }
            if (p->cands.empty()) {
                auto fn = [](int f) { return f == 3 ? "IPv4 и IPv6" : f == 2 ? "только IPv6" : f == 1 ? "только IPv4" : "нет"; };
                failLocked(strfmt("нет общего сетевого протокола с другом (у вас: %s, у друга: %s)",
                                  fn(offerFamilies(myOffer)), fn(offerFamilies(p->offer))));
            } else if (now - connectStartMs >= (uint64_t)cfg.connectTimeoutMs) {
                failLocked("друг не ответил за отведённое время");
            } else {
                probe(p, now);
                due = std::min(due, std::max(p->nextProbeMs, now + 1));
            }
        } else {
            probe(p, now);
            due = std::min(due, std::max(p->nextProbeMs, now + 1));
        }
        return;
    }
    if (p->guestMode) {  // the join exchange is driven by groupTick()
        due = std::min(due, now + 300);
        return;
    }
    bool fresh = p->lastRxMs && now - p->lastRxMs < (uint64_t)cfg.stallMs;
    bool nowConnected = fresh && !p->left;
    if (nowConnected != p->connected) {
        p->connected = nowConnected;
        if (group) LBLOG("%s: %s", displayName(p).c_str(), nowConnected ? "на связи" : "связи нет");
    }
    if (!fresh && !group && state.load() == ST_CONNECTED) setState(ST_STALLED);
    if (now - p->lastTxMs >= (uint64_t)cfg.keepaliveMs) sendKeepalive(p, cur, now);
    if (now >= p->nextPingMs) {
        bool probing = canRelay(p, now) && !directFresh(p, now);
        sendPing(p, cur, now);
        p->nextPingMs = now + (uint64_t)(probing ? std::min(cfg.pingMs, 1000) : cfg.pingMs);
    }
    if (p->initiator) rekey(p, cur, now);
    if (p->lastRxMs && now - p->lastRxMs > 8000 && now >= p->nextProbeMs) {
        sendPunch(p, now);
        p->nextProbeMs = now + 3000;
    }
    profileTick(p, cur, now);
    if (grp.role == 1) syncTick(p, cur, now);
    due = std::min(due, now + 500);
}

// ============================================================ receiving

void Impl::readUdp(UdpSocket* us, uint64_t now) {
    uint8_t buf[2600];
    // A time budget keeps the timers running when a flood of handshake requests arrives (each one costs a few DH
    // operations): what is left in the socket is read on the next turn of the loop.
    const uint64_t t0 = nowMs();
    for (int i = 0; i < 256; i++) {
        Addr from;
        ssize_t n = us->recvFrom(buf, sizeof buf, from);
        if (n < 0) break;
        if (n == 0) continue;
        onUdp(buf, (size_t)n, from, now);
        sweepDoomed();
        if ((i & 3) == 3 && nowMs() - t0 >= 15) break;
    }
}

void Impl::onUdp(const uint8_t* b, size_t n, const Addr& src, uint64_t now) {
    if (stunIsMessage(b, n)) {
        onStun(b, n);
        return;
    }
    onDatagram(b, n, Route::direct(src), now, false);
}

bool Impl::engineActive() const {
    int st = state.load();
    return (st >= ST_CONNECTING && st <= ST_STALLED) || (st == ST_READY && grp.role != 0);
}

void Impl::onDatagram(const uint8_t* b, size_t n, const Route& src, uint64_t now, bool nested) {
    if (n == 0 || !engineActive()) return;
    switch (b[0]) {
        case T_PUNCH:
            if (!src.viaRelay()) onPunch(b, n, src);
            break;
        case T_MSG1: onMsg1(b, n, src, now); break;
        case T_MSG2: onMsg2(b, n, src, now); break;
        case T_DATA: onData(b, n, src, now, nested); break;
        default: break;
    }
}

void Impl::onPunch(const uint8_t* b, size_t n, const Route& src) {
    if (n != PUNCH_LEN) return;
    Peer* p = peerBySid(b + 1);
    if (!p) return;
    punchRx++;
    bool seen = false;
    for (const Addr& a : p->punchSeen)
        if (a == src.addr) seen = true;
    if (!seen && p->punchSeen.size() < 8) {
        p->punchSeen.push_back(src.addr);
        LBLOG("получен пробный пакет от %s (%s)", displayName(p).c_str(), addrStr(src.addr).c_str());
    }
    if (p->initiator && p->pend.active && !bestSession(p, nowMs())) sendRaw(src.addr, p->pend.msg1, MSG1_LEN);
}

// A MSG1 does not say who it is from (only the responder's key is in its MAC), so the responder tries the keys of the
// peers it answers for, those known to live at the source address first; the group's guest key comes last.
void Impl::onMsg1(const uint8_t* b, size_t n, const Route& src, uint64_t now) {
    if (n != MSG1_LEN) return;
    for (auto& p : peers) {  // a retransmission of a request that was answered: repeat the same answer
        if (!p->guestMode && p->haveLast && memcmp(b, p->lastMsg1, MSG1_LEN) == 0) {
            reply(p.get(), src, p->lastMsg2, MSG2_LEN, now);
            return;
        }
    }
    if (!src.viaRelay()) {
        for (GuestSess& g : grp.guests) {
            if (memcmp(b, g.msg1, MSG1_LEN) == 0) {
                sendRaw(src.addr, g.msg2, MSG2_LEN);
                return;
            }
        }
    }
    uint8_t es[32];  // the part of the handshake that does not depend on who the sender is: once per datagram
    if (!hsMsg1Shared(b, n, kp, es)) {
        if (grp.role != 0) dropped++;
        else authFailed("запрос", now);
        return;
    }
    std::vector<Peer*> order;
    for (auto& p : peers) {
        if (p->initiator || p->guestMode) continue;
        if (src.viaRelay() && p->slot != src.relay) continue;
        order.push_back(p.get());
    }
    if (!src.viaRelay()) {
        auto at = [&](Peer* p) {
            if (p->addrValid && p->addr == src.addr) return true;
            for (const Addr& a : p->cands)
                if (a == src.addr) return true;
            return false;
        };
        std::stable_partition(order.begin(), order.end(), at);
    }
    for (Peer* p : order)
        if (onMsg1Peer(p, b, n, es, src, now)) return;
    if (grp.role == 1 && onMsg1Guest(b, n, es, src, now)) return;
    if (grp.role != 0) {  // a member that has not been announced to us yet: it repeats its request
        dropped++;
        return;
    }
    authFailed("запрос", now);
}

bool Impl::onMsg1Peer(Peer* p, const uint8_t* b, size_t n, const uint8_t* es, const Route& src, uint64_t now) {
    HsRespIn in;
    const uint8_t* ss = sharedStatic(p, kp);
    if (!ss || !hsConsumeInitiation(b, n, kp, p->offer.pub, in, es, ss)) return false;
    if (in.ts <= p->lastInitTs) {
        dropped++;
        return true;
    }
    p->lastInitTs = in.ts;
    uint32_t idx = newIdx();
    TransportKeys keys;
    uint8_t m2[MSG2_LEN];
    if (!hsCreateResponse(in, kp, p->offer.pub, psk, idx, m2, keys)) return true;
    Session* s = allocSession(p);
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
    memcpy(p->lastMsg1, b, MSG1_LEN);
    memcpy(p->lastMsg2, m2, MSG2_LEN);
    p->haveLast = true;
    hsRx++;
    updatePath(p, src, now);
    reply(p, src, m2, MSG2_LEN, now);
    LBLOG("получен запрос соединения от %s (%s)", displayName(p).c_str(),
          src.viaRelay() ? "через создателя" : addrStr(src.addr).c_str());
    return true;
}

// The door of the group: a newcomer that knows the group code runs the handshake with the guest key pair.
bool Impl::onMsg1Guest(const uint8_t* b, size_t n, const uint8_t* es, const Route& src, uint64_t now) {
    if (src.viaRelay()) return false;
    HsRespIn in;
    const uint8_t* ss = guestShared();
    if (!ss || !hsConsumeInitiation(b, n, kp, grp.guest.pub, in, es, ss)) return false;
    uint32_t idx = newIdx();
    TransportKeys keys;
    uint8_t m2[MSG2_LEN];
    if (!hsCreateResponse(in, kp, grp.guest.pub, psk, idx, m2, keys)) return true;
    if (grp.guests.size() >= kMaxGuests) {
        size_t victim = 0;
        for (size_t i = 1; i < grp.guests.size(); i++)
            if (grp.guests[i].createdMs < grp.guests[victim].createdMs) victim = i;
        grp.guests[victim].s.clear();
        grp.guests.erase(grp.guests.begin() + (long)victim);
    }
    GuestSess g;
    g.s.clear();
    g.s.valid = true;
    g.s.confirmed = false;
    g.s.initiator = false;
    g.s.localIdx = idx;
    g.s.remoteIdx = in.senderIdx;
    memcpy(g.s.sendKey, keys.send, 32);
    memcpy(g.s.recvKey, keys.recv, 32);
    g.s.createdMs = now;
    g.s.lastRxMs = now;
    crypto::wipe(&keys, sizeof keys);
    memcpy(g.msg1, b, MSG1_LEN);
    memcpy(g.msg2, m2, MSG2_LEN);
    g.addr = src.addr;
    g.createdMs = g.lastRxMs = now;
    grp.guests.push_back(g);
    hsRx++;
    sendRaw(src.addr, m2, MSG2_LEN);
    LBLOG("в дверь группы стучится устройство %s", addrStr(src.addr).c_str());
    return true;
}

void Impl::onMsg2(const uint8_t* b, size_t n, const Route& src, uint64_t now) {
    if (n != MSG2_LEN) return;
    uint32_t myIdx = le32(b + 5);
    Peer* p = nullptr;
    for (auto& q : peers) {
        if (q->initiator && q->pend.active && q->pend.localIdx == myIdx) {
            p = q.get();
            break;
        }
    }
    if (!p) return;
    uint32_t remoteIdx = 0;
    TransportKeys keys;
    if (!hsConsumeResponse(p->pend, b, n, keyFor(p), psk, remoteIdx, keys)) {
        authFailed("ответ", now);
        return;
    }
    Session* s = allocSession(p);
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
    updatePath(p, src, now);
    markConnected(p, src, now);
    sendKeepalive(p, s, now);  // confirms the new keys to the responder
    if (p->guestMode) {
        grp.nextJoinMs = 0;  // the door is open: knock with K_JOIN at once
        LBLOG("дверь группы открыта, отправляю заявку");
    }
}

// Something authenticated has just arrived from the peer.
void Impl::markConnected(Peer* p, const Route& src, uint64_t now) {
    p->lastRxMs = now;
    lastRxMs = now;
    p->left = false;
    if (p->guestMode) return;
    if (!p->connectedSinceMs) p->connectedSinceMs = now;
    p->everConnected = true;
    if (grp.role == 0 && state.load() != ST_CONNECTED) {
        if (!connectedSinceMs) connectedSinceMs = now;
        setState(ST_CONNECTED);
        LBLOG("соединение установлено (%s)", src.viaRelay() ? "через создателя" : addrStr(src.addr).c_str());
    }
}

void Impl::onData(const uint8_t* b, size_t n, const Route& src, uint64_t now, bool nested) {
    if (n < DATA_HDR + AEAD_TAG) return;
    Found f = findSession(le32(b + 1));
    if (!f.sess) {
        dropped++;
        return;
    }
    Session* s = f.sess;
    uint64_t ctr = le64(b + 5);
    if (!s->replay.check(ctr)) {
        (grp.role == 0 ? dropped : dupDropped)++;  // in a group the same packet may arrive twice, by two paths
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
    if (!s->confirmed) {
        s->confirmed = true;
        handshakes++;
    }
    if (f.guest) {  // a newcomer at the door: only K_JOIN means anything
        if (src.viaRelay()) return;
        f.guest->lastRxMs = now;
        f.guest->addr = src.addr;
        if (plen >= 1 && plain[0] == K_JOIN) onJoin(f.guest, plain, plen, now);
        return;
    }
    Peer* p = f.peer;
    if (src.viaRelay() && src.relay != p->slot) return;  // the creator relays only what a member really sent
    updatePath(p, src, now);
    markConnected(p, src, now);
    handlePlain(p, s, plain, plen, src, now, nested);
}

void Impl::handlePlain(Peer* p, Session* s, const uint8_t* plain, size_t n, const Route& src, uint64_t now, bool nested) {
    if (n == 0) return;  // keepalive
    if (p->guestMode) {  // before admission only the answer to K_JOIN counts
        if (plain[0] == K_WELCOME) onWelcome(p, plain, n, now);
        else if (plain[0] == K_REJECT) onReject(p, plain, n);
        return;
    }
    switch (plain[0]) {
        case K_IP: deliverIp(p, plain + 1, n - 1); break;
        case K_FRAG:
            if (n > FRAG_HDR) {
                std::vector<uint8_t> whole;
                if (p->reasm.add(be16(plain + 1), plain[3], plain[4], plain + FRAG_HDR, n - FRAG_HDR, now, whole)) {
                    fragRecv++;
                    deliverIp(p, whole.data(), whole.size());
                }
            }
            break;
        case K_CTRL:
            if (n >= 10 && plain[1] == C_PING) {
                uint8_t r[11];
                size_t rn = std::min<size_t>(n, sizeof r);
                memcpy(r, plain, rn);
                r[1] = C_PONG;
                sendTransport(p, s, r, rn, now);
            } else if (n >= 10 && plain[1] == C_PONG) {
                uint64_t t = be64(plain + 2);
                bool viaRelayPing = n >= 11 && plain[10] == 1;
                if (viaRelayPing) p->relayEchoMs = now;
                else p->directEchoMs = now;
                if (t <= now && now - t < 60000 && (!viaRelayPing || !directOk(p, now))) p->rttMs = (int64_t)(now - t);
            }
            break;
        case K_BYE:
            p->left = true;
            p->connected = false;
            if (grp.role == 0 && state.load() == ST_CONNECTED) setState(ST_STALLED);
            LBLOG("%s отключился", displayName(p).c_str());
            if (grp.role == 1) doomed.push_back(p->slot);
            break;
        case K_RELAY: onRelay(p, plain, n, now, nested); break;
        case K_MEMBER: onMember(p, plain, n, now); break;
        case K_MEMBER_ACK: onMemberAck(p, plain, n); break;
        case K_PROFILE: onProfile(p, s, plain, n, now); break;
        case K_AVATAR: onAvatar(p, s, plain, n, now); break;
        case K_PROFILE_ACK: onProfileAck(p, plain, n); break;
        default: break;
    }
}

}  // namespace lb
