// LanBridge native core: engine, lifecycle, main loop and the public API. The work itself is in engine_net.cpp (sessions,
// handshakes, datagrams), engine_group.cpp (peers, groups, relay, profiles) and engine_tun.cpp (TUN side, flows).
#include <errno.h>

#include <algorithm>
#include <cstring>

#include "engine_impl.h"

namespace lb {

using Impl = Engine::Impl;

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

// ============================================================ lifecycle helpers

void Impl::setState(int s) {
    int old = state.exchange(s);
    if (old != s) LBLOG("состояние: %s -> %s", stateName(old), stateName(s));
}

void Impl::wake() {
    if (wakeFd[1] >= 0) {
        uint8_t b = 1;
        ssize_t r = plat::fdWrite(wakeFd[1], &b, 1);
        (void)r;
    }
}

void Impl::drainWake() {
    uint8_t b[64];
    while (plat::fdRead(wakeFd[0], b, sizeof b) > 0) {
    }
}

// Opens the missing sockets. IPv4 and IPv6 are independent: the tunnel works with one of them, and a failure of
// the other family is only logged (a device or a network without IPv6 is normal).
bool Impl::openSocketLocked() {
    for (int fam = 0; fam < 2; fam++) {
        std::unique_ptr<UdpSocket>& slot = fam ? s6 : s4;
        std::string& why = fam ? sockErr6 : sockErr4;
        if (slot) continue;
        std::string err;
        slot = factory ? factory(fam == 1, err) : openSysUdp(fam == 1, err);
        if (slot && slot->v6() != (fam == 1)) slot.reset();  // a factory that returned the wrong family
        if (!slot) {
            why = err.empty() ? "сокет не создан" : err;
            LBLOG("транспорт %s недоступен: %s", fam ? "IPv6" : "IPv4", why.c_str());
        } else {
            why.clear();
            LBLOG("транспорт %s: порт %u", fam ? "IPv6" : "IPv4", (unsigned)slot->port());
        }
    }
    if (!haveSocket()) {
        lastErr = sockErr4.empty() ? sockErr6 : (sockErr6.empty() ? sockErr4 : sockErr4 + "; " + sockErr6);
        return false;
    }
    if (wakeFd[0] < 0) {
        if (!plat::makeWake(wakeFd)) {
            lastErr = strfmt("wake: %s", plat::errStr(plat::sockErrno()).c_str());
            wakeFd[0] = wakeFd[1] = -1;
            s4.reset();
            s6.reset();
            return false;
        }
    }
    return true;
}

void Impl::resetFragStatsLocked() {
    for (auto& p : peers) p->reasm.clear();
    fragSeq = 0;
    fragSent = fragRecv = dropTooBig = mssClamped = 0;
    v6Tx = v6Rx = 0;
}

void Impl::closeTunLocked() {
    if (tunFd >= 0) {
        plat::closeFd(tunFd);
        tunFd = -1;
    }
}

void Impl::resetRuntimeLocked() {
    for (auto& p : peers) {
        for (Session& s : p->sess) s.clear();
        p->pend.wipe();
    }
    for (GuestSess& g : grp.guests) g.s.clear();
    peers.clear();
    doomed.clear();
    havePeer = false;
    crypto::wipe(grp.secret, sizeof grp.secret);
    crypto::wipe(&grp.guest, sizeof grp.guest);
    grp = GroupState();
    view = NetView();
    viewKey.clear();
    layoutVer = 0;
    ll6.clear();
    pokes.clear();
    rxBytes = txBytes = rxPkts = txPkts = 0;
    bcastTx = bcastRx = mcastTx = mcastRx = 0;
    authFail = punchRx = hsRx = dropped = handshakes = dupDropped = 0;
    dropForeignDst = dropNoSession = dropBadHdr = dropRxSrc = dropRxDst = tunWriteErr = 0;
    udpQueued = udpDropped = 0;
    resetFragStatsLocked();
    resetFlowsLocked();
    outq.clear();
    udpAssoc.clear();
    fragFix.clear();
    udpFixups = 0;
    lastRxMs = lastTxMs = 0;
    connectStartMs = connectedSinceMs = 0;
    closeTunLocked();
}

void Impl::startThreadLocked() {
    if (th.joinable()) return;
    running = true;
    th = std::thread([this] { loop(); });
}

void Impl::stopThread() {  // must be called without holding mu
    if (!th.joinable()) return;
    running = false;
    wake();
    th.join();
}

void Impl::failLocked(const std::string& why) {
    lastErr = why;
    LBLOG("ошибка: %s", why.c_str());
    setState(ST_FAILED);
}

void Impl::failTunLocked(const std::string& why) {
    closeTunLocked();
    failLocked(why);
}

// ============================================================ STUN

void Impl::stunKeepalive(uint64_t now) {
    stunPend.erase(std::remove_if(stunPend.begin(), stunPend.end(),
                                  [now](const StunPend& p) { return now - p.sentMs > 8000; }),
                   stunPend.end());
    int sent[2] = {0, 0};  // at most two servers per address family
    for (size_t i = 0; i < stun.size(); i++) {
        if (!stun[i].ok) continue;
        int& cnt = sent[stun[i].addr.v6 ? 1 : 0];
        if (cnt >= 2) continue;
        StunPend p;
        randomBytes(p.txid, 12);
        p.srv = i;
        p.sentMs = now;
        uint8_t req[20];
        stunBuildRequest(req, p.txid);
        sendRaw(stun[i].addr, req, sizeof req);
        stunPend.push_back(p);
        cnt++;
    }
}

void Impl::onStun(const uint8_t* b, size_t n) {
    int st = state.load();
    if (!(st == ST_READY || (grp.role == 1 && st >= ST_CONNECTING && st <= ST_STALLED))) return;
    uint8_t tx[12];
    if (!stunGetTxid(b, n, tx)) return;
    for (size_t i = 0; i < stunPend.size(); i++) {
        if (memcmp(stunPend[i].txid, tx, 12) != 0) continue;
        size_t si = stunPend[i].srv;
        stunPend.erase(stunPend.begin() + (long)i);
        Addr m;
        if (si < stun.size() && stunParseResponse(b, n, tx, m)) {
            StunServer& s = stun[si];
            if (s.ok && s.mapped != m) {
                mappingChanged = true;
                LBLOG("STUN: внешний адрес изменился %s -> %s", addrStr(s.mapped).c_str(), addrStr(m).c_str());
                s.mapped = m;
            }
        }
        return;
    }
}

// Creator: empty datagrams to the addresses of newcomers (see Engine::openHint) open the creator's NAT for them.
void Impl::sendPokes(uint64_t now) {
    for (size_t i = 0; i < pokes.size();) {
        Poke& k = pokes[i];
        if (now >= k.until) {
            pokes.erase(pokes.begin() + (long)i);
            continue;
        }
        if (now >= k.next) {
            uint8_t pk[PUNCH_LEN];
            pk[0] = T_PUNCH;
            randomBytes(pk + 1, PUNCH_LEN - 1);  // matches no peer: the receiver drops it
            sendRaw(k.a, pk, PUNCH_LEN);
            k.next = now + 400;
        }
        i++;
    }
}

// ============================================================ main loop

void Impl::loop() {
    while (running.load()) {
        int timeout;
        int tfd;
        int fd4 = -1, fd6 = -1;
        bool out4 = false, out6 = false;  // the queue is a FIFO: only the socket of its head packet matters
        {
            std::lock_guard<std::mutex> g(mu);
            if (!outq.empty()) (outq.front().to.v6 ? out6 : out4) = true;
            fd4 = s4 ? s4->fd() : -1;
            fd6 = s6 ? s6->fd() : -1;
            int64_t t = (int64_t)nextTickMs - (int64_t)nowMs();
            if (t < 0) t = 0;
            if (t > 1000) t = 1000;
            timeout = (int)t;
            tfd = tunFd;
        }
        pollfd fds[4];
        int nf = 0, ti = -1, i4 = -1, i6 = -1;
        fds[nf++] = plat::pollItem(wakeFd[0], POLLIN);
        if (fd4 >= 0) {
            i4 = nf;
            fds[nf++] = plat::pollItem(fd4, (short)(POLLIN | (out4 ? POLLOUT : 0)));
        }
        if (fd6 >= 0) {
            i6 = nf;
            fds[nf++] = plat::pollItem(fd6, (short)(POLLIN | (out6 ? POLLOUT : 0)));
        }
        if (tfd >= 0) {
            ti = nf;
            fds[nf++] = plat::pollItem(tfd, POLLIN);
        }
        int r = plat::pollFds(fds, nf, timeout);
        if (r < 0 && errno != EINTR) plat::sleepMs(10);
        std::lock_guard<std::mutex> g(mu);
        if (!running.load()) break;
        uint64_t now = nowMs();
        if (r > 0) {
            if (fds[0].revents & POLLIN) drainWake();
            if ((i4 >= 0 && (fds[i4].revents & POLLOUT)) || (i6 >= 0 && (fds[i6].revents & POLLOUT))) flushOut();
            if (i4 >= 0 && (fds[i4].revents & POLLIN) && s4) readUdp(s4.get(), now);
            if (i6 >= 0 && (fds[i6].revents & POLLIN) && s6) readUdp(s6.get(), now);
            if (ti >= 0 && tunFd == tfd && fds[ti].revents) readTun(now, fds[ti].revents);
        }
        sweepDoomed();
        if (!outq.empty()) flushOut();
        tick(now);
        if (!outq.empty()) flushOut();
    }
}

void Impl::tick(uint64_t now) {
    gcAssoc(now);
    uint64_t due = now + 1000;
    const int st = state.load();
    const bool group = grp.role != 0;
    const bool active = st >= ST_CONNECTING && st <= ST_STALLED;
    // The public addresses are kept alive (and watched) while the code is waiting for somebody; a group's creator
    // keeps doing it all the time, because newcomers can come at any moment.
    if (haveIdentity && (st == ST_READY || (active && grp.role == 1))) {
        if (now >= nextStunMs) {
            stunKeepalive(now);
            nextStunMs = now + (uint64_t)cfg.stunKeepMs;
        }
        due = std::min(due, nextStunMs);
    }
    if (group && (st == ST_READY || active)) {
        groupTick(now);
        std::vector<Peer*> ps;
        for (auto& p : peers) ps.push_back(p.get());
        for (Peer* p : ps) peerTick(p, now, due);
        sweepDoomed();
        sendPokes(now);
        if (!pokes.empty()) due = std::min(due, now + 250);
        if (active) {
            int nconn = connectedPeers(now, (uint64_t)cfg.stallMs);
            if (nconn > 0) {
                if (st != ST_CONNECTED) {
                    if (!connectedSinceMs) connectedSinceMs = now;
                    setState(ST_CONNECTED);
                }
            } else if (presentPeers() == 0) {
                if (st != ST_CONNECTING) {
                    connectedSinceMs = 0;
                    setState(ST_CONNECTING);
                }
            } else if (st == ST_CONNECTED) {
                setState(ST_STALLED);
            }
        }
    } else if (!group && active && !peers.empty()) {
        peerTick(peers[0].get(), now, due);
    }
    nextTickMs = due;
}

// ============================================================ public API: preparing

Engine::Engine() : p_(new Impl()) {}

Engine::~Engine() { stop(); }

void Engine::setConfig(const Config& c) {
    std::lock_guard<std::mutex> g(p_->mu);
    p_->cfg = c;
}

void Engine::setSocketFactory(UdpFactory f) {
    std::lock_guard<std::mutex> g(p_->mu);
    p_->factory = std::move(f);
}

namespace {

// Public (server reflexive) candidates: up to two per family. An IPv6 one that the code already implies (an address
// of the list with the IPv6 port) is not written twice.
void addSrflx(Offer& o, const std::vector<Addr>& distinct) {
    int n4 = 0, n6 = 0;
    for (const Addr& a : distinct) {
        int& cnt = a.v6 ? n6 : n4;
        if (cnt >= 2 || !addrUsablePeer(a)) continue;
        if (a.v6) {
            bool implied = false;
            for (const Ip6& x : o.v6) implied |= (x == a.ip6 && o.port6 == a.port);
            if (implied) {
                cnt++;
                continue;
            }
            Candidate c{1, 0, a.port};
            c.v6 = true;
            c.ip6 = a.ip6;
            o.cands.push_back(c);
        } else {
            o.cands.push_back(Candidate{1, a.ip4, a.port});
        }
        cnt++;
    }
}

std::vector<Addr> distinctMapped(const std::vector<StunServer>& stun) {
    std::vector<Addr> d;
    for (const StunServer& sv : stun)
        if (sv.ok && std::find(d.begin(), d.end(), sv.mapped) == d.end()) d.push_back(sv.mapped);
    return d;
}

}  // namespace

int Engine::prepare(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                    const std::string& deviceName, int ttlSec, std::vector<uint8_t>& offerOut) {
    return prepareCommon(false, stunServers, localIps, deviceName, ttlSec, offerOut);
}

int Engine::prepareGroup(const std::vector<std::string>& stunServers, const std::vector<std::string>& localIps,
                         const std::string& deviceName, int ttlSec, std::vector<uint8_t>& codeOut) {
    return prepareCommon(true, stunServers, localIps, deviceName, ttlSec, codeOut);
}

int Engine::prepareCommon(bool group, const std::vector<std::string>& stunServers,
                          const std::vector<std::string>& localIps, const std::string& deviceName, int ttlSec,
                          std::vector<uint8_t>& offerOut) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> life(s.lifeMu);
    int st = s.state.load();
    if (st == ST_CONNECTING || st == ST_CONNECTED || st == ST_STALLED) return 3;
    if (st == ST_FAILED) stopInternal();

    s.stopThread();
    {
        std::lock_guard<std::mutex> g(s.mu);
        if (s.grp.role != 0 && s.haveSocket()) s.sendBye(nowMs());  // leaving the previous group
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
    int answered = stunGather(s.s4.get(), s.s6.get(), servers, s.cfg.stunTimeoutMs);
    LBLOG("STUN: ответили %d из %d (запрошено %d)", answered, (int)servers.size(), (int)stunServers.size());

    std::lock_guard<std::mutex> g(s.mu);
    s.stun.clear();
    for (const StunServer& sv : servers)
        if (sv.ok) s.stun.push_back(sv);
    // The NAT type comes from IPv4 servers only: IPv6 normally has no address translation, so its answers say nothing
    // about it.
    std::vector<Addr> distinct = distinctMapped(s.stun);
    std::vector<Addr> distinct4Servers;
    int servers4 = 0;
    for (const StunServer& sv : s.stun) {
        if (sv.addr.v6) continue;
        servers4++;
        if (std::find(distinct4Servers.begin(), distinct4Servers.end(), sv.mapped) == distinct4Servers.end())
            distinct4Servers.push_back(sv.mapped);
    }
    int nat = 0;
    if (servers4 >= 2) nat = distinct4Servers.size() == 1 ? 1 : 2;
    s.myNat = nat;
    for (const Addr& a : distinct) LBLOG("внешний адрес: %s", addrStr(a).c_str());
    LBLOG("тип NAT (IPv4): %s", nat == 1 ? "конусный (EIM)" : nat == 2 ? "симметричный (EDM)" : "не определён");

    Offer o;
    o.version = group ? kOfferVersionGroup : kOfferVersion;
    o.expiresAt = (uint32_t)(wallMs() / 1000 + (uint64_t)(ttlSec > 0 ? ttlSec : 600));
    o.nat = (uint8_t)nat;
    o.name = sanitize(deviceName, 24);
    o.port6 = s.s6 ? s.s6->port() : 0;
    std::vector<uint32_t> seen;
    for (const std::string& t : localIps) {
        uint32_t ip;
        if (parseIp(t, ip)) {
            if (ip == 0 || !s.s4) continue;
            if (std::find(seen.begin(), seen.end(), ip) != seen.end()) continue;
            if (seen.size() >= 4) continue;
            seen.push_back(ip);
            o.cands.push_back(Candidate{0, ip, s.s4->port()});
            continue;
        }
        // IPv6: only addresses that can be used across the tunnel (global or unique-local), at most three. They are
        // mirrored through the tunnel and, together with the port of the IPv6 socket, are the IPv6 host candidates.
        Ip6 a6;
        if (!parseIp6(t, a6)) continue;
        if (ip6IsUnspecified(a6) || ip6IsLoopback(a6) || ip6IsLinkLocal(a6) || ip6IsMulticast(a6) || ip6IsV4Mapped(a6))
            continue;
        if (o.v6.size() >= 3 || std::find(o.v6.begin(), o.v6.end(), a6) != o.v6.end()) continue;
        o.v6.push_back(a6);
    }
    addSrflx(o, distinct);
    if (offerCandidates(o).empty()) {
        s.lastErr = "нет сетевых адресов";
        s.setState(ST_IDLE);
        return 2;
    }
    if (group) {
        o.group = true;
        randomBytes(o.gsecret, sizeof o.gsecret);
        o.gthird = groupPickThird(o.gsecret, seen);
        o.gmax = (uint8_t)kGroupMax;
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
    if (group) {
        GroupState& gs = s.grp;
        gs = GroupState();
        gs.role = 1;
        memcpy(gs.secret, o.gsecret, 32);
        groupGuestKeys(o.gsecret, gs.guest);
        gs.third = o.gthird;
        gs.net4 = groupNet4(o.gthird);
        gs.net6 = groupNet6(o.gsecret);
        gs.maxMembers = o.gmax;
        gs.mySlot = 1;
        gs.joinUntilS = o.expiresAt;
        s.rebuildNets();
    }
    s.nextStunMs = nowMs() + (uint64_t)s.cfg.stunKeepMs;
    s.nextTickMs = 0;
    s.setState(ST_READY);
    s.startThreadLocked();
    int fam = offerFamilies(o);
    LBLOG("%s создан: кандидатов %d, адресов IPv6 %d, доступность: %s, действует до %u", group ? "код группы" : "код",
          (int)offerCandidates(o).size(), (int)o.v6.size(),
          fam == 3 ? "IPv4 и IPv6" : fam == 2 ? "только IPv6" : "только IPv4", (unsigned)o.expiresAt);
    if (group)
        LBLOG("группа: сеть %s/24, до %d устройств", ipStr(s.grp.net4).c_str(), (int)o.gmax);
    return 0;
}

int Engine::renewGroup(int ttlSec, std::vector<uint8_t>& codeOut) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    int st = s.state.load();
    if (s.grp.role != 1 || !s.haveIdentity || !(st == ST_READY || (st >= ST_CONNECTING && st <= ST_STALLED))) return 1;
    Offer o = s.myOffer;
    o.expiresAt = (uint32_t)(wallMs() / 1000 + (uint64_t)(ttlSec > 0 ? ttlSec : 600));
    // The public addresses may have changed since the first code: take the current ones.
    o.cands.erase(std::remove_if(o.cands.begin(), o.cands.end(), [](const Candidate& c) { return c.type == 1; }),
                  o.cands.end());
    addSrflx(o, distinctMapped(s.stun));
    if (!offerEncode(o, codeOut)) return 2;
    s.myOffer = o;
    s.grp.joinUntilS = o.expiresAt;
    s.mappingChanged = false;
    LBLOG("код группы продлён до %u", (unsigned)o.expiresAt);
    return 0;
}

int Engine::joinGroup(const std::vector<uint8_t>& blob) {
    Offer o;
    int rc = offerDecode(blob.data(), blob.size(), o);
    if (rc != OFFER_OK) return rc;
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.haveIdentity || s.state.load() != ST_READY) return OFFER_NOT_READY;
    if (s.grp.role != 0 || s.havePeer || !s.peers.empty()) return OFFER_GROUP_BUSY;
    if (!o.group) return OFFER_NOT_GROUP;
    if (offerExpired(s.myOffer)) return OFFER_OWN_EXPIRED;
    if (memcmp(o.pub, s.kp.pub, 32) == 0) return OFFER_OWN;
    if (offerExpired(o)) return OFFER_EXPIRED;
    uint64_t now = nowMs();
    Peer* c = s.addPeer(1, o, blob, now);
    if (c->cands.empty()) {
        s.peers.clear();
        return OFFER_NO_CANDIDATES;
    }
    c->isCreator = true;
    c->guestMode = true;
    c->initiator = true;  // the newcomer always knocks
    GroupState gs;
    gs.role = 2;
    memcpy(gs.secret, o.gsecret, 32);
    groupGuestKeys(o.gsecret, gs.guest);
    gs.third = o.gthird;
    gs.net4 = groupNet4(o.gthird);
    gs.net6 = groupNet6(o.gsecret);
    gs.maxMembers = o.gmax;
    gs.joinState = 1;
    gs.joinStartMs = now;
    gs.nextJoinMs = 0;
    s.grp = gs;
    s.lastErr.clear();
    for (const Candidate& k : offerCandidates(s.myOffer))
        if (!k.v6 && k.type == 0 && (k.ip & 0xFFFFFF00u) == gs.net4)
            LBLOG("внимание: локальная сеть этого устройства (%s) совпадает с сетью группы %s/24", ipStr(k.ip).c_str(),
                  ipStr(gs.net4).c_str());
    s.nextTickMs = 0;
    s.wake();
    int fam = offerFamilies(o);
    LBLOG("вход в группу \"%s\": кандидатов %d, доступность %s, сеть %s/24", o.name.c_str(), (int)c->cands.size(),
          fam == 3 ? "IPv4+IPv6" : fam == 2 ? "IPv6" : "IPv4", ipStr(gs.net4).c_str());
    return OFFER_OK;
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
    for (const Candidate& k : offerCandidates(o, false)) {
        if (!c.empty()) c += ",";
        c += strfmt("%s:%s", k.type == 0 ? "host" : "srflx", addrStr(candAddr(k)).c_str());
    }
    std::string v6;
    for (const Ip6& a : o.v6) v6 += (v6.empty() ? "" : ",") + ip6Str(a);
    int fam = offerFamilies(o);
    int common = -1;  // -1: our own code is not made yet
    {
        std::lock_guard<std::mutex> g(p_->mu);
        if (p_->haveIdentity) common = (offerFamilies(p_->myOffer) & fam) != 0 ? 1 : 0;
    }
    text = strfmt("code=%d\nname=%s\nexpires=%u\nnat=%d\ncands=%s\nv6=%s\nfamilies=%d\ncommon=%d\ngroup=%d\nmax=%d\n", rc,
                  o.name.c_str(), (unsigned)o.expiresAt, (int)o.nat, c.c_str(), v6.c_str(), fam, common, o.group ? 1 : 0,
                  o.group ? (int)o.gmax : 0);
    return rc;
}

int Engine::setPeer(const std::vector<uint8_t>& blob) {
    Offer o;
    int rc = offerDecode(blob.data(), blob.size(), o);
    if (rc != OFFER_OK) return rc;
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.haveIdentity || s.state.load() != ST_READY || s.grp.role != 0) return OFFER_NOT_READY;
    if (offerExpired(s.myOffer)) return OFFER_OWN_EXPIRED;
    if (memcmp(o.pub, s.kp.pub, 32) == 0) return OFFER_OWN;
    if (o.group) return OFFER_NOT_GROUP;
    if (offerExpired(o)) return OFFER_EXPIRED;
    s.peers.clear();
    s.doomed.clear();
    Peer* p = s.addPeer(2, o, blob, nowMs());
    s.havePeer = true;
    s.lay = computeLayout(s.myOffer, o);
    p->initiator = s.lay.initiator;
    s.rebuildNets();
    LBLOG("друг: \"%s\", кандидатов %d, NAT %d; сеть %s/%d, мой %s, друг %s, роль %s", o.name.c_str(), (int)p->cands.size(),
          (int)o.nat, ipStr(s.lay.net).c_str(), s.lay.prefix, ipStr(s.lay.myIp).c_str(), ipStr(s.lay.peerIp).c_str(),
          p->initiator ? "инициатор" : "ответчик");
    {
        int mine = offerFamilies(s.myOffer), theirs = offerFamilies(o);
        auto fn = [](int f) { return f == 3 ? "IPv4+IPv6" : f == 2 ? "IPv6" : f == 1 ? "IPv4" : "нет"; };
        LBLOG("доступность: у меня %s, у друга %s%s", fn(mine), fn(theirs),
              (mine & theirs) ? "" : " — общего протокола нет, соединение невозможно");
    }
    LBLOG("IPv6: сеть %s/%d, мой %s, друг %s; реальных адресов у друга %d, у меня %d", ip6Str(s.lay.net6).c_str(),
          s.lay.prefix6, ip6Str(s.lay.myIp6).c_str(), ip6Str(s.lay.peerIp6).c_str(), (int)s.lay.aliasPeer6.size(),
          (int)s.lay.aliasMine6.size());
    return OFFER_OK;
}

bool Engine::layout(Layout& out) {
    std::lock_guard<std::mutex> g(p_->mu);
    if (!p_->havePeer || p_->grp.role != 0) return false;
    out = p_->lay;
    return true;
}

std::string Engine::netLayout() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->layoutText();
}

// ============================================================ public API: running

int Engine::start(int tunFd, int mtu) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    auto fail = [&](int code, const char* msg) {
        if (tunFd >= 0) plat::closeFd(tunFd);
        s.lastErr = msg;
        LBLOG("старт отклонён: %s", msg);
        return code;
    };
    const bool group = s.grp.role != 0;
    if (s.state.load() != ST_READY || !s.haveIdentity || !s.haveSocket()) return fail(1, "движок не готов к запуску");
    if (!group && (!s.havePeer || s.peers.empty())) return fail(1, "движок не готов к запуску");
    if (group && s.grp.role == 2 && s.grp.joinState != 2) return fail(1, "вас ещё не приняли в группу");
    if (group && !s.view.valid) return fail(1, "сеть группы не определена");
    if (!group) {
        if (offerExpired(s.myOffer)) return fail(2, "ваш код истёк");
        if (offerExpired(s.peers[0]->offer)) return fail(3, "код друга истёк");
    }
    if (tunFd < 0) return fail(4, "нет TUN-интерфейса");
    plat::setNonBlocking(tunFd);

    uint64_t now = nowMs();
    if (!group) {
        Peer& p = *s.peers[0];
        for (Session& x : p.sess) x.clear();
        p.pend.wipe();
        p.haveLast = false;
        p.lastInitTs = p.lastTsSent = 0;
        p.punchSeen.clear();
        p.addrValid = false;
        p.left = p.connected = p.everConnected = false;
        p.rttMs = -1;
        p.lastRxMs = p.lastTxMs = p.lastDirectRxMs = p.lastRelayRxMs = 0;
        p.directEchoMs = p.relayEchoMs = 0;
        p.connectedSinceMs = 0;
        p.nextPingMs = p.nextRekeyMs = p.nextProbeMs = 0;
        p.startMs = now;
        p.rxBytes = p.txBytes = 0;
        s.lastRxMs = s.lastTxMs = 0;
        s.connectedSinceMs = 0;
        s.outq.clear();
    }
    s.rxBytes = s.txBytes = s.rxPkts = s.txPkts = 0;
    s.bcastTx = s.bcastRx = s.mcastTx = s.mcastRx = 0;
    s.authFail = s.punchRx = s.hsRx = s.dropped = s.handshakes = s.dupDropped = 0;
    memset(s.psk, 0, sizeof s.psk);
    s.dropForeignDst = s.dropNoSession = s.dropBadHdr = s.dropRxSrc = s.dropRxDst = s.tunWriteErr = 0;
    s.udpQueued = s.udpDropped = 0;
    s.resetFragStatsLocked();
    s.resetFlowsLocked();
    s.udpAssoc.clear();
    s.fragFix.clear();
    s.udpFixups = 0;
    s.closeTunLocked();
    s.tunFd = tunFd;
    s.mtu = mtu;
    s.connectStartMs = now;
    s.nextTickMs = 0;
    s.setState(ST_CONNECTING);
    s.startThreadLocked();
    s.wake();
    LBLOG("старт: TUN fd=%d, MTU %d%s", tunFd, mtu, group ? " (группа)" : "");
    return 0;
}

int Engine::swapTun(int newFd) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    int st = s.state.load();
    if (newFd < 0) return 1;
    if (s.tunFd < 0 || !(st >= ST_CONNECTING && st <= ST_STALLED)) {
        plat::closeFd(newFd);
        return 1;
    }
    plat::setNonBlocking(newFd);
    int old = s.tunFd;
    s.tunFd = newFd;
    plat::closeFd(old);
    s.udpAssoc.clear();
    s.fragFix.clear();
    for (auto& p : s.peers) p->reasm.clear();
    s.wake();
    LBLOG("TUN заменён: fd=%d, версия сети %u", newFd, (unsigned)s.layoutVer);
    return 0;
}

void Engine::retry() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.state.load() != ST_FAILED || s.tunFd < 0 || s.peers.empty()) return;
    if (s.grp.role == 0 && !s.havePeer) return;
    uint64_t now = nowMs();
    s.connectStartMs = now;
    for (auto& p : s.peers) {
        p->startMs = now;
        p->nextProbeMs = 0;
    }
    s.nextTickMs = 0;
    s.lastErr.clear();
    s.setState(ST_CONNECTING);
    s.wake();
}

void Engine::stopInternal() {
    Impl& s = *p_;
    // The thread stops first: after that nothing else is sent to the peers, so the goodbye is the last datagram they
    // get. (Said while the thread still ran, a pong answering a late ping could follow it and mark the peer as present
    // again for a moment.)
    s.stopThread();
    {
        std::lock_guard<std::mutex> g(s.mu);
        if (s.engineActive() && s.haveSocket()) {
            s.sendBye(nowMs());
            s.flushOut();  // nobody flushes the queue any more
        }
    }
    std::lock_guard<std::mutex> g(s.mu);
    s.resetRuntimeLocked();
    s.s4.reset();
    s.s6.reset();
    for (int i = 0; i < 2; i++) {
        if (s.wakeFd[i] >= 0) plat::closeFd(s.wakeFd[i]);
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

// ============================================================ public API: profile, members

bool Engine::setProfile(const std::string& name, const std::vector<uint8_t>& avatar) {
    if (avatar.size() > kAvatarMax) return false;
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    std::string nm = utf8Trunc(name, kProfileNameMax);
    if (nm == s.profName && avatar == s.avatar) return true;
    s.profName = nm;
    s.avatar = avatar;
    s.profVer++;
    if (s.profVer == 0) s.profVer = 1;
    s.resetProfileOut();
    s.nextTickMs = 0;
    s.wake();
    return true;
}

std::string Engine::members() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->membersText();
}

bool Engine::memberAvatar(int slot, std::vector<uint8_t>& out) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.view.valid && slot == s.view.mySlot) {
        if (s.avatar.empty()) return false;
        out = s.avatar;
        return true;
    }
    Peer* p = s.peerBySlot(slot);
    if (!p || p->guestMode || p->avatar.empty()) return false;
    out = p->avatar;
    return true;
}

// ============================================================ public API: the creator's mailbox

namespace {

void hintKey(const uint8_t secret[32], uint8_t key[32]) {
    uint8_t buf[10 + 32];
    memcpy(buf, "LBhint-key", 10);
    memcpy(buf + 10, secret, 32);
    crypto::blake2s(key, 32, nullptr, 0, buf, sizeof buf);
    crypto::wipe(buf, sizeof buf);
}

}  // namespace

std::string Engine::hintTopic() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.grp.role == 0) return std::string();
    uint8_t buf[12 + 32], h[32];
    memcpy(buf, "LBhint-topic", 12);
    memcpy(buf + 12, s.grp.secret, 32);
    crypto::blake2s(h, 32, nullptr, 0, buf, sizeof buf);
    static const char* hex = "0123456789abcdef";
    std::string t = "lb";
    for (int i = 0; i < 12; i++) {
        t.push_back(hex[h[i] >> 4]);
        t.push_back(hex[h[i] & 15]);
    }
    crypto::wipe(buf, sizeof buf);
    return t;
}

// A newcomer's note: where it can be reached. Format: 0xB1 | counter[8] | AEAD(ts[4] | n[1] | n x (family, ip, port)).
bool Engine::sealHint(std::vector<uint8_t>& out) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.grp.role != 2 || s.grp.joinState != 1) return false;
    std::vector<uint8_t> pl(5);
    uint32_t ts = (uint32_t)(wallMs() / 1000);
    pl[0] = (uint8_t)(ts >> 24);
    pl[1] = (uint8_t)(ts >> 16);
    pl[2] = (uint8_t)(ts >> 8);
    pl[3] = (uint8_t)ts;
    int n = 0;
    for (const Candidate& c : offerCandidates(s.myOffer)) {
        if (n >= 6) break;
        if (c.v6) {
            pl.push_back(6);
            pl.insert(pl.end(), c.ip6.begin(), c.ip6.end());
        } else {
            pl.push_back(4);
            for (int i = 3; i >= 0; i--) pl.push_back((uint8_t)(c.ip >> (8 * i)));
        }
        pl.push_back((uint8_t)(c.port >> 8));
        pl.push_back((uint8_t)c.port);
        n++;
    }
    if (n == 0) return false;
    pl[4] = (uint8_t)n;
    uint8_t key[32], ctrb[8];
    hintKey(s.grp.secret, key);
    randomBytes(ctrb, sizeof ctrb);
    uint64_t ctr = be64(ctrb);
    out.assign(1 + 8 + pl.size() + AEAD_TAG, 0);
    out[0] = 0xB1;
    memcpy(out.data() + 1, ctrb, 8);
    crypto::aeadEncrypt(out.data() + 9, key, ctr, nullptr, 0, pl.data(), pl.size());
    crypto::wipe(key, sizeof key);
    return true;
}

int Engine::openHint(const std::vector<uint8_t>& note) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    if (s.grp.role != 1 || !s.engineActive()) return -1;
    if (note.size() < 1 + 8 + 5 + AEAD_TAG || note.size() > 1 + 8 + 5 + 6 * 19 + AEAD_TAG || note[0] != 0xB1) return -1;
    uint8_t key[32];
    hintKey(s.grp.secret, key);
    uint64_t ctr = be64(note.data() + 1);
    size_t clen = note.size() - 9;
    uint8_t pl[5 + 6 * 19];
    bool ok = crypto::aeadDecrypt(pl, key, ctr, nullptr, 0, note.data() + 9, clen);
    crypto::wipe(key, sizeof key);
    if (!ok) return -1;
    size_t plen = clen - AEAD_TAG;
    uint32_t ts = be32(pl);
    uint64_t nowS = wallMs() / 1000;
    if ((nowS > ts ? nowS - ts : ts - nowS) > 900) return -1;
    size_t n = pl[4], pos = 5;
    uint64_t now = nowMs();
    int added = 0;
    for (size_t i = 0; i < n; i++) {
        Addr a;
        if (pos + 1 > plen) break;
        uint8_t fam = pl[pos++];
        if (fam == 4 && pos + 6 <= plen) {
            a = addr4(be32(pl + pos), be16(pl + pos + 4));
            pos += 6;
        } else if (fam == 6 && pos + 18 <= plen) {
            Ip6 x;
            memcpy(x.data(), pl + pos, 16);
            a = addr6(x, be16(pl + pos + 16));
            pos += 18;
        } else {
            break;
        }
        if (!addrUsablePeer(a) || !s.sockFor(a)) continue;
        bool have = false;
        for (Impl::Poke& k : s.pokes) {
            if (k.a == a) {
                k.until = now + 8000;
                have = true;
            }
        }
        if (!have) {
            if (s.pokes.size() >= 16) continue;
            Impl::Poke k;
            k.a = a;
            k.until = now + 8000;
            k.next = 0;
            s.pokes.push_back(k);
        }
        added++;
    }
    if (added) {
        LBLOG("записка новичка: адресов для прогрева %d", added);
        s.nextTickMs = 0;
        s.wake();
    }
    return added;
}

// ============================================================ public API: status and diagnostics

void Engine::status(int64_t out[STATUS_FIELDS]) {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    uint64_t now = nowMs();
    memset(out, 0, sizeof(int64_t) * STATUS_FIELDS);
    const int st = s.state.load();
    const bool group = s.grp.role != 0;
    out[0] = st;
    out[1] = (int64_t)s.rxBytes;
    out[2] = (int64_t)s.txBytes;
    out[3] = (int64_t)s.rxPkts;
    out[4] = (int64_t)s.txPkts;
    out[5] = -1;
    out[6] = s.lastRxMs ? (int64_t)(now - s.lastRxMs) : -1;
    out[7] = (s.connectedSinceMs && (st == ST_CONNECTED || st == ST_STALLED)) ? (int64_t)((now - s.connectedSinceMs) / 1000) : 0;
    out[8] = -1;
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
    out[19] = 0;
    out[20] = s.haveIdentity ? (int64_t)s.myOffer.expiresAt : 0;
    out[21] = (int64_t)s.handshakes;
    out[22] = 0;
    if (!group && !s.peers.empty()) {
        const Peer& p = *s.peers[0];
        out[5] = p.rttMs;
        out[8] = p.addrValid ? (addrIsLocalNet(p.addr) ? 1 : 0) : -1;
        out[19] = (int64_t)p.offer.nat;
        out[22] = p.left ? 1 : 0;
    } else if (group) {
        // aggregates over the members that are in touch: the worst round trip, "local" only when every path is local
        int64_t rtt = -1;
        int local = 0, remote = 0;
        for (const auto& p : s.peers) {
            if (p->guestMode || p->left) continue;
            if (!(p->lastRxMs && now - p->lastRxMs < (uint64_t)s.cfg.stallMs)) continue;
            rtt = std::max(rtt, p->rttMs);
            if (p->addrValid) (addrIsLocalNet(p->addr) ? local : remote)++;
        }
        out[5] = rtt;
        out[8] = (local + remote) == 0 ? -1 : (remote == 0 ? 1 : 0);
    }
    out[23] = (int64_t)s.layoutVer;
    out[24] = s.presentPeers();
    out[25] = s.connectedPeers(now, (uint64_t)s.cfg.stallMs);
    out[26] = s.grp.role;
    out[27] = s.grp.joinState;
    out[28] = group ? s.grp.mySlot : 0;
    out[29] = s.grp.role == 1 ? (int64_t)s.grp.joinUntilS : 0;
    out[30] = (int64_t)(s.grp.relayFwd + s.grp.relayTx);
    out[31] = s.memberListSettled() ? 1 : 0;
}

std::string Engine::info() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    std::string o;
    const Peer* p0 = (s.grp.role == 0 && !s.peers.empty()) ? s.peers[0].get() : nullptr;
    o += strfmt("path=%s\n", p0 && p0->addrValid ? addrStr(p0->addr).c_str() : "");
    if (p0 && s.havePeer) {
        o += strfmt("myIp=%s\npeerIp=%s\nnet=%s\nprefix=%d\nrole=%s\npeerName=%s\n", ipStr(s.lay.myIp).c_str(),
                    ipStr(s.lay.peerIp).c_str(), ipStr(s.lay.net).c_str(), s.lay.prefix,
                    p0->initiator ? "initiator" : "responder", s.displayName(p0).c_str());
        std::string ra, ap;
        for (uint32_t x : s.lay.aliasMine) ra += (ra.empty() ? "" : ",") + ipStr(x);
        for (uint32_t x : s.lay.aliasPeer) ap += (ap.empty() ? "" : ",") + ipStr(x);
        o += "realIp=" + ra + "\naliasPeer=" + ap + "\n";
        std::string ra6, ap6;
        for (const Ip6& x : s.lay.aliasMine6) ra6 += (ra6.empty() ? "" : ",") + ip6Str(x);
        for (const Ip6& x : s.lay.aliasPeer6) ap6 += (ap6.empty() ? "" : ",") + ip6Str(x);
        o += strfmt("myIp6=%s\npeerIp6=%s\nnet6=%s\nprefix6=%d\n", ip6Str(s.lay.myIp6).c_str(),
                    ip6Str(s.lay.peerIp6).c_str(), ip6Str(s.lay.net6).c_str(), s.lay.prefix6);
        o += "realIp6=" + ra6 + "\naliasPeer6=" + ap6 + "\n";
    }
    if (s.grp.role != 0) {
        o += strfmt("group=%s\nslot=%d\nmaxMembers=%d\nnet=%s\nmyIp=%s\nnet6=%s\nmyIp6=%s\njoinUntil=%llu\n",
                    s.grp.role == 1 ? "creator" : "member", s.grp.mySlot, s.grp.maxMembers, ipStr(s.grp.net4).c_str(),
                    s.view.valid ? ipStr(s.view.myIp).c_str() : "", ip6Str(s.grp.net6).c_str(),
                    s.view.valid ? ip6Str(s.view.myIp6).c_str() : "", (unsigned long long)s.grp.joinUntilS);
        o += strfmt("relayForwarded=%llu\nrelaySent=%llu\nduplicates=%llu\nguests=%d\npokes=%d\n",
                    (unsigned long long)s.grp.relayFwd, (unsigned long long)s.grp.relayTx,
                    (unsigned long long)s.dupDropped, (int)s.grp.guests.size(), (int)s.pokes.size());
    }
    o += strfmt("localPort=%u\nlocalPort6=%u\nstun=%d\nmtu=%d\n", (unsigned)(s.s4 ? s.s4->port() : 0),
                (unsigned)(s.s6 ? s.s6->port() : 0), (int)s.stun.size(), s.mtu);
    o += strfmt("transport4=%s\ntransport6=%s\n", s.s4 ? "ok" : (s.sockErr4.empty() ? "-" : s.sockErr4.c_str()),
                s.s6 ? "ok" : (s.sockErr6.empty() ? "-" : s.sockErr6.c_str()));
    o += strfmt("txErr4=%llu\ntxErr6=%llu\nnoRoute=%llu\n", (unsigned long long)s.txErr4, (unsigned long long)s.txErr6,
                (unsigned long long)s.noRoute);
    std::string m;
    for (const StunServer& sv : s.stun) {
        if (!m.empty()) m += ",";
        m += addrStr(sv.mapped);
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
    return p_->s4 ? p_->s4->fd() : -1;
}

int Engine::socketFd6() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->s6 ? p_->s6->fd() : -1;
}

uint16_t Engine::localPort() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->s4 ? p_->s4->port() : 0;
}

uint16_t Engine::localPort6() {
    std::lock_guard<std::mutex> g(p_->mu);
    return p_->s6 ? p_->s6->port() : 0;
}

}  // namespace lb
