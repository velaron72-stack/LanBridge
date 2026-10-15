// LanBridge native core: engine, peers and groups. The list of peers, the virtual network, admission to a group, the
// member list, relaying through the creator, names and avatars.
#include <algorithm>
#include <cstring>

#include "engine_impl.h"

namespace lb {

using Impl = Engine::Impl;

// ============================================================ peers

Peer* Impl::peerBySlot(int slot) {
    for (auto& p : peers)
        if (p->slot == slot) return p.get();
    return nullptr;
}

Peer* Impl::peerByPub(const uint8_t* pub) {
    for (auto& p : peers)
        if (memcmp(p->offer.pub, pub, 32) == 0) return p.get();
    return nullptr;
}

Peer* Impl::peerBySid(const uint8_t* sid) {
    for (auto& p : peers)
        if (memcmp(p->sid, sid, 8) == 0) return p.get();
    return nullptr;
}

Peer* Impl::creatorPeer() {
    for (auto& p : peers)
        if (p->isCreator) return p.get();
    return nullptr;
}

std::string Impl::displayName(const Peer* p) const {
    if (!p->profName.empty()) return p->profName;
    if (!p->offer.name.empty()) return p->offer.name;
    return strfmt("участник %d", p->slot);
}

void Impl::filterCands(Peer* p) {
    p->cands.clear();
    int skipped = 0;
    for (const Candidate& k : offerCandidates(p->offer)) {
        Addr a = candAddr(k);
        if (sockFor(a)) p->cands.push_back(a);
        else skipped++;  // a family this device has no socket for: nothing could be sent there
    }
    if (skipped) LBLOG("%s: адресов другого семейства пропущено: %d (нет сокета)", displayName(p).c_str(), skipped);
}

Peer* Impl::addPeer(int slot, const Offer& o, const std::vector<uint8_t>& blob, uint64_t now) {
    std::unique_ptr<Peer> p(new Peer());
    p->slot = slot;
    p->offer = o;
    p->blob = blob;
    p->addedMs = p->startMs = now;
    p->initiator = memcmp(kp.pub, o.pub, 32) < 0;
    deriveSid(p->sid, kp.pub, o.pub);
    filterCands(p.get());
    Peer* raw = p.get();
    peers.push_back(std::move(p));
    return raw;
}

void Impl::removePeer(int slot, const char* why) {
    for (size_t i = 0; i < peers.size(); i++) {
        if (peers[i]->slot != slot) continue;
        LBLOG("%s убран из сети (%s)", displayName(peers[i].get()).c_str(), why);
        for (Session& s : peers[i]->sess) s.clear();
        peers[i]->pend.wipe();
        peers.erase(peers.begin() + (long)i);
        break;
    }
    ll6.erase(std::remove_if(ll6.begin(), ll6.end(), [slot](const LlEntry& e) { return e.slot == slot; }), ll6.end());
    if (grp.role == 1) bumpEntry(slot, false, nullptr, std::vector<uint8_t>());
    rebuildNets();
}

void Impl::sweepDoomed() {
    if (doomed.empty()) return;
    std::vector<int> d;
    d.swap(doomed);
    for (int slot : d)
        if (peerBySlot(slot)) removePeer(slot, "вышел или пропал");
}

// ============================================================ the virtual network

namespace {

std::string joinIp4(const std::vector<uint32_t>& v) {
    std::string s;
    for (uint32_t x : v) s += (s.empty() ? "" : ",") + ipStr(x);
    return s;
}
std::string joinIp6(const std::vector<Ip6>& v) {
    std::string s;
    for (const Ip6& x : v) s += (s.empty() ? "" : ",") + ip6Str(x);
    return s;
}

std::string netText(const NetView& v, const std::string& peer4, const std::string& peer6) {
    std::string t = strfmt("my=%s\npeer=%s\nnet=%s\nprefix=%d\nbcast=%s\ninitiator=%d\nrealMine=%s\nrealPeer=%s\n",
                           ipStr(v.myIp).c_str(), peer4.c_str(), ipStr(v.net).c_str(), v.prefix, ipStr(v.bcast).c_str(),
                           v.initiator ? 1 : 0, joinIp4(v.realMine).c_str(), joinIp4(v.realPeer).c_str());
    t += strfmt("my6=%s\npeer6=%s\nnet6=%s\nprefix6=%d\nrealMine6=%s\nrealPeer6=%s\nslot=%d\ngroup=%d\n",
                ip6Str(v.myIp6).c_str(), peer6.c_str(), ip6Str(v.net6).c_str(), v.prefix6, joinIp6(v.realMine6).c_str(),
                joinIp6(v.realPeer6).c_str(), v.mySlot, v.group ? 1 : 0);
    return t;
}

}  // namespace

// Recomputes every peer's addresses and the TUN view after the member list (or the friend) changed. The layout
// version moves when something the TUN has to be set up with is different.
void Impl::rebuildNets() {
    NetView nv;
    if (grp.role == 0) {
        if (havePeer && !peers.empty()) {
            Peer& p = *peers[0];
            nv.valid = true;
            nv.group = false;
            nv.mySlot = lay.initiator ? 1 : 2;
            nv.net = lay.net;
            nv.myIp = lay.myIp;
            nv.bcast = lay.bcast;
            nv.prefix = lay.prefix;
            nv.net6 = lay.net6;
            nv.myIp6 = lay.myIp6;
            nv.prefix6 = lay.prefix6;
            nv.initiator = lay.initiator;
            nv.realMine = lay.aliasMine;
            nv.realPeer = lay.aliasPeer;
            nv.realMine6 = lay.aliasMine6;
            nv.realPeer6 = lay.aliasPeer6;
            p.slot = lay.initiator ? 2 : 1;
            p.net.ip4 = lay.peerIp;
            p.net.ip6 = lay.peerIp6;
            p.net.aliasPeer = lay.aliasPeer;
            p.net.aliasMine = lay.aliasMine;
            p.net.aliasPeer6 = lay.aliasPeer6;
            p.net.aliasMine6 = lay.aliasMine6;
        }
    } else if (grp.mySlot != 0) {
        std::vector<GroupMemberRef> refs;
        std::vector<Peer*> who;
        for (auto& p : peers) {
            if (p->guestMode) continue;
            refs.push_back(GroupMemberRef{p->slot, &p->offer});
            who.push_back(p.get());
        }
        GroupNets gn = computeGroupNets(grp.net4, grp.net6, grp.mySlot, myOffer, refs);
        for (size_t i = 0; i < who.size(); i++) {
            who[i]->net.ip4 = gn.peers[i].ip4;
            who[i]->net.ip6 = gn.peers[i].ip6;
            who[i]->net.aliasPeer = gn.peers[i].aliasPeer;
            who[i]->net.aliasMine = gn.peers[i].aliasMine;
            who[i]->net.aliasPeer6 = gn.peers[i].aliasPeer6;
            who[i]->net.aliasMine6 = gn.peers[i].aliasMine6;
        }
        nv.valid = true;
        nv.group = true;
        nv.mySlot = grp.mySlot;
        nv.net = grp.net4;
        nv.myIp = gn.myIp4;
        nv.bcast = grp.net4 | 255u;
        nv.prefix = 24;
        nv.net6 = grp.net6;
        nv.myIp6 = gn.myIp6;
        nv.prefix6 = 64;
        nv.realMine = gn.realMine;
        nv.realPeer = gn.realPeer;
        nv.realMine6 = gn.realMine6;
        nv.realPeer6 = gn.realPeer6;
    }
    std::string key = nv.valid ? netText(nv, "", "") : std::string();
    view = nv;
    if (key != viewKey) {
        viewKey = key;
        layoutVer++;
        if (nv.valid)
            LBLOG("сеть: %s/%d, мой адрес %s, зеркалируемых адресов: %d (маршруты), своих: %d; версия %u", ipStr(nv.net).c_str(),
                  nv.prefix, ipStr(nv.myIp).c_str(), (int)nv.realPeer.size(), (int)nv.realMine.size(), (unsigned)layoutVer);
    }
}

std::string Impl::layoutText() const {
    if (!view.valid) return std::string();
    std::string p4, p6;
    const Peer* first = nullptr;
    for (const auto& p : peers)
        if (!p->guestMode && (!first || p->slot < first->slot)) first = p.get();
    if (first) {
        p4 = ipStr(first->net.ip4);
        p6 = ip6Str(first->net.ip6);
    }
    return netText(view, p4, p6) + strfmt("ver=%u\n", (unsigned)layoutVer);
}

bool Impl::inVec(const std::vector<uint32_t>& v, uint32_t x) {
    for (uint32_t y : v)
        if (y == x) return true;
    return false;
}
bool Impl::inVec6(const std::vector<Ip6>& v, const Ip6& x) {
    for (const Ip6& y : v)
        if (y == x) return true;
    return false;
}

Peer* Impl::ownerOf4(uint32_t ip) {
    for (auto& p : peers) {
        if (p->guestMode) continue;
        if (ip == p->net.ip4 || inVec(p->net.aliasPeer, ip)) return p.get();
    }
    return nullptr;
}

Peer* Impl::ownerOf6(const Ip6& a) {
    for (auto& p : peers) {
        if (p->guestMode) continue;
        if (a == p->net.ip6 || inVec6(p->net.aliasPeer6, a)) return p.get();
    }
    return nullptr;
}

bool Impl::isMyAddr(const Peer* p, uint32_t ip) const { return ip == view.myIp || inVec(p->net.aliasMine, ip); }
bool Impl::isMyAddr6(const Peer* p, const Ip6& a) const { return a == view.myIp6 || inVec6(p->net.aliasMine6, a); }
bool Impl::isPeerAddr(const Peer* p, uint32_t ip) const { return ip == p->net.ip4 || inVec(p->net.aliasPeer, ip); }
bool Impl::isPeerAddr6(const Peer* p, const Ip6& a) const { return a == p->net.ip6 || inVec6(p->net.aliasPeer6, a); }

int Impl::presentPeers() const {
    int n = 0;
    for (const auto& p : peers) n += p->guestMode ? 0 : 1;
    return n;
}

int Impl::connectedPeers(uint64_t now, uint64_t freshMs) const {
    int n = 0;
    for (const auto& p : peers) {
        if (p->guestMode || p->left) continue;
        bool hasSession = false;
        for (const Session& s : p->sess)
            if (s.valid && s.confirmed && now - s.createdMs < (uint64_t)cfg.rejectAfterMs) hasSession = true;
        if (hasSession && p->lastRxMs && now - p->lastRxMs < freshMs) n++;
    }
    return n;
}

// A newcomer's member list is complete when it knows everybody that K_WELCOME announced.
bool Impl::memberListSettled() const {
    if (grp.role != 2) return true;
    if (grp.joinState != 2) return false;
    int others = 0;
    for (const auto& p : peers)
        if (!p->guestMode && !p->isCreator) others++;
    return others >= grp.expectOthers;
}

// Link-local IPv6 addresses are not part of the virtual network: a peer's own fe80:: address is learned from what it
// sends, so that an application can answer to it.
void Impl::learnLl6(const Ip6& a, int slot, uint64_t now) {
    for (LlEntry& e : ll6) {
        if (e.a == a) {
            if (e.slot != slot && now - e.ms < 60000) return;  // somebody else's address: no taking over
            e.slot = slot;
            e.ms = now;
            return;
        }
    }
    if (ll6.size() >= kMaxLl) ll6.erase(ll6.begin());
    ll6.push_back(LlEntry{a, slot, now});
}

Peer* Impl::lookupLl6(const Ip6& a, uint64_t now) {
    for (const LlEntry& e : ll6)
        if (e.a == a && now - e.ms < 600000) return peerBySlot(e.slot);
    // Two devices only: the other one is the only possible neighbour.
    Peer* only = nullptr;
    int n = 0;
    for (auto& p : peers) {
        if (p->guestMode) continue;
        only = p.get();
        n++;
    }
    return n == 1 ? only : nullptr;
}

// ============================================================ group: door, member list

void Impl::bumpEntry(int slot, bool present, const uint8_t* pub, const std::vector<uint8_t>& blob) {
    if (slot < 1 || slot > kGroupMax) return;
    GroupState::Entry& e = grp.roster[slot];
    e.used = true;
    e.present = present;
    if (pub) memcpy(e.pub, pub, 32);
    e.blob = present ? blob : std::vector<uint8_t>();
    grp.rosterVer++;
    if (grp.rosterVer == 0) grp.rosterVer = 1;
    e.ver = grp.rosterVer;
}

void Impl::groupTick(uint64_t now) {
    if (grp.role == 0) return;
    for (size_t i = 0; i < grp.guests.size();) {
        GuestSess& g = grp.guests[i];
        uint64_t idle = now - g.lastRxMs;
        if (idle > 30000 || (!g.joined && now - g.createdMs > 30000)) {
            g.s.clear();
            grp.guests.erase(grp.guests.begin() + (long)i);
        } else {
            i++;
        }
    }
    if (grp.role == 2 && grp.joinState == 1) {
        if (now - grp.joinStartMs >= (uint64_t)cfg.joinTimeoutMs) {
            grp.joinState = 3;
            grp.rejectReason = REJ_TIMEOUT;
            lastErr = "создатель группы не отвечает: проверьте, что он запустил группу и код не истёк";
            LBLOG("вход в группу: %s", lastErr.c_str());
        } else if (now >= grp.nextJoinMs) {
            sendJoin(now);
        }
    }
    if (grp.role == 1) {
        for (auto& p : peers) {
            uint64_t last = std::max(p->lastRxMs, p->addedMs);
            // A member that was in touch keeps its place much longer (a sleeping phone comes back by itself: the
            // handshake restarts as long as the creator still knows its key); one that never answered goes soon.
            uint64_t limit = p->everConnected ? (uint64_t)cfg.memberReapMs * 6 : (uint64_t)cfg.memberReapMs / 2;
            if (now - last > limit) {
                LBLOG("%s не отвечает, место освобождено", displayName(p.get()).c_str());
                doomed.push_back(p->slot);
            }
        }
        sweepDoomed();
    }
}

void Impl::sendJoin(uint64_t now) {
    grp.nextJoinMs = now + 700;
    Peer* c = creatorPeer();
    if (!c || !c->guestMode) return;
    Session* s = bestSession(c, now);
    if (!s) return;
    std::vector<uint8_t> blob;
    Offer mine = myOffer;
    mine.group = false;
    if (!offerEncode(mine, blob)) return;
    std::vector<uint8_t> plain = msgJoin(blob);
    sendTransport(c, s, plain.data(), plain.size(), now, true);
}

void Impl::sendGuest(GuestSess* g, const std::vector<uint8_t>& plain, uint64_t now) {
    uint8_t out[DATA_HDR + 64 + AEAD_TAG];
    if (plain.size() > 64) return;
    size_t n = seal(&g->s, plain.data(), plain.size(), out);
    sendRaw(g->addr, out, n);
    (void)now;
}

void Impl::onJoin(GuestSess* g, const uint8_t* plain, size_t n, uint64_t now) {
    if (grp.role != 1) return;
    std::vector<uint8_t> blob;
    Offer o;
    if (!parseJoin(plain, n, blob) || offerDecode(blob.data(), blob.size(), o) != OFFER_OK || o.group ||
        memcmp(o.pub, kp.pub, 32) == 0 || memcmp(o.pub, grp.guest.pub, 32) == 0) {
        sendGuest(g, msgReject(REJ_BAD), now);
        return;
    }
    if (wallMs() / 1000 > grp.joinUntilS + (uint64_t)std::max(0, cfg.joinGraceS)) {
        sendGuest(g, msgReject(REJ_CLOSED), now);
        LBLOG("заявка отклонена: код группы истёк");
        return;
    }
    Peer* ex = peerByPub(o.pub);
    int slot;
    if (ex) {
        slot = ex->slot;  // the newcomer repeats its request (our answer was lost)
    } else {
        if ((int)peers.size() + 1 >= grp.maxMembers) {
            sendGuest(g, msgReject(REJ_FULL), now);
            LBLOG("заявка отклонена: группа заполнена");
            return;
        }
        slot = 0;
        for (int s = 2; s <= grp.maxMembers && !slot; s++)
            if (!peerBySlot(s)) slot = s;
        if (!slot) {
            sendGuest(g, msgReject(REJ_FULL), now);
            return;
        }
        Peer* p = addPeer(slot, o, blob, now);
        p->addr = g->addr;  // where the newcomer was heard from is the first thing to try
        p->addrValid = true;
        p->addrMs = now;
        bumpEntry(slot, true, o.pub, blob);
        rebuildNets();
        LBLOG("в группу вошёл \"%s\": место %d", o.name.c_str(), slot);
    }
    g->joined = true;
    g->slot = slot;
    int others = presentPeers() - 1;
    sendGuest(g, msgWelcome((uint8_t)slot, (uint8_t)grp.maxMembers, (uint8_t)std::max(0, others)), now);
}

void Impl::onWelcome(Peer* p, const uint8_t* plain, size_t n, uint64_t now) {
    uint8_t slot, mx, others;
    if (grp.role != 2 || grp.joinState != 1 || !parseWelcome(plain, n, slot, mx, others)) return;
    grp.mySlot = slot;
    grp.maxMembers = mx;
    grp.expectOthers = others;
    grp.joinState = 2;
    // From now on the creator is an ordinary peer: new handshake with the real keys.
    for (Session& s : p->sess) s.clear();
    p->pend.wipe();
    p->haveLast = false;
    p->lastTsSent = p->lastInitTs = 0;
    p->guestMode = false;
    p->initiator = memcmp(kp.pub, p->offer.pub, 32) < 0;
    deriveSid(p->sid, kp.pub, p->offer.pub);
    p->startMs = now;
    p->nextProbeMs = 0;
    p->nextPingMs = 0;
    p->lastRxMs = now;
    p->connected = false;
    LBLOG("принят в группу: место %d из %d, других участников: %d", (int)slot, (int)mx, (int)others);
    rebuildNets();
}

void Impl::onReject(Peer* p, const uint8_t* plain, size_t n) {
    uint8_t why;
    if (grp.role != 2 || grp.joinState != 1 || !parseReject(plain, n, why)) return;
    grp.joinState = 3;
    grp.rejectReason = why;
    lastErr = why == REJ_FULL ? "в группе нет мест"
              : why == REJ_CLOSED ? "код группы истёк: попросите создателя продлить код или создать новый"
                                  : "создатель группы отклонил заявку";
    LBLOG("вход в группу: %s", lastErr.c_str());
    (void)p;
}

void Impl::onMember(Peer* p, const uint8_t* plain, size_t n, uint64_t now) {
    if (grp.role != 2 || !p->isCreator) return;
    MemberMsg m;
    if (!parseMember(plain, n, m) || m.slot == 1) return;
    if (Session* s = bestSession(p, now)) {
        std::vector<uint8_t> ack = msgMemberAck(m.slot, m.ver);
        sendTransport(p, s, ack.data(), ack.size(), now);
    }
    if (grp.seen[m.slot] && !verNewer(m.ver, grp.seenVer[m.slot])) return;  // a repeat or an older entry
    grp.seen[m.slot] = true;
    grp.seenVer[m.slot] = m.ver;
    if (m.slot == grp.mySlot) return;
    if (!m.present) {
        if (peerBySlot(m.slot)) doomed.push_back(m.slot);
        return;
    }
    Offer o;
    if (offerDecode(m.offer.data(), m.offer.size(), o) != OFFER_OK || o.group) return;
    if (memcmp(o.pub, kp.pub, 32) == 0) return;
    Peer* ex = peerBySlot(m.slot);
    if (ex && memcmp(ex->offer.pub, o.pub, 32) == 0) return;
    if (ex) removePeer(m.slot, "место занял другой");
    if (Peer* dup = peerByPub(o.pub)) removePeer(dup->slot, "переехал на другое место");
    Peer* np = addPeer(m.slot, o, m.offer, now);
    LBLOG("в группе новый участник \"%s\" (место %d), путей: %d", o.name.c_str(), m.slot, (int)np->cands.size());
    rebuildNets();
}

void Impl::onMemberAck(Peer* p, const uint8_t* plain, size_t n) {
    uint8_t slot;
    uint16_t ver;
    if (grp.role != 1 || !parseMemberAck(plain, n, slot, ver)) return;
    p->synced[slot] = ver;
}

// Creator: tells a member about the others until it acknowledges every entry.
void Impl::syncTick(Peer* p, Session* cur, uint64_t now) {
    if (now < p->nextSyncMs) return;
    p->nextSyncMs = now + 500;
    int sent = 0;
    for (int slot = 2; slot <= grp.maxMembers && sent < 4; slot++) {
        const GroupState::Entry& e = grp.roster[slot];
        if (!e.used || slot == p->slot) continue;
        auto it = p->synced.find(slot);
        if (it != p->synced.end() && it->second == e.ver) continue;
        if (!e.present && it == p->synced.end()) continue;  // it never knew this member: nothing to take back
        if (e.present && memcmp(e.pub, p->offer.pub, 32) == 0) continue;
        MemberMsg m;
        m.slot = (uint8_t)slot;
        m.present = e.present;
        m.ver = e.ver;
        m.offer = e.blob;
        std::vector<uint8_t> plain = msgMember(m);
        sendTransport(p, cur, plain.data(), plain.size(), now);
        sent++;
    }
    if (sent) p->nextSyncMs = now + (uint64_t)cfg.syncMs;
}

// ============================================================ relay

void Impl::onRelay(Peer* p, const uint8_t* plain, size_t n, uint64_t now, bool nested) {
    if (nested || n < 3) return;
    uint8_t type = plain[2];  // the first byte of the carried datagram
    if (type < T_PUNCH || type > T_DATA) return;
    if (grp.role == 1) {  // creator: pass it on to the member it is meant for
        Peer* dst = peerBySlot(plain[1]);
        if (!dst || dst == p || dst->guestMode) return;
        Session* ds = bestSession(dst, now);
        if (!ds) return;
        uint8_t out[MAX_PLAIN];
        out[0] = K_RELAY;
        out[1] = (uint8_t)p->slot;
        memcpy(out + 2, plain + 2, n - 2);
        sendTransport(dst, ds, out, n, now);
        grp.relayFwd++;
    } else if (grp.role == 2 && p->isCreator) {  // member: a datagram from another member
        Peer* from = peerBySlot(plain[1]);
        if (!from || from->guestMode) return;
        onDatagram(plain + 2, n - 2, Route::relayed(from->slot), now, true);
    }
}

// ============================================================ profile (name and avatar)

namespace {
uint16_t fullMask(size_t avatarLen) {
    int cnt = avatarChunks(avatarLen);
    return cnt <= 0 ? 0 : (cnt >= 16 ? 0xFFFF : (uint16_t)((1u << cnt) - 1u));
}
}  // namespace

void Impl::resetProfileOut() {
    for (auto& p : peers) p->pout = ProfileOut();
}

void Impl::profileTick(Peer* p, Session* cur, uint64_t now) {
    if (profVer == 0) return;
    ProfileOut& o = p->pout;
    if (o.ver != profVer) {
        o = ProfileOut();
        o.ver = profVer;
    }
    if (o.done || now < o.nextMs) return;
    uint16_t full = fullMask(avatar.size());
    if (o.metaAcked && (o.ackMask & full) == full) {
        o.done = true;
        return;
    }
    if (!o.metaAcked) {
        std::vector<uint8_t> m = msgProfile(profVer, profName, (uint16_t)avatar.size());
        sendTransport(p, cur, m.data(), m.size(), now);
    }
    int cnt = avatarChunks(avatar.size()), sent = 0, missing = 0;
    for (int i = 0; i < cnt; i++) {
        if ((o.ackMask >> i) & 1) continue;
        missing++;
        if (sent >= 4) continue;
        size_t off = (size_t)i * kAvatarChunk;
        size_t len = std::min(kAvatarChunk, avatar.size() - off);
        std::vector<uint8_t> c = msgAvatar(profVer, (uint8_t)i, (uint8_t)cnt, avatar.data() + off, len);
        sendTransport(p, cur, c.data(), c.size(), now);
        sent++;
    }
    if (o.tries < 255) o.tries++;
    o.nextMs = now + (missing > sent ? 250u : (o.tries < 12 ? 1000u : 5000u));
}

static void completeProfileIn(Peer* p) {
    ProfileIn& in = p->pin;
    if (!in.haveMeta) return;
    if (in.cnt != 0 && in.mask != fullMask(in.avLen)) return;
    p->profName = in.name;
    p->avatar = in.avLen ? in.buf : std::vector<uint8_t>();
    p->profVer = in.ver;
    LBLOG("профиль \"%s\": аватар %u байт", in.name.c_str(), (unsigned)in.avLen);
}

static void ackProfile(Impl* im, Peer* p, Session* s, uint16_t ver, bool haveMeta, uint16_t mask, uint64_t now, bool force) {
    if (!force && now - p->pin.lastAckMs < 150) return;
    p->pin.lastAckMs = now;
    std::vector<uint8_t> a = msgProfileAck(ver, haveMeta, mask);
    im->sendTransport(p, s, a.data(), a.size(), now);
}

void Impl::onProfile(Peer* p, Session* s, const uint8_t* plain, size_t n, uint64_t now) {
    uint16_t ver, av;
    std::string name;
    if (!parseProfile(plain, n, ver, name, av)) return;
    if (p->profVer != 0) {
        if (ver == p->profVer) {  // already complete
            ackProfile(this, p, s, ver, true, fullMask(p->avatar.size()), now, true);
            return;
        }
        if (!verNewer(ver, p->profVer)) return;
    }
    ProfileIn& in = p->pin;
    if (in.ver != ver) {
        in = ProfileIn();
        in.ver = ver;
    }
    in.haveMeta = true;
    in.name = name;
    in.avLen = av;
    in.cnt = (uint8_t)avatarChunks(av);
    if (in.buf.size() != av) {
        in.buf.assign(av, 0);
        in.mask = 0;
    }
    bool before = p->profVer == ver;
    completeProfileIn(p);
    (void)before;
    ackProfile(this, p, s, ver, true, in.mask, now, true);
}

void Impl::onAvatar(Peer* p, Session* s, const uint8_t* plain, size_t n, uint64_t now) {
    uint16_t ver;
    uint8_t idx, cnt;
    const uint8_t* data;
    size_t len;
    if (!parseAvatar(plain, n, ver, idx, cnt, data, len)) return;
    if (p->profVer != 0 && ver == p->profVer) {
        ackProfile(this, p, s, ver, true, fullMask(p->avatar.size()), now, false);
        return;
    }
    ProfileIn& in = p->pin;
    if (in.ver != ver || !in.haveMeta) {  // the meta record has not arrived yet: ask for it
        ackProfile(this, p, s, ver, false, 0, now, false);
        return;
    }
    if (cnt != in.cnt) return;
    size_t off = (size_t)idx * kAvatarChunk;
    size_t want = (idx + 1 == cnt) ? in.avLen - off : kAvatarChunk;
    if (len != want || off + len > in.buf.size()) return;
    memcpy(in.buf.data() + off, data, len);
    in.mask |= (uint16_t)(1u << idx);
    bool complete = in.mask == fullMask(in.avLen);
    if (complete) completeProfileIn(p);
    ackProfile(this, p, s, ver, true, in.mask, now, complete);
}

void Impl::onProfileAck(Peer* p, const uint8_t* plain, size_t n) {
    uint16_t ver, mask;
    bool haveMeta;
    if (!parseProfileAck(plain, n, ver, haveMeta, mask)) return;
    ProfileOut& o = p->pout;
    if (ver != o.ver) return;
    if (haveMeta) o.metaAcked = true;
    o.ackMask |= mask;
}

// ============================================================ members list for the app

// "S" line: this device. "M" lines: the others. TAB-separated fields:
//  S: slot, name, ip4, ip6, profileVersion, role(0 direct, 1 creator, 2 member)
//  M: slot, name, state(1 connecting 2 connected 3 silent 4 left), rttMs, path(0 none 1 internet 2 local network
//     3 through the creator), pathText, ip4, ip6, profileVersion, isCreator, rxBytes, txBytes, connectedSec, families
std::string Impl::membersText() {
    uint64_t now = nowMs();
    std::string o;
    o += strfmt("S\t%d\t%s\t%s\t%s\t%u\t%d\n", view.valid ? view.mySlot : 0, profName.c_str(),
                view.valid ? ipStr(view.myIp).c_str() : "", view.valid ? ip6Str(view.myIp6).c_str() : "", (unsigned)profVer,
                grp.role);
    std::vector<Peer*> order;
    for (auto& p : peers)
        if (!p->guestMode) order.push_back(p.get());
    std::sort(order.begin(), order.end(), [](Peer* a, Peer* b) { return a->slot < b->slot; });
    for (Peer* p : order) {
        bool hasSession = false;
        for (const Session& s : p->sess)
            if (s.valid && s.confirmed && now - s.createdMs < (uint64_t)cfg.rejectAfterMs) hasSession = true;
        bool fresh = p->lastRxMs && now - p->lastRxMs < (uint64_t)cfg.stallMs;
        int st = p->left ? 4 : !hasSession ? 1 : fresh ? 2 : 3;
        bool dOk = directOk(p, now), rOk = relayOk(p, now);
        int kind = 0;
        std::string pt;
        if (st == 2 || st == 3) {
            if (canRelay(p, now) && !dOk && rOk) {
                kind = 3;
                pt = "через создателя";
            } else if (p->addrValid) {
                kind = addrIsLocalNet(p->addr) ? 2 : 1;
                pt = addrStr(p->addr);
            }
        }
        o += strfmt("M\t%d\t%s\t%d\t%lld\t%d\t%s\t%s\t%s\t%u\t%d\t%llu\t%llu\t%llu\t%d\n", p->slot, displayName(p).c_str(), st,
                    (long long)p->rttMs, kind, pt.c_str(), ipStr(p->net.ip4).c_str(), ip6Str(p->net.ip6).c_str(),
                    (unsigned)p->profVer, p->isCreator || (grp.role == 2 && p->slot == 1) ? 1 : 0,
                    (unsigned long long)p->rxBytes, (unsigned long long)p->txBytes,
                    (unsigned long long)((p->connectedSinceMs && st != 1) ? (now - p->connectedSinceMs) / 1000 : 0),
                    offerFamilies(p->offer));
    }
    return o;
}

}  // namespace lb
