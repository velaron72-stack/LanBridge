// LanBridge native core: engine, TUN side. Packets from the TUN are routed to the right peer (or to all of them for
// broadcast and multicast), packets from peers are checked and written to the TUN. Flow statistics for diagnostics.
#include <errno.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>

#include "engine_impl.h"

namespace lb {

using Impl = Engine::Impl;

namespace {
// Through the creator every datagram carries 31 more bytes (K_RELAY header and the outer transport header of the
// creator's session), so the biggest inner packet that still fits one datagram is correspondingly smaller.
constexpr size_t kUnfragRelay = IP_MAX_UNFRAGMENTED - 31;
}  // namespace

Ip6 Impl::srcOf6(const uint8_t* ip) {
    Ip6 a;
    memcpy(a.data(), ip + 8, 16);
    return a;
}
Ip6 Impl::dstOf6(const uint8_t* ip) {
    Ip6 a;
    memcpy(a.data(), ip + 24, 16);
    return a;
}

// ============================================================ flow statistics

void Impl::resetFlowsLocked() {
    flowTab.clear();
    flowOverflow = 0;
    selftestPkts = 0;
    headRing.clear();
    tailCount = 0;
    flowEpochMs = nowMs();
}

// Adds one packet to the flow table and to the head/tail rings.
void Impl::recordFlow(PktRec r, uint16_t svc, bool isFrag, size_t tot) {
    uint64_t rel = nowMs() - flowEpochMs;
    r.tMs = (uint32_t)rel;
    r.len = (uint16_t)(tot > 65535 ? 65535 : tot);
    if (headRing.size() < 120) headRing.push_back(r);
    tailRing[tailCount % (sizeof tailRing / sizeof tailRing[0])] = r;
    tailCount++;

    Flow* f = nullptr;
    for (Flow& x : flowTab) {
        if (x.dir == r.dir && x.proto == r.proto && x.v6 == r.v6 && x.svc == svc &&
            (r.v6 ? (x.s6 == r.s6 && x.d6 == r.d6) : (x.sip == r.sip && x.dip == r.dip))) {
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
        Flow nf;
        memset(&nf, 0, sizeof nf);
        nf.dir = r.dir;
        nf.proto = r.proto;
        nf.v6 = r.v6;
        nf.sip = r.sip;
        nf.dip = r.dip;
        nf.s6 = r.s6;
        nf.d6 = r.d6;
        nf.svc = svc;
        nf.firstMs = nf.lastMs = rel;
        flowTab.push_back(nf);
        f = &flowTab.back();
    }
    f->pkts++;
    f->bytes += tot;
    if (tot > f->maxLen) f->maxLen = (uint16_t)(tot > 65535 ? 65535 : tot);
    f->lastMs = rel;
    if (isFrag) f->frags++;
    if (r.proto == 6) {
        uint8_t tcpFlags = r.tcpFlags;
        if ((tcpFlags & 0x02) && !(tcpFlags & 0x10)) f->syn++;
        else if ((tcpFlags & 0x02) && (tcpFlags & 0x10)) f->synack++;
        if (tcpFlags & 0x04) f->rst++;
        if (tcpFlags & 0x01) f->fin++;
    }
}

void Impl::noteFlow(char dir, const uint8_t* ip, size_t tot) {
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
    PktRec r;
    memset(&r, 0, sizeof r);
    r.dir = dir;
    r.proto = proto;
    r.tcpFlags = tcpFlags;
    r.ipFlags = (uint8_t)(fragField >> 13);
    r.v6 = false;
    r.sip = be32(ip + 12);
    r.dip = be32(ip + 16);
    r.sport = sp;
    r.dport = dp;
    recordFlow(r, svc, isFrag, tot);
}

void Impl::noteFlow6(char dir, const uint8_t* ip, size_t tot) {
    Ip6Info in = ip6Parse(ip, tot);
    if (!in.ok) return;
    uint16_t sp = 0, dp = 0, svc = 0;
    uint8_t tcpFlags = 0;
    if (in.first && (in.proto == 6 || in.proto == 17) && tot >= in.l4off + 4) {
        sp = be16(ip + in.l4off);
        dp = be16(ip + in.l4off + 2);
        if (sp == 41377 || dp == 41377) {
            selftestPkts++;
            return;
        }
        svc = serviceOf(sp, dp);
        if (in.proto == 6 && tot >= in.l4off + 14) tcpFlags = ip[in.l4off + 13];
    } else if (in.first && in.proto == 58 && tot >= in.l4off + 1) {
        svc = ip[in.l4off];
    }
    PktRec r;
    memset(&r, 0, sizeof r);
    r.dir = dir;
    r.proto = in.proto;
    r.tcpFlags = tcpFlags;
    r.ipFlags = in.fragment ? 1 : 0;
    r.v6 = true;
    r.s6 = srcOf6(ip);
    r.d6 = dstOf6(ip);
    r.sport = sp;
    r.dport = dp;
    recordFlow(r, svc, in.fragment, tot);
}

// ============================================================ UDP source fixup

uint64_t Impl::assocKey(uint16_t lport, uint32_t rip, uint16_t rport) {
    return ((uint64_t)lport << 48) | ((uint64_t)rport << 32) | rip;
}

// Incoming unicast UDP: remember which of our addresses the peer sent it to.
void Impl::noteUdpIn(Peer* from, const uint8_t* ip, size_t tot) {
    if (ip[9] != 17) return;
    size_t ihl = (size_t)(ip[0] & 15) * 4;
    if ((be16(ip + 6) & 0x1FFF) != 0 || tot < ihl + 8) return;
    uint32_t src = be32(ip + 12), dst = be32(ip + 16);
    if (!isMyAddr(from, dst)) return;
    uint64_t now = nowMs();
    if (udpAssoc.size() > 4096) udpAssoc.clear();
    udpAssoc[assocKey(be16(ip + ihl + 2), src, be16(ip + ihl))] = UdpAssoc{dst, now};
}

// Outgoing unicast UDP: make a reply come from the address the peer used (see udpAssoc).
void Impl::fixUdpOut(uint8_t* ip, size_t tot, uint64_t now) {
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

void Impl::gcAssoc(uint64_t now) {
    for (auto& p : peers) p->reasm.expire(now);
    if (now - lastAssocGcMs < 30000) return;
    lastAssocGcMs = now;
    for (auto it = udpAssoc.begin(); it != udpAssoc.end();) {
        if (now - it->second.lastMs > 180000) it = udpAssoc.erase(it);
        else ++it;
    }
    fragFix.erase(std::remove_if(fragFix.begin(), fragFix.end(), [now](const FragFix& f) { return f.expMs <= now; }),
                  fragFix.end());
}

// ============================================================ from a peer to the TUN

// Writes one IP packet into the TUN. False when it could not be written (already counted).
bool Impl::writeTun(const uint8_t* ip, size_t tot) {
    ssize_t w = write(tunFd, ip, tot);
    if (w < 0) {
        dropped++;
        tunWriteErr++;
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != EINVAL && errno != EMSGSIZE &&
            errno != ENOBUFS)
            failTunLocked(strfmt("TUN write: %s", strerror(errno)));
        return false;
    }
    return true;
}

// Everything that arrives from a peer as an IP packet (also after reassembly of tunnel chunks).
void Impl::deliverIp(Peer* from, const uint8_t* ip, size_t len) {
    if (tunFd < 0 || !view.valid) return;
    if (len >= 1 && (ip[0] >> 4) == 6) {
        deliverIp6(from, ip, len);
        return;
    }
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
    if (!isPeerAddr(from, src)) {  // a member may only speak with its own addresses
        dropped++;
        dropRxSrc++;
        noteFlow('Y', ip, tot);
        return;
    }
    bool bc = dst == 0xFFFFFFFFu || dst == view.bcast;
    bool mc = (dst >> 28) == 0xE;
    if (!(isMyAddr(from, dst) || bc || mc)) {
        dropped++;
        dropRxDst++;
        noteFlow('Y', ip, tot);
        return;
    }
    noteUdpIn(from, ip, tot);
    if (!writeTun(ip, tot)) return;
    noteFlow('R', ip, tot);
    rxPkts++;
    rxBytes += tot;
    from->rxBytes += tot;
    if (bc) bcastRx++;
    if (mc) mcastRx++;
}

void Impl::deliverIp6(Peer* from, const uint8_t* ip, size_t len) {
    Ip6Info in = ip6Parse(ip, len);
    if (!in.ok) {
        dropped++;
        dropBadHdr++;
        return;
    }
    size_t tot = in.tot;
    if (in.first && in.proto == 58 && in.l4off < tot && icmp6LocalOnly(ip[in.l4off])) {
        dropped++;  // neighbour/router discovery and MLD never cross the tunnel
        return;
    }
    Ip6 src = srcOf6(ip), dst = dstOf6(ip);
    bool ll = ip6IsLinkLocal(src);
    if (!isPeerAddr6(from, src) && !ll) {
        dropped++;
        dropRxSrc++;
        noteFlow6('Y', ip, tot);
        return;
    }
    bool mc = ip6IsMulticast(dst);
    bool ok = mc ? ip6McastScope(dst) > 1 : (isMyAddr6(from, dst) || ip6IsLinkLocal(dst));
    if (!ok) {
        dropped++;
        dropRxDst++;
        noteFlow6('Y', ip, tot);
        return;
    }
    if (!writeTun(ip, tot)) return;
    if (ll) learnLl6(src, from->slot, nowMs());
    noteFlow6('R', ip, tot);
    rxPkts++;
    rxBytes += tot;
    from->rxBytes += tot;
    v6Rx++;
    if (mc) mcastRx++;
}

// ============================================================ from the TUN to the peers

void Impl::readTun(uint64_t now, short revents) {
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

// A SYN or SYN-ACK that leaves through the tunnel gets its MSS option capped, so that the peer's TCP segments
// always fit into one datagram (the peer does the same for the segments we receive).
void Impl::clampMss(uint8_t* p, size_t tot, size_t l4) {
    if (tot < l4 + 20 || !(p[l4 + 13] & 0x02)) return;
    size_t doff = (size_t)(p[l4 + 12] >> 4) * 4;
    if (doff < 24 || l4 + doff > tot) return;
    size_t i = l4 + 20, end = l4 + doff;
    while (i < end) {
        uint8_t kind = p[i];
        if (kind == 0) break;
        if (kind == 1) {
            i++;
            continue;
        }
        if (i + 1 >= end) break;
        size_t olen = p[i + 1];
        if (olen < 2 || i + olen > end) break;
        if (kind == 2 && olen == 4) {
            uint16_t mss = be16(p + i + 2);
            if (mss > kMssCap) {
                putBe16(p + i + 2, (uint16_t)kMssCap);
                uint32_t sum = (~(uint32_t)be16(p + l4 + 16)) & 0xFFFF;
                sum += (~(uint32_t)mss) & 0xFFFF;
                sum += kMssCap;
                while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
                putBe16(p + l4 + 16, (uint16_t)~sum);
                mssClamped++;
            }
            return;
        }
        i += olen;
    }
}

// Sends one inner IP packet: in one datagram when it is small enough, otherwise in tunnel chunks.
bool Impl::sendIp(Peer* to, Session* cur, const uint8_t* p, size_t tot, uint64_t now) {
    size_t unfrag = IP_MAX_UNFRAGMENTED;
    if (canRelay(to, now) && !directFresh(to, now)) unfrag = kUnfragRelay;
    if (tot <= unfrag) {
        uint8_t plain[1 + IP_MAX_UNFRAGMENTED];
        plain[0] = K_IP;
        memcpy(plain + 1, p, tot);
        sendTransport(to, cur, plain, tot + 1, now);
        return true;
    }
    size_t cnt = (tot + FRAG_CHUNK - 1) / FRAG_CHUNK;
    if (cnt > (size_t)FRAG_MAX) {
        dropped++;
        dropTooBig++;
        return false;
    }
    uint16_t id = fragSeq++;
    for (size_t i = 0; i < cnt; i++) {
        size_t off = i * FRAG_CHUNK;
        size_t len = std::min(FRAG_CHUNK, tot - off);
        uint8_t plain[FRAG_HDR + FRAG_CHUNK];
        plain[0] = K_FRAG;
        putBe16(plain + 1, id);
        plain[3] = (uint8_t)i;
        plain[4] = (uint8_t)cnt;
        memcpy(plain + FRAG_HDR, p + off, len);
        sendTransport(to, cur, plain, FRAG_HDR + len, now);
    }
    fragSent++;
    return true;
}

// Packets keep their source when it is our virtual address or a real address of ours that this peer routes to us
// (replies then match what the application expects); anything else is rewritten to the virtual address.
bool Impl::toPeer4(Peer* to, const uint8_t* pkt, size_t tot, size_t ihl, bool unicast, uint64_t now) {
    Session* cur = bestSession(to, now);
    if (!cur) return false;
    uint8_t* p = const_cast<uint8_t*>(pkt);
    if (!isMyAddr(to, be32(p + 12))) ipRewriteSrc(p, tot, view.myIp);
    if (unicast) fixUdpOut(p, tot, now);
    if (p[9] == 6 && (be16(p + 6) & 0x3FFF) == 0) clampMss(p, tot, ihl);
    noteFlow('T', p, tot);
    if (!sendIp(to, cur, p, tot, now)) return false;
    txPkts++;
    txBytes += tot;
    to->txBytes += tot;
    return true;
}

bool Impl::toPeer6(Peer* to, const uint8_t* pkt, size_t tot, const Ip6Info& in, uint64_t now) {
    Session* cur = bestSession(to, now);
    if (!cur) return false;
    uint8_t* p = const_cast<uint8_t*>(pkt);
    Ip6 src = srcOf6(p);
    if (!isMyAddr6(to, src) && !ip6IsLinkLocal(src)) ip6RewriteSrc(p, tot, view.myIp6);
    if (in.proto == 6 && in.first && !in.fragment) clampMss(p, tot, in.l4off);
    noteFlow6('T', p, tot);
    if (!sendIp(to, cur, p, tot, now)) return false;
    txPkts++;
    txBytes += tot;
    to->txBytes += tot;
    v6Tx++;
    return true;
}

void Impl::onTunPacket(uint8_t* p, size_t n, uint64_t now) {
    if (n >= 1 && (p[0] >> 4) == 6) {
        onTunPacket6(p, n, now);
        return;
    }
    if (n < 20 || (p[0] >> 4) != 4) return;
    size_t ihl = (size_t)(p[0] & 15) * 4;
    size_t tot = be16(p + 2);
    if (ihl < 20 || ihl > n || tot < ihl || tot > n) {
        dropBadHdr++;
        return;
    }
    if (p[9] == 2) return;  // IGMP stays local
    if (!view.valid) {
        dropped++;
        dropNoSession++;
        return;
    }
    uint32_t dst = be32(p + 16);
    if (Peer* to = ownerOf4(dst)) {
        if (!toPeer4(to, p, tot, ihl, true, now)) {
            dropped++;
            dropNoSession++;
        }
        return;
    }
    bool bc = dst == 0xFFFFFFFFu || dst == view.bcast;
    bool mc = (dst >> 28) == 0xE;
    if (!bc && !mc) {
        dropped++;
        dropForeignDst++;
        noteFlow('X', p, tot);
        return;
    }
    // Broadcast and multicast go to every member, each with its own copy (the source depends on the receiver).
    bool any = false;
    uint8_t copy[4096];
    for (auto& q : peers) {
        if (q->guestMode) continue;
        memcpy(copy, p, tot);
        any |= toPeer4(q.get(), copy, tot, ihl, false, now);
    }
    if (!any) {
        dropped++;
        dropNoSession++;
        return;
    }
    if (bc) bcastTx++;
    if (mc) mcastTx++;
}

void Impl::onTunPacket6(uint8_t* p, size_t n, uint64_t now) {
    Ip6Info in = ip6Parse(p, n);
    if (!in.ok) {
        dropBadHdr++;
        return;
    }
    size_t tot = in.tot;
    if (in.first && in.proto == 58 && in.l4off < tot && icmp6LocalOnly(p[in.l4off])) return;  // stays local
    Ip6 dst = dstOf6(p);
    bool mc = ip6IsMulticast(dst);
    if (mc && ip6McastScope(dst) <= 1) return;  // interface-local: never leaves the device
    if (!view.valid) {
        dropped++;
        dropNoSession++;
        return;
    }
    if (!mc) {
        Peer* to = ownerOf6(dst);
        if (!to && ip6IsLinkLocal(dst)) to = lookupLl6(dst, now);
        if (!to) {
            dropped++;
            dropForeignDst++;
            noteFlow6('X', p, tot);
            return;
        }
        if (!toPeer6(to, p, tot, in, now)) {
            dropped++;
            dropNoSession++;
        }
        return;
    }
    bool any = false;
    uint8_t copy[4096];
    for (auto& q : peers) {
        if (q->guestMode) continue;
        memcpy(copy, p, tot);
        any |= toPeer6(q.get(), copy, tot, in, now);
    }
    if (!any) {
        dropped++;
        dropNoSession++;
        return;
    }
    mcastTx++;
}

// ============================================================ diagnostics

static const char* protoName(uint8_t p) {
    return p == 6 ? "TCP" : p == 17 ? "UDP" : p == 1 ? "ICMP" : p == 58 ? "ICMPv6" : p == 2 ? "IGMP" : "IP";
}

// Flow lines show an IPv6 address as it is; packet lines put it in brackets when a port follows.
static std::string addrText(bool v6, uint32_t v4, const Ip6& a6) { return v6 ? ip6Str(a6) : ipStr(v4); }

static std::string pktLine(uint32_t tMs, char dir, uint8_t proto, bool v6, uint32_t sip, uint32_t dip, const Ip6& s6,
                           const Ip6& d6, uint16_t sp, uint16_t dp, uint16_t len, uint8_t tcpFlags, uint8_t ipFlags) {
    std::string a = addrText(v6, sip, s6), b = addrText(v6, dip, d6);
    if (proto == 6 || proto == 17) {
        if (sp || dp) {
            if (v6) {
                a = "[" + a + "]";
                b = "[" + b + "]";
            }
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
    if (!v6 && (ipFlags & 0x2)) fl += (fl.empty() ? "" : " ") + std::string("DF");
    if (!v6 && (ipFlags & 0x1)) fl += (fl.empty() ? "" : " ") + std::string("MF");
    if (v6 && (ipFlags & 0x1)) fl += (fl.empty() ? "" : " ") + std::string("FRAG");
    return strfmt("%7.3f %c %s %s > %s len=%u%s%s\n", tMs / 1000.0, dir, protoName(proto), a.c_str(), b.c_str(),
                  (unsigned)len, fl.empty() ? "" : " ", fl.c_str());
}

std::string Engine::flows() {
    Impl& s = *p_;
    std::lock_guard<std::mutex> g(s.mu);
    uint64_t now = nowMs();
    std::string o = strfmt(
        "drops foreignDst=%llu noSession=%llu badHeader=%llu rxSrc=%llu rxDst=%llu tunWrite=%llu udpQueued=%llu "
        "udpDropped=%llu\n",
        (unsigned long long)s.dropForeignDst, (unsigned long long)s.dropNoSession, (unsigned long long)s.dropBadHdr,
        (unsigned long long)s.dropRxSrc, (unsigned long long)s.dropRxDst, (unsigned long long)s.tunWriteErr,
        (unsigned long long)s.udpQueued, (unsigned long long)s.udpDropped);
    o += strfmt("проверка LAN (порт 41377, в списках не показана): %llu пакетов; вытеснено записей: %llu; с момента сброса: %.1f с\n",
                (unsigned long long)s.selftestPkts, (unsigned long long)s.flowOverflow, (now - s.flowEpochMs) / 1000.0);
    o += strfmt("подмен источника в ответах UDP: %llu; запомнено потоков UDP: %u\n", (unsigned long long)s.udpFixups,
                (unsigned)s.udpAssoc.size());
    o += strfmt("пакетов IPv6: в туннель %llu, из туннеля %llu\n", (unsigned long long)s.v6Tx, (unsigned long long)s.v6Rx);
    uint64_t reasmExpired = 0;
    for (const auto& p : s.peers) reasmExpired += p->reasm.expiredTotal();
    o += strfmt("крупных пакетов разбито туннелем: %llu, собрано: %llu (не собрано за %d с: %llu, слишком крупных: %llu); "
                "MSS урезан в %llu SYN\n",
                (unsigned long long)s.fragSent, (unsigned long long)s.fragRecv, (int)(FragReassembler::kTimeoutMs / 1000),
                (unsigned long long)reasmExpired, (unsigned long long)s.dropTooBig, (unsigned long long)s.mssClamped);
    if (s.grp.role != 0) {
        o += strfmt("группа: роль %s, моё место %d из %d, участников %d, повторов по двум путям отброшено %llu, "
                    "через создателя передано %llu / отправлено %llu\n",
                    s.grp.role == 1 ? "создатель" : "участник", s.grp.mySlot, s.grp.maxMembers, s.presentPeers(),
                    (unsigned long long)s.dupDropped, (unsigned long long)s.grp.relayFwd, (unsigned long long)s.grp.relayTx);
    }
    for (const auto& p : s.peers) {
        bool hasSession = false;
        for (const Session& ss : p->sess)
            if (ss.valid && ss.confirmed) hasSession = true;
        auto ago = [&](uint64_t t) { return t ? (long long)((now - t) / 1000) : -1LL; };
        o += strfmt("участник %d \"%s\": сессия %s, связь %s, путь %s, RTT %lld мс, ответов напрямую %llds назад, через создателя %llds, "
                    "принято %llu, отправлено %llu байт\n",
                    p->slot, s.displayName(p.get()).c_str(), hasSession ? "есть" : "нет", p->connected ? "есть" : "нет",
                    p->addrValid ? addrStr(p->addr).c_str() : "-", (long long)p->rttMs, ago(p->directEchoMs),
                    ago(p->relayEchoMs), (unsigned long long)p->rxBytes, (unsigned long long)p->txBytes);
    }
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
                    addrText(f.v6, f.sip, f.s6).c_str(), addrText(f.v6, f.dip, f.d6).c_str(), port.c_str(),
                    (unsigned long long)f.pkts, (unsigned long long)f.bytes, (unsigned)f.maxLen, f.firstMs / 1000.0,
                    f.lastMs / 1000.0, extra.c_str());
    }
    o += strfmt("\nПервые пакеты (%u):\n", (unsigned)s.headRing.size());
    for (const Impl::PktRec& r : s.headRing)
        o += pktLine(r.tMs, r.dir, r.proto, r.v6, r.sip, r.dip, r.s6, r.d6, r.sport, r.dport, r.len, r.tcpFlags, r.ipFlags);
    size_t cap = sizeof s.tailRing / sizeof s.tailRing[0];
    size_t n = s.tailCount < cap ? s.tailCount : cap;
    o += strfmt("\nПоследние пакеты (%u из %llu):\n", (unsigned)n, (unsigned long long)s.tailCount);
    for (size_t i = 0; i < n; i++) {
        const Impl::PktRec& r = s.tailRing[(s.tailCount - n + i) % cap];
        o += pktLine(r.tMs, r.dir, r.proto, r.v6, r.sip, r.dip, r.s6, r.d6, r.sport, r.dport, r.len, r.tcpFlags, r.ipFlags);
    }
    return o;
}

void Engine::resetFlows() {
    std::lock_guard<std::mutex> g(p_->mu);
    p_->resetFlowsLocked();
}

}  // namespace lb
