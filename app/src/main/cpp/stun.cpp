#include "stun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <algorithm>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>

#include "util.h"

namespace lb {

static const uint32_t kCookie = 0x2112A442u;

bool stunResolve(const std::string& hostPort, std::vector<Addr>& out) {
    std::string host = hostPort;
    std::string port = "3478";
    if (!hostPort.empty() && hostPort[0] == '[') {  // "[v6]:port" or "[v6]"
        size_t close = hostPort.find(']');
        if (close == std::string::npos) return false;
        host = hostPort.substr(1, close - 1);
        if (close + 1 < hostPort.size()) {
            if (hostPort[close + 1] != ':') return false;
            port = hostPort.substr(close + 2);
        }
    } else if (std::count(hostPort.begin(), hostPort.end(), ':') > 1) {  // a bare IPv6 literal
        host = hostPort;
    } else {
        size_t c = hostPort.rfind(':');
        if (c != std::string::npos) {
            host = hostPort.substr(0, c);
            port = hostPort.substr(c + 1);
        }
    }
    if (host.empty() || port.empty()) return false;
    int pn = atoi(port.c_str());
    if (pn <= 0 || pn > 65535) return false;
    uint16_t pt = (uint16_t)pn;

    in_addr a4;
    if (inet_pton(AF_INET, host.c_str(), &a4) == 1) {
        out.push_back(addr4(ntohl(a4.s_addr), pt));
        return true;
    }
    Ip6 a6;
    if (host.find(':') != std::string::npos) {
        if (!parseIp6(host, a6)) return false;
        out.push_back(addr6(a6, pt));
        return true;
    }
    addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    bool have4 = false, have6 = false, any = false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        Addr a;
        if (!p->ai_addr || !addrFromSock(p->ai_addr, (socklen_t)p->ai_addrlen, a)) continue;
        if (a.v6 ? have6 : have4) continue;
        a.port = pt;
        (a.v6 ? have6 : have4) = true;
        out.push_back(a);
        any = true;
    }
    freeaddrinfo(res);
    return any;
}

void stunBuildRequest(uint8_t out[20], const uint8_t txid[12]) {
    putBe16(out, 0x0001);  // Binding Request
    putBe16(out + 2, 0);
    putBe32(out + 4, kCookie);
    memcpy(out + 8, txid, 12);
}

bool stunIsMessage(const uint8_t* p, size_t n) {
    if (n < 20 || (p[0] & 0xC0) != 0) return false;
    if (be32(p + 4) != kCookie) return false;
    size_t len = be16(p + 2);
    return len % 4 == 0 && 20 + len <= n;
}

bool stunGetTxid(const uint8_t* p, size_t n, uint8_t txid[12]) {
    if (!stunIsMessage(p, n)) return false;
    memcpy(txid, p + 8, 12);
    return true;
}

bool stunParseResponse(const uint8_t* p, size_t n, const uint8_t txid[12], Addr& out) {
    if (!stunIsMessage(p, n)) return false;
    if (be16(p) != 0x0101) return false;  // Binding Success Response
    if (memcmp(p + 8, txid, 12) != 0) return false;
    size_t total = 20 + be16(p + 2);
    size_t off = 20;
    bool haveXor = false, haveMapped = false;
    Addr xa, ma;
    while (off + 4 <= total) {
        uint16_t type = be16(p + off);
        size_t alen = be16(p + off + 2);
        const uint8_t* v = p + off + 4;
        if (off + 4 + alen > total) break;
        if ((type == 0x0020 || type == 0x0001) && alen >= 8) {
            bool xored = type == 0x0020;
            Addr a;
            bool good = false;
            if (v[1] == 1) {
                if (xored) {
                    a = addr4(be32(v + 4) ^ kCookie, (uint16_t)(be16(v + 2) ^ (kCookie >> 16)));
                } else {
                    a = addr4(be32(v + 4), be16(v + 2));
                }
                good = true;
            } else if (v[1] == 2 && alen >= 20) {
                Ip6 ip;
                memcpy(ip.data(), v + 4, 16);
                if (xored) {
                    uint8_t mask[16];
                    putBe32(mask, kCookie);
                    memcpy(mask + 4, txid, 12);
                    for (int i = 0; i < 16; i++) ip[(size_t)i] ^= mask[i];
                    a = addr6(ip, (uint16_t)(be16(v + 2) ^ (kCookie >> 16)));
                } else {
                    a = addr6(ip, be16(v + 2));
                }
                good = true;
            }
            if (good) {
                if (xored) {
                    xa = a;
                    haveXor = true;
                } else {
                    ma = a;
                    haveMapped = true;
                }
            }
        }
        off += 4 + ((alen + 3) & ~(size_t)3);
    }
    if (haveXor) {
        out = xa;
        return true;
    }
    if (haveMapped) {
        out = ma;
        return true;
    }
    return false;
}

namespace {
struct ResolveShared {
    std::mutex m;
    std::condition_variable cv;
    std::vector<std::vector<Addr>> addrs;
    size_t pending = 0;
};
}  // namespace

std::vector<StunServer> stunResolveAll(const std::vector<std::string>& names, int timeoutMs) {
    std::vector<StunServer> out;
    if (names.empty()) return out;
    auto sh = std::make_shared<ResolveShared>();
    sh->addrs.resize(names.size());
    sh->pending = names.size();
    for (size_t i = 0; i < names.size(); i++) {
        std::string nm = names[i];
        try {
            std::thread([sh, i, nm]() {
                std::vector<Addr> v;
                if (!stunResolve(nm, v)) v.clear();
                std::lock_guard<std::mutex> g(sh->m);
                sh->addrs[i] = v;
                sh->pending--;
                sh->cv.notify_all();
            }).detach();
        } catch (...) {
            std::lock_guard<std::mutex> g(sh->m);
            sh->pending--;
        }
    }
    std::unique_lock<std::mutex> lk(sh->m);
    sh->cv.wait_for(lk, std::chrono::milliseconds(timeoutMs), [&] { return sh->pending == 0; });
    for (size_t i = 0; i < names.size(); i++) {
        for (const Addr& a : sh->addrs[i]) {
            // IPv4 loopback and private servers stay allowed (tests, servers in the local network)
            bool keep = a.v6 ? addrUsablePeer(a) : (a.port != 0 && a.ip4 != 0 && (a.ip4 >> 24) < 224);
            if (!keep) continue;
            bool dup = false;
            for (const StunServer& s : out) dup |= s.addr == a;
            if (dup) continue;
            StunServer s;
            s.name = names[i];
            s.addr = a;
            out.push_back(s);
        }
    }
    return out;
}

int stunGather(UdpSocket* s4, UdpSocket* s6, std::vector<StunServer>& sv, int timeoutMs) {
    if (sv.empty()) return 0;
    std::vector<int> fails(sv.size(), 0);
    std::vector<char> dead(sv.size(), 0);
    for (size_t i = 0; i < sv.size(); i++) {
        randomBytes(sv[i].txid, 12);
        sv[i].ok = false;
        if (!(sv[i].addr.v6 ? s6 : s4)) dead[i] = 1;  // no socket of that family
    }
    const uint64_t start = nowMs();
    uint64_t nextSend = start;
    int rounds = 0;
    size_t answered = 0;
    auto settled = [&]() {
        size_t n = 0;
        for (size_t i = 0; i < sv.size(); i++) n += (sv[i].ok || dead[i]) ? 1 : 0;
        return n;
    };
    while (settled() < sv.size()) {
        uint64_t now = nowMs();
        if (now - start >= (uint64_t)timeoutMs) break;
        if (now >= nextSend && rounds < 5) {
            for (size_t i = 0; i < sv.size(); i++) {
                StunServer& s = sv[i];
                if (s.ok || dead[i]) continue;
                UdpSocket* sock = s.addr.v6 ? s6 : s4;
                uint8_t req[20];
                stunBuildRequest(req, s.txid);
                ssize_t r = sock->sendTo(s.addr, req, sizeof req);
                if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS && errno != EINTR) {
                    if (++fails[i] >= 2) dead[i] = 1;  // unreachable network, bad address family, ...
                }
            }
            rounds++;
            nextSend = now + (rounds == 1 ? 400 : 700);
        }
        uint64_t limit = start + (uint64_t)timeoutMs;
        uint64_t wake = std::min(nextSend, limit);
        int wait = wake > now ? (int)(wake - now) : 1;
        if (wait < 1) wait = 1;
        pollfd pfd[2];
        int np = 0;
        UdpSocket* socks[2] = {nullptr, nullptr};
        if (s4) {
            pfd[np] = pollfd{s4->fd(), POLLIN, 0};
            socks[np++] = s4;
        }
        if (s6) {
            pfd[np] = pollfd{s6->fd(), POLLIN, 0};
            socks[np++] = s6;
        }
        int r = poll(pfd, (nfds_t)np, wait);
        if (r <= 0) continue;
        for (int k = 0; k < np; k++) {
            if (!(pfd[k].revents & POLLIN)) continue;
            for (int j = 0; j < 32; j++) {
                uint8_t buf[600];
                Addr from;
                ssize_t n = socks[k]->recvFrom(buf, sizeof buf, from);
                if (n < 0) break;
                if (n == 0) continue;
                for (StunServer& s : sv) {
                    if (s.ok) continue;
                    Addr m;
                    if (stunParseResponse(buf, (size_t)n, s.txid, m)) {
                        s.ok = true;
                        s.mapped = m;
                        answered++;
                        break;
                    }
                }
            }
        }
    }
    return (int)answered;
}

}  // namespace lb
