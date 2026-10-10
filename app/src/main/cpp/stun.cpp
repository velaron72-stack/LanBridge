#include "stun.h"

#include <arpa/inet.h>
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

bool stunResolve(const std::string& hostPort, sockaddr_in& out) {
    std::string host = hostPort;
    std::string port = "3478";
    size_t c = hostPort.rfind(':');
    if (c != std::string::npos) {
        host = hostPort.substr(0, c);
        port = hostPort.substr(c + 1);
    }
    if (host.empty() || port.empty()) return false;
    int pn = atoi(port.c_str());
    if (pn <= 0 || pn > 65535) return false;
    memset(&out, 0, sizeof out);
    out.sin_family = AF_INET;
    out.sin_port = htons((uint16_t)pn);
    if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) == 1) return true;
    addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    bool ok = false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(sockaddr_in)) {
            out.sin_addr = ((sockaddr_in*)p->ai_addr)->sin_addr;
            ok = true;
            break;
        }
    }
    freeaddrinfo(res);
    return ok;
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

bool stunParseResponse(const uint8_t* p, size_t n, const uint8_t txid[12], StunAddr& out) {
    if (!stunIsMessage(p, n)) return false;
    if (be16(p) != 0x0101) return false;  // Binding Success Response
    if (memcmp(p + 8, txid, 12) != 0) return false;
    size_t total = 20 + be16(p + 2);
    size_t off = 20;
    bool haveXor = false, haveMapped = false;
    StunAddr xa, ma;
    while (off + 4 <= total) {
        uint16_t type = be16(p + off);
        size_t alen = be16(p + off + 2);
        const uint8_t* v = p + off + 4;
        if (off + 4 + alen > total) break;
        if (alen >= 8 && v[1] == 1) {
            if (type == 0x0020) {
                xa.port = (uint16_t)(be16(v + 2) ^ (kCookie >> 16));
                xa.ip = be32(v + 4) ^ kCookie;
                haveXor = true;
            } else if (type == 0x0001) {
                ma.port = be16(v + 2);
                ma.ip = be32(v + 4);
                haveMapped = true;
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
    std::vector<sockaddr_in> addrs;
    std::vector<char> ok;
    size_t pending = 0;
};
}  // namespace

std::vector<StunServer> stunResolveAll(const std::vector<std::string>& names, int timeoutMs) {
    std::vector<StunServer> out;
    if (names.empty()) return out;
    auto sh = std::make_shared<ResolveShared>();
    sh->addrs.resize(names.size());
    sh->ok.assign(names.size(), 0);
    sh->pending = names.size();
    for (size_t i = 0; i < names.size(); i++) {
        std::string nm = names[i];
        try {
            std::thread([sh, i, nm]() {
                sockaddr_in a;
                memset(&a, 0, sizeof a);
                bool ok = stunResolve(nm, a);
                std::lock_guard<std::mutex> g(sh->m);
                if (ok) {
                    sh->addrs[i] = a;
                    sh->ok[i] = 1;
                }
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
        if (!sh->ok[i]) continue;
        bool dup = false;
        for (const StunServer& s : out) {
            if (s.addr.sin_addr.s_addr == sh->addrs[i].sin_addr.s_addr && s.addr.sin_port == sh->addrs[i].sin_port) dup = true;
        }
        if (dup) continue;
        StunServer s;
        s.name = names[i];
        s.addr = sh->addrs[i];
        out.push_back(s);
    }
    return out;
}

int stunGather(int sock, std::vector<StunServer>& sv, int timeoutMs) {
    if (sv.empty()) return 0;
    for (StunServer& s : sv) {
        randomBytes(s.txid, 12);
        s.ok = false;
    }
    const uint64_t start = nowMs();
    uint64_t nextSend = start;
    int rounds = 0;
    size_t answered = 0;
    while (answered < sv.size()) {
        uint64_t now = nowMs();
        if (now - start >= (uint64_t)timeoutMs) break;
        if (now >= nextSend && rounds < 5) {
            for (StunServer& s : sv) {
                if (s.ok) continue;
                uint8_t req[20];
                stunBuildRequest(req, s.txid);
                sendto(sock, req, sizeof req, MSG_DONTWAIT, (const sockaddr*)&s.addr, sizeof s.addr);
            }
            rounds++;
            nextSend = now + (rounds == 1 ? 400 : 700);
        }
        uint64_t limit = start + (uint64_t)timeoutMs;
        uint64_t wake = std::min(nextSend, limit);
        int wait = wake > now ? (int)(wake - now) : 1;
        if (wait < 1) wait = 1;
        pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int r = poll(&pfd, 1, wait);
        if (r > 0 && (pfd.revents & POLLIN)) {
            for (int k = 0; k < 32; k++) {
                uint8_t buf[600];
                sockaddr_in from;
                socklen_t fl = sizeof from;
                ssize_t n = recvfrom(sock, buf, sizeof buf, MSG_DONTWAIT, (sockaddr*)&from, &fl);
                if (n <= 0) break;
                for (StunServer& s : sv) {
                    if (s.ok) continue;
                    StunAddr m;
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
