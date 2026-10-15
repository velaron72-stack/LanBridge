// Simulated network for the native tests: UDP sockets of both address families that exchange datagrams in memory.
// The engine takes them through Engine::setSocketFactory(), so IPv6 (and every mix of IPv4/IPv6, NAT, firewalls and
// failures) can be tested on a host whose kernel has no IPv6 at all.
//
// What is simulated:
//  * hosts with a public IPv4 address behind a port-translating NAT (external port = local port + shift) and/or an
//    IPv6 address without translation;
//  * a stateful inbound filter per family (a datagram is accepted only from an endpoint the host has sent to);
//  * families that cannot be used at all (the socket cannot be created, or sending fails with ENETUNREACH);
//  * "black holes": every peer datagram of one family is dropped (a broken path);
//  * blocked pairs of hosts (two devices that cannot reach each other) and random loss of peer datagrams;
//  * STUN servers (Binding responses with XOR-MAPPED-ADDRESS of either family).
#pragma once

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "addr.h"
#include "udpio.h"
#include "util.h"

namespace sim {

using lb::Addr;
using lb::Ip6;

struct Host {
    std::string name;
    bool open4 = true, open6 = true;  // the socket of this family can be created
    bool has4 = true, has6 = true;    // the family has connectivity (otherwise sending fails: ENETUNREACH)
    uint32_t pub4 = 0;                // external IPv4 address
    int shift4 = 0;                   // NAT: external port = local port + shift4
    Ip6 addr6{};                      // the host's IPv6 address (global, no translation)
    bool fw4 = false, fw6 = false;    // accept datagrams only from endpoints this host has sent to
};

class Net;

class Sock : public lb::UdpSocket {
public:
    Sock(Net& net, Host& host, bool v6);
    ~Sock() override;
    int fd() const override { return rd_; }
    bool v6() const override { return v6_; }
    uint16_t port() const override { return port_; }
    ssize_t sendTo(const Addr& to, const uint8_t* b, size_t n) override;
    ssize_t recvFrom(uint8_t* b, size_t cap, Addr& from) override;

    Addr ext() const;  // the address the others see
    void push(const Addr& from, const uint8_t* b, size_t n);

private:
    friend class Net;
    Net& net_;
    Host& host_;
    bool v6_;
    uint16_t port_;
    int rd_ = -1, wr_ = -1;
    std::set<std::string> sentTo_;  // pinholes of the stateful filter
};

class Net {
public:
    std::mutex mu;
    std::map<std::string, Sock*> byExt;
    std::vector<Addr> stunServers;
    std::atomic<bool> drop4{false}, drop6{false};  // black hole for peer traffic of the family (STUN still works)
    std::atomic<uint64_t> sent4{0}, sent6{0}, delivered4{0}, delivered6{0};
    std::atomic<size_t> maxLen4{0}, maxLen6{0};
    std::atomic<uint16_t> nextPort{41000};
    std::atomic<int> lossPermille{0};  // share of peer datagrams that disappear (per mille)
    std::set<std::string> blocked;     // "from>to" host names

    // Hosts `a` and `b` cannot exchange datagrams (both directions) until unblocked.
    void block(const std::string& a, const std::string& b, bool on = true) {
        std::lock_guard<std::mutex> g(mu);
        for (const std::string& k : {a + ">" + b, b + ">" + a}) {
            if (on) blocked.insert(k);
            else blocked.erase(k);
        }
    }

    lb::UdpFactory factory(Host* h) {
        return [this, h](bool v6, std::string& err) -> std::unique_ptr<lb::UdpSocket> {
            if (v6 ? !h->open6 : !h->open4) {
                err = std::string("simulated: no ") + (v6 ? "IPv6" : "IPv4") + " socket on " + h->name;
                return nullptr;
            }
            return std::unique_ptr<lb::UdpSocket>(new Sock(*this, *h, v6));
        };
    }

    void addStun(const Addr& a) { stunServers.push_back(a); }
    bool isStun(const Addr& a) const {
        for (const Addr& s : stunServers)
            if (s == a) return true;
        return false;
    }

    // Called with `mu` held.
    void route(Sock* from, const Addr& to, const uint8_t* b, size_t n) {
        Addr fromExt = from->ext();
        if (isStun(to)) {
            if (n >= 20 && b[0] == 0 && b[1] == 1) answerStun(from, fromExt, to, b);
            return;
        }
        from->sentTo_.insert(lb::addrStr(to));
        (to.v6 ? sent6 : sent4)++;
        std::atomic<size_t>& mx = to.v6 ? maxLen6 : maxLen4;
        if (n > mx) mx = n;
        if (to.v6 ? drop6.load() : drop4.load()) return;
        auto it = byExt.find(lb::addrStr(to));
        if (it == byExt.end()) return;
        Sock* rcv = it->second;
        if (rcv->v6_ != to.v6) return;
        if (!blocked.empty() && blocked.count(from->host_.name + ">" + rcv->host_.name)) return;
        if (lossPermille.load() > 0 && rand() % 1000 < lossPermille.load()) return;
        if (!(to.v6 ? rcv->host_.has6 : rcv->host_.has4)) return;  // the receiver has no connectivity either
        bool fw = to.v6 ? rcv->host_.fw6 : rcv->host_.fw4;
        if (fw && !rcv->sentTo_.count(lb::addrStr(fromExt))) return;
        (to.v6 ? delivered6 : delivered4)++;
        rcv->push(fromExt, b, n);
    }

private:
    void answerStun(Sock* from, const Addr& mapped, const Addr& server, const uint8_t* req) {
        uint8_t r[48];
        size_t alen = mapped.v6 ? 20 : 8;
        lb::putBe16(r, 0x0101);
        lb::putBe16(r + 2, (uint16_t)(4 + alen));
        lb::putBe32(r + 4, 0x2112A442u);
        memcpy(r + 8, req + 8, 12);
        lb::putBe16(r + 20, 0x0020);
        lb::putBe16(r + 22, (uint16_t)alen);
        r[24] = 0;
        r[25] = mapped.v6 ? 2 : 1;
        lb::putBe16(r + 26, (uint16_t)(mapped.port ^ 0x2112));
        if (mapped.v6) {
            uint8_t mask[16];
            lb::putBe32(mask, 0x2112A442u);
            memcpy(mask + 4, req + 8, 12);
            for (int i = 0; i < 16; i++) r[28 + i] = (uint8_t)(mapped.ip6[(size_t)i] ^ mask[i]);
        } else {
            lb::putBe32(r + 28, mapped.ip4 ^ 0x2112A442u);
        }
        from->push(server, r, 20 + 4 + alen);
    }
};

inline Sock::Sock(Net& net, Host& host, bool v6) : net_(net), host_(host), v6_(v6) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) abort();
    rd_ = sv[0];
    wr_ = sv[1];
    for (int fd : {rd_, wr_}) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    int buf = 1 << 20;
    setsockopt(wr_, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    setsockopt(rd_, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
    port_ = net.nextPort++;
    std::lock_guard<std::mutex> g(net_.mu);
    net_.byExt[lb::addrStr(ext())] = this;
}

inline Sock::~Sock() {
    {
        std::lock_guard<std::mutex> g(net_.mu);
        auto it = net_.byExt.find(lb::addrStr(ext()));
        if (it != net_.byExt.end() && it->second == this) net_.byExt.erase(it);
    }
    close(rd_);
    close(wr_);
}

inline Addr Sock::ext() const {
    if (v6_) return lb::addr6(host_.addr6, port_);
    return lb::addr4(host_.pub4, (uint16_t)(port_ + host_.shift4));
}

inline ssize_t Sock::sendTo(const Addr& to, const uint8_t* b, size_t n) {
    if (to.v6 != v6_) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (!(v6_ ? host_.has6 : host_.has4)) {
        errno = ENETUNREACH;
        return -1;
    }
    std::lock_guard<std::mutex> g(net_.mu);
    net_.route(this, to, b, n);
    return (ssize_t)n;
}

// Wire format inside the simulated host: 1 family, 16 IPv6, 4 IPv4, 2 port, then the datagram.
inline void Sock::push(const Addr& from, const uint8_t* b, size_t n) {
    std::vector<uint8_t> m(23 + n);
    m[0] = from.v6 ? 1 : 0;
    memcpy(&m[1], from.ip6.data(), 16);
    lb::putBe32(&m[17], from.ip4);
    lb::putBe16(&m[21], from.port);
    if (n) memcpy(&m[23], b, n);
    ssize_t r = send(wr_, m.data(), m.size(), MSG_DONTWAIT);
    (void)r;  // a full queue drops the datagram, like a real socket buffer
}

inline ssize_t Sock::recvFrom(uint8_t* b, size_t cap, Addr& from) {
    uint8_t tmp[4000];
    ssize_t n = recv(rd_, tmp, sizeof tmp, MSG_DONTWAIT);
    if (n < 0) return -1;
    if (n < 23) return 0;
    from = Addr();
    from.v6 = tmp[0] != 0;
    memcpy(from.ip6.data(), tmp + 1, 16);
    from.ip4 = lb::be32(tmp + 17);
    from.port = lb::be16(tmp + 21);
    size_t len = (size_t)n - 23;
    if (len > cap) len = cap;
    memcpy(b, tmp + 23, len);
    return (ssize_t)len;
}

}  // namespace sim
