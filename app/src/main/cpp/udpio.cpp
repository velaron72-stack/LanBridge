#include "udpio.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "util.h"

namespace lb {

namespace {

class SysUdp : public UdpSocket {
public:
    SysUdp(int fd, bool v6, uint16_t port) : fd_(fd), v6_(v6), port_(port) {}
    ~SysUdp() override {
        if (fd_ >= 0) close(fd_);
    }
    int fd() const override { return fd_; }
    bool v6() const override { return v6_; }
    uint16_t port() const override { return port_; }

    ssize_t sendTo(const Addr& to, const uint8_t* b, size_t n) override {
        if (to.v6 != v6_) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        sockaddr_storage ss;
        socklen_t sl = 0;
        if (!addrToSock(to, ss, sl)) {
            errno = EINVAL;
            return -1;
        }
        return sendto(fd_, b, n, MSG_DONTWAIT, (const sockaddr*)&ss, sl);
    }

    ssize_t recvFrom(uint8_t* b, size_t cap, Addr& from) override {
        sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        ssize_t n = recvfrom(fd_, b, cap, MSG_DONTWAIT, (sockaddr*)&ss, &sl);
        if (n < 0) return -1;
        if (!addrFromSock((const sockaddr*)&ss, sl, from)) return 0;
        return n;
    }

private:
    int fd_;
    bool v6_;
    uint16_t port_;
};

}  // namespace

std::unique_ptr<UdpSocket> openSysUdp(bool v6, std::string& err) {
    int s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        err = strfmt("socket(%s): %s", v6 ? "IPv6" : "IPv4", strerror(errno));
        return nullptr;
    }
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
    fcntl(s, F_SETFD, FD_CLOEXEC);
    int buf = 4 << 20;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    sockaddr_storage ss;
    socklen_t sl = 0;
    if (v6) {
        int one = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    }
    Addr any = v6 ? addr6(Ip6{}, 0) : addr4(0, 0);
    addrToSock(any, ss, sl);
    if (bind(s, (const sockaddr*)&ss, sl) < 0) {
        err = strfmt("bind(%s): %s", v6 ? "IPv6" : "IPv4", strerror(errno));
        close(s);
        return nullptr;
    }
    sockaddr_storage got;
    socklen_t gl = sizeof got;
    if (getsockname(s, (sockaddr*)&got, &gl) < 0) {
        err = strfmt("getsockname: %s", strerror(errno));
        close(s);
        return nullptr;
    }
    Addr me;
    if (!addrFromSock((const sockaddr*)&got, gl, me)) {
        err = "getsockname: неизвестное семейство адресов";
        close(s);
        return nullptr;
    }
    return std::unique_ptr<UdpSocket>(new SysUdp(s, v6, me.port));
}

}  // namespace lb
