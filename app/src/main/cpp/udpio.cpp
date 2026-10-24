#include "udpio.h"

#include <errno.h>

#include <cstring>

#include "plat.h"
#include "util.h"

namespace lb {

namespace {

class SysUdp : public UdpSocket {
public:
    SysUdp(int fd, bool v6, uint16_t port) : fd_(fd), v6_(v6), port_(port) {}
    ~SysUdp() override {
        if (fd_ >= 0) plat::closeFd(fd_);
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
        return plat::sendTo(fd_, b, n, (const sockaddr*)&ss, sl);
    }

    ssize_t recvFrom(uint8_t* b, size_t cap, Addr& from) override {
        sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        ssize_t n = plat::recvFrom(fd_, b, cap, (sockaddr*)&ss, &sl);
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
    int s = plat::openUdp(v6 ? AF_INET6 : AF_INET);
    if (s < 0) {
        err = strfmt("socket(%s): %s", v6 ? "IPv6" : "IPv4", plat::errStr(plat::sockErrno()).c_str());
        return nullptr;
    }
    plat::setBuffers(s, 4 << 20);
    sockaddr_storage ss;
    socklen_t sl = 0;
    if (v6) plat::setV6Only(s);
    Addr any = v6 ? addr6(Ip6{}, 0) : addr4(0, 0);
    addrToSock(any, ss, sl);
    if (bind(s, (const sockaddr*)&ss, sl) < 0) {
        err = strfmt("bind(%s): %s", v6 ? "IPv6" : "IPv4", plat::errStr(plat::sockErrno()).c_str());
        plat::closeFd(s);
        return nullptr;
    }
    sockaddr_storage got;
    socklen_t gl = sizeof got;
    if (getsockname(s, (sockaddr*)&got, &gl) < 0) {
        err = strfmt("getsockname: %s", plat::errStr(plat::sockErrno()).c_str());
        plat::closeFd(s);
        return nullptr;
    }
    Addr me;
    if (!addrFromSock((const sockaddr*)&got, gl, me)) {
        err = "getsockname: неизвестное семейство адресов";
        plat::closeFd(s);
        return nullptr;
    }
    return std::unique_ptr<UdpSocket>(new SysUdp(s, v6, me.port));
}

}  // namespace lb
