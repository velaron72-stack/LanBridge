#include "plat.h"

#include <cstring>
#include <mutex>

#ifndef _WIN32
#include <time.h>
#endif

namespace lb {
namespace plat {

#ifdef _WIN32

namespace {

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#ifndef SIO_UDP_NETRESET
#define SIO_UDP_NETRESET _WSAIOW(IOC_VENDOR, 15)
#endif

thread_local int g_lastWsa = 0;

int mapWsa(int w) {
    switch (w) {
        case 0: return 0;
        case WSAEWOULDBLOCK:
        case WSAEINPROGRESS:
        case WSAEALREADY: return EAGAIN;
        case WSAEINTR: return EINTR;
        case WSAENOBUFS: return ENOBUFS;
        case WSAEMSGSIZE: return EMSGSIZE;
        case WSAEINVAL: return EINVAL;
        case WSAEFAULT: return EFAULT;
        case WSAEBADF:
        case WSAENOTSOCK: return EBADF;
        case WSAEACCES: return EACCES;
        case WSAEADDRINUSE: return EADDRINUSE;
        case WSAEADDRNOTAVAIL: return EADDRNOTAVAIL;
        case WSAEAFNOSUPPORT:
        case WSAEPFNOSUPPORT:
        case WSAEPROTONOSUPPORT:
        case WSAESOCKTNOSUPPORT:
        case WSAEOPNOTSUPP: return EAFNOSUPPORT;
        case WSAENETDOWN: return ENETDOWN;
        case WSAENETUNREACH: return ENETUNREACH;
        case WSAEHOSTUNREACH: return EHOSTUNREACH;
        case WSAECONNRESET:
        case WSAECONNABORTED: return ECONNRESET;
        case WSAENETRESET: return ENETRESET;
        case WSAEDESTADDRREQ: return EDESTADDRREQ;
        case WSAEMFILE: return EMFILE;
        case WSAETIMEDOUT: return ETIMEDOUT;
        case WSAEISCONN: return EISCONN;
        case WSAENOTCONN: return ENOTCONN;
        case WSANOTINITIALISED: return ENETDOWN;
        default: return EIO;
    }
}

int setErrnoFromWsa() {
    int w = WSAGetLastError();
    g_lastWsa = w;
    int e = mapWsa(w);
    errno = e;
    return e;
}

SOCKET S(int fd) { return (SOCKET)(unsigned)fd; }
int FD(SOCKET s) { return s == INVALID_SOCKET ? -1 : (int)s; }

void quietUdp(SOCKET s) {
    // A UDP socket must not turn an ICMP "port unreachable" (a peer that went away) into a receive error.
    DWORD no = 0;
    DWORD got = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &no, sizeof no, nullptr, 0, &got, nullptr, nullptr);
    got = 0;
    WSAIoctl(s, SIO_UDP_NETRESET, &no, sizeof no, nullptr, 0, &got, nullptr, nullptr);
}

}  // namespace

bool init() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA d;
        ok = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    });
    return ok;
}

int sockErrno() { return setErrnoFromWsa(); }

std::string errStr(int e) {
    std::string s = strerror(e);
    if (g_lastWsa != 0 && mapWsa(g_lastWsa) == e) s += " (WSA" + std::to_string(g_lastWsa) + ")";
    return s;
}

int closeFd(int fd) { return closesocket(S(fd)); }

bool setNonBlocking(int fd) {
    u_long on = 1;
    return ioctlsocket(S(fd), FIONBIO, &on) == 0;
}

ssize_t fdRead(int fd, void* b, size_t n) {
    int r = recv(S(fd), (char*)b, (int)n, 0);
    if (r == SOCKET_ERROR) {
        setErrnoFromWsa();
        return -1;
    }
    return r;
}

ssize_t fdWrite(int fd, const void* b, size_t n) {
    int r = send(S(fd), (const char*)b, (int)n, 0);
    if (r == SOCKET_ERROR) {
        setErrnoFromWsa();
        return -1;
    }
    return r;
}

ssize_t sendTo(int fd, const void* b, size_t n, const sockaddr* sa, socklen_t sl) {
    int r = sendto(S(fd), (const char*)b, (int)n, 0, sa, sl);
    if (r == SOCKET_ERROR) {
        setErrnoFromWsa();
        return -1;
    }
    return r;
}

ssize_t recvFrom(int fd, void* b, size_t n, sockaddr* sa, socklen_t* sl) {
    int r = recvfrom(S(fd), (char*)b, (int)n, 0, sa, sl);
    if (r == SOCKET_ERROR) {
        setErrnoFromWsa();
        return -1;
    }
    return r;
}

int openUdp(int family) {
    if (!init()) {
        errno = ENETDOWN;
        return -1;
    }
    SOCKET s = WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) {
        setErrnoFromWsa();
        return -1;
    }
    u_long on = 1;
    ioctlsocket(s, FIONBIO, &on);
    quietUdp(s);
    return FD(s);
}

bool setBuffers(int fd, int bytes) {
    bool a = setsockopt(S(fd), SOL_SOCKET, SO_RCVBUF, (const char*)&bytes, sizeof bytes) == 0;
    bool b = setsockopt(S(fd), SOL_SOCKET, SO_SNDBUF, (const char*)&bytes, sizeof bytes) == 0;
    return a && b;
}

bool setV6Only(int fd) {
    DWORD one = 1;
    return setsockopt(S(fd), IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&one, sizeof one) == 0;
}

bool datagramPair(int fds[2], int bufBytes) {
    fds[0] = fds[1] = -1;
    int a = openUdp(AF_INET);
    int b = openUdp(AF_INET);
    if (a < 0 || b < 0) {
        if (a >= 0) closeFd(a);
        if (b >= 0) closeFd(b);
        return false;
    }
    sockaddr_in la, lb2;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    lb2 = la;
    int sl = sizeof la;
    bool ok = bind(S(a), (sockaddr*)&la, sizeof la) == 0 && bind(S(b), (sockaddr*)&lb2, sizeof lb2) == 0 &&
              getsockname(S(a), (sockaddr*)&la, &sl) == 0;
    sl = sizeof lb2;
    ok = ok && getsockname(S(b), (sockaddr*)&lb2, &sl) == 0 && connect(S(a), (sockaddr*)&lb2, sizeof lb2) == 0 &&
         connect(S(b), (sockaddr*)&la, sizeof la) == 0;
    if (!ok) {
        setErrnoFromWsa();
        closeFd(a);
        closeFd(b);
        return false;
    }
    if (bufBytes > 0) {
        setBuffers(a, bufBytes);
        setBuffers(b, bufBytes);
    }
    fds[0] = a;
    fds[1] = b;
    return true;
}

bool makeWake(int fds[2]) { return datagramPair(fds, 64 * 1024); }

pollfd pollItem(int fd, short events) {
    pollfd p;
    p.fd = S(fd);
    p.events = events;
    p.revents = 0;
    return p;
}

int pollFds(pollfd* p, int n, int timeoutMs) {
    int r = WSAPoll(p, (ULONG)n, timeoutMs);
    if (r == SOCKET_ERROR) {
        setErrnoFromWsa();
        return -1;
    }
    return r;
}

void sleepMs(int ms) { Sleep((DWORD)(ms < 0 ? 0 : ms)); }

#else  // POSIX

bool init() { return true; }

int sockErrno() { return errno; }

std::string errStr(int e) { return strerror(e); }

int closeFd(int fd) { return close(fd); }

bool setNonBlocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return fl >= 0 && fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

ssize_t fdRead(int fd, void* b, size_t n) { return read(fd, b, n); }

ssize_t fdWrite(int fd, const void* b, size_t n) { return write(fd, b, n); }

ssize_t sendTo(int fd, const void* b, size_t n, const sockaddr* sa, socklen_t sl) {
    return sendto(fd, b, n, MSG_DONTWAIT, sa, sl);
}

ssize_t recvFrom(int fd, void* b, size_t n, sockaddr* sa, socklen_t* sl) {
    return recvfrom(fd, b, n, MSG_DONTWAIT, sa, sl);
}

int openUdp(int family) {
    int s = socket(family, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    setNonBlocking(s);
    fcntl(s, F_SETFD, FD_CLOEXEC);
    return s;
}

bool setBuffers(int fd, int bytes) {
    bool a = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes) == 0;
    bool b = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes) == 0;
    return a && b;
}

bool setV6Only(int fd) {
    int one = 1;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) == 0;
}

bool datagramPair(int fds[2], int bufBytes) {
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) < 0) return false;
    for (int i = 0; i < 2; i++) {
        setNonBlocking(fds[i]);
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
        if (bufBytes > 0) setBuffers(fds[i], bufBytes);
    }
    return true;
}

bool makeWake(int fds[2]) {
    if (pipe(fds) < 0) return false;
    for (int i = 0; i < 2; i++) {
        setNonBlocking(fds[i]);
        fcntl(fds[i], F_SETFD, FD_CLOEXEC);
    }
    return true;
}

pollfd pollItem(int fd, short events) { return pollfd{fd, events, 0}; }

int pollFds(pollfd* p, int n, int timeoutMs) { return poll(p, (nfds_t)n, timeoutMs); }

void sleepMs(int ms) {
    timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
}

#endif

}  // namespace plat
}  // namespace lb
