// LanBridge native core: the few operating-system calls that differ between Linux/Android and Windows.
// Everything above this layer (engine, transport, groups) is the same code on both. A "fd" is a small int on both
// systems; on Windows every fd the core touches is a socket (the TUN fd is a loopback UDP socket fed by a Wintun
// pump, see wintun_win.cpp), so read/write/poll semantics match the Linux ones: one datagram or IP packet per call.
#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sys/types.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <errno.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace lb {
namespace plat {

// Once per process (Winsock on Windows, nothing elsewhere). Every function below that creates a socket calls it.
bool init();

// errno after a failed socket call: on Windows the Winsock error mapped to the errno value the engine tests for.
int sockErrno();
// strerror() that also names the Winsock error code on Windows.
std::string errStr(int e);

int closeFd(int fd);                                   // close(2) / closesocket
bool setNonBlocking(int fd);
ssize_t fdRead(int fd, void* b, size_t n);             // read(2) / recv: -1 with errno set (EAGAIN: nothing waiting)
ssize_t fdWrite(int fd, const void* b, size_t n);      // write(2) / send
ssize_t sendTo(int fd, const void* b, size_t n, const sockaddr* sa, socklen_t sl);  // never blocks
ssize_t recvFrom(int fd, void* b, size_t n, sockaddr* sa, socklen_t* sl);           // never blocks

int openUdp(int family);                               // non-blocking, close-on-exec, no ICMP reset errors; -1 on failure
bool setBuffers(int fd, int bytes);                    // SO_RCVBUF + SO_SNDBUF
bool setV6Only(int fd);

// A pair of connected datagram endpoints. POSIX: socketpair(AF_UNIX, SOCK_DGRAM). Windows: two loopback UDP sockets
// connected to each other. Both ends are non-blocking.
bool datagramPair(int fds[2], int bufBytes);
// The wake-up channel of the engine loop: pipe on POSIX, a small datagram pair on Windows.
bool makeWake(int fds[2]);

pollfd pollItem(int fd, short events);
int pollFds(pollfd* p, int n, int timeoutMs);          // poll(2) / WSAPoll

void sleepMs(int ms);

}  // namespace plat
}  // namespace lb
