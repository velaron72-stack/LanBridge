// Real-kernel end-to-end harness: two network namespaces, a TUN device in each (like Android's VpnService),
// two LanBridge engines in between (loopback UDP). The apps (nettest.py) run inside the namespaces.
// Needs root and /dev/net/tun. Usage: nettest [alias]    (stdin EOF stops it)
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "engine.h"
#include "util.h"

using namespace lb;

static int sendFd(int sock, int fd) {
    char c = 'F';
    iovec iov{&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    memset(ctl, 0, sizeof ctl);
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl;
    m.msg_controllen = sizeof ctl;
    cmsghdr* cm = CMSG_FIRSTHDR(&m);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &fd, sizeof(int));
    return (int)sendmsg(sock, &m, 0);
}
static int recvFd(int sock) {
    char c;
    iovec iov{&c, 1};
    char ctl[CMSG_SPACE(sizeof(int))];
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl;
    m.msg_controllen = sizeof ctl;
    if (recvmsg(sock, &m, 0) <= 0) return -1;
    cmsghdr* cm = CMSG_FIRSTHDR(&m);
    if (!cm) return -1;
    int fd;
    memcpy(&fd, CMSG_DATA(cm), sizeof(int));
    return fd;
}

static sockaddr_in sa(uint32_t ip) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(ip);
    return a;
}
static uint32_t maskOf(int prefix) { return prefix == 0 ? 0 : (0xFFFFFFFFu << (32 - prefix)); }

static std::string childDo(const std::string& line) {
    std::istringstream is(line);
    std::string cmd;
    is >> cmd;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    std::string res = "ok";
    if (cmd == "ADDR") {
        std::string ifn, ip;
        int prefix;
        is >> ifn >> ip >> prefix;
        ifreq ifr{};
        strncpy(ifr.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
        uint32_t v;
        parseIp(ip, v);
        sockaddr_in a = sa(v);
        memcpy(&ifr.ifr_addr, &a, sizeof a);
        if (ioctl(s, SIOCSIFADDR, &ifr) < 0) res = std::string("err SIOCSIFADDR ") + strerror(errno);
        a = sa(maskOf(prefix));
        memcpy(&ifr.ifr_netmask, &a, sizeof a);
        if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) res = std::string("err SIOCSIFNETMASK ") + strerror(errno);
    } else if (cmd == "UP") {
        std::string ifn;
        int mtu;
        is >> ifn >> mtu;
        ifreq ifr{};
        strncpy(ifr.ifr_name, ifn.c_str(), IFNAMSIZ - 1);
        if (mtu > 0) {
            ifr.ifr_mtu = mtu;
            if (ioctl(s, SIOCSIFMTU, &ifr) < 0) res = std::string("err SIOCSIFMTU ") + strerror(errno);
        }
        ioctl(s, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) res = std::string("err SIOCSIFFLAGS ") + strerror(errno);
    } else if (cmd == "ROUTE") {
        std::string ip;
        int prefix;
        is >> ip >> prefix;
        uint32_t v;
        parseIp(ip, v);
        rtentry rt{};
        sockaddr_in d = sa(v), m = sa(maskOf(prefix)), g = sa(0);
        memcpy(&rt.rt_dst, &d, sizeof d);
        memcpy(&rt.rt_genmask, &m, sizeof m);
        memcpy(&rt.rt_gateway, &g, sizeof g);
        rt.rt_flags = RTF_UP | (prefix == 32 ? RTF_HOST : 0);
        static char dev[] = "lbtun0";
        rt.rt_dev = dev;
        if (ioctl(s, SIOCADDRT, &rt) < 0) res = std::string("err SIOCADDRT ") + strerror(errno);
    } else if (cmd == "DELROUTE") {
        std::string ip;
        int prefix;
        is >> ip >> prefix;
        uint32_t v;
        parseIp(ip, v);
        rtentry rt{};
        sockaddr_in d = sa(v), m = sa(maskOf(prefix)), g = sa(0);
        memcpy(&rt.rt_dst, &d, sizeof d);
        memcpy(&rt.rt_genmask, &m, sizeof m);
        memcpy(&rt.rt_gateway, &g, sizeof g);
        rt.rt_flags = RTF_UP;
        static char dev[] = "lbtun0";
        rt.rt_dev = dev;
        if (ioctl(s, SIOCDELRT, &rt) < 0) res = std::string("err SIOCDELRT ") + strerror(errno);
    } else {
        res = "err unknown";
    }
    close(s);
    return res;
}

struct Child {
    pid_t pid = -1;
    int ctl = -1;
    int tun = -1;
};

static Child spawn(const char* name) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(sv[0]);
        if (unshare(CLONE_NEWNET) != 0) {
            perror("unshare");
            _exit(1);
        }
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        ifreq lo{};
        strncpy(lo.ifr_name, "lo", IFNAMSIZ - 1);
        ioctl(s, SIOCGIFFLAGS, &lo);
        lo.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(s, SIOCSIFFLAGS, &lo);
        close(s);
        int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, "lbtun0", IFNAMSIZ - 1);
        if (fd < 0 || ioctl(fd, TUNSETIFF, &ifr) < 0) {
            perror("tun");
            _exit(2);
        }
        sendFd(sv[1], fd);
        close(fd);
        FILE* in = fdopen(sv[1], "r");
        char line[512];
        while (fgets(line, sizeof line, in)) {
            std::string r = childDo(line) + "\n";
            (void)!write(sv[1], r.data(), r.size());
        }
        _exit(0);
    }
    close(sv[1]);
    Child c;
    c.pid = pid;
    c.ctl = sv[0];
    c.tun = recvFd(sv[0]);
    (void)name;
    return c;
}

static bool ctl(Child& c, const std::string& cmd) {
    std::string l = cmd + "\n";
    (void)!write(c.ctl, l.data(), l.size());
    char buf[256];
    ssize_t n = read(c.ctl, buf, sizeof buf - 1);
    if (n <= 0) return false;
    buf[n] = 0;
    if (strncmp(buf, "ok", 2) != 0) {
        fprintf(stderr, "child cmd '%s' -> %s", cmd.c_str(), buf);
        return false;
    }
    return true;
}

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> o;
    std::string cur;
    for (char c : s) {
        if (c == d) {
            if (!cur.empty()) o.push_back(cur);
            cur.clear();
        } else cur += c;
    }
    if (!cur.empty()) o.push_back(cur);
    return o;
}

int main(int argc, char** argv) {
    bool alias = false, android = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "alias")) alias = true;
        if (!strcmp(argv[i], "android")) android = true;
    }
    Child ca = spawn("A"), cb = spawn("B");
    if (ca.tun < 0 || cb.tun < 0) {
        fprintf(stderr, "cannot create TUN in namespaces\n");
        return 2;
    }
    Engine ea, eb;
    std::vector<uint8_t> oa, ob;
    std::vector<std::string> ipsA = {"127.0.0.1"}, ipsB = {"127.0.0.1"};
    if (alias) {
        ipsA = {"192.168.1.5", "127.0.0.1"};
        ipsB = {"10.20.30.7", "127.0.0.1"};
    }
    if (ea.prepare({}, ipsA, "Alpha", 600, oa) != 0 || eb.prepare({}, ipsB, "Bravo", 600, ob) != 0) {
        fprintf(stderr, "prepare failed\n");
        return 3;
    }
    if (ea.setPeer(ob) != 0 || eb.setPeer(oa) != 0) {
        fprintf(stderr, "setPeer failed\n");
        return 3;
    }
    Layout la, lb;
    ea.layout(la);
    eb.layout(lb);
    std::string info = ea.info() + eb.info();
    auto cfgChild = [&](Child& c, Engine& e, const Layout& l) {
        bool ok = true;
        std::string inf = e.info();
        std::string realIps, aliasPeer;
        for (const std::string& line : split(inf, '\n')) {
            if (line.rfind("realIp=", 0) == 0) realIps = line.substr(7);
            if (line.rfind("aliasPeer=", 0) == 0) aliasPeer = line.substr(10);
        }
        std::vector<std::string> mine = split(realIps, ',');
        if (!mine.empty()) {
            ok &= ctl(c, "ADDR lbtun0 " + mine[0] + " 32");
            ok &= ctl(c, "ADDR lbtun0:1 " + ipStr(l.myIp) + " " + std::to_string(l.prefix));
        } else {
            ok &= ctl(c, "ADDR lbtun0 " + ipStr(l.myIp) + " " + std::to_string(l.prefix));
        }
        ok &= ctl(c, "UP lbtun0 1280");
        if (android) {
            // Android installs the virtual network as a plain route without a preferred source: every packet that
            // leaves through the TUN then gets the FIRST address of the interface as its source.
            ok &= ctl(c, "DELROUTE " + ipStr(l.net) + " " + std::to_string(l.prefix));
            ok &= ctl(c, "ROUTE " + ipStr(l.net) + " " + std::to_string(l.prefix));
        }
        ok &= ctl(c, "ROUTE 255.255.255.255 32");
        ok &= ctl(c, "ROUTE 224.0.0.0 4");
        for (const std::string& a : split(aliasPeer, ',')) ok &= ctl(c, "ROUTE " + a + " 32");
        return ok;
    };
    if (!cfgChild(ca, ea, la) || !cfgChild(cb, eb, lb)) return 4;
    if (ea.start(ca.tun, 1280) != 0 || eb.start(cb.tun, 1280) != 0) {
        fprintf(stderr, "start failed: %s %s\n", ea.lastError().c_str(), eb.lastError().c_str());
        return 5;
    }
    int64_t sa_[STATUS_FIELDS], sb_[STATUS_FIELDS];
    bool up = false;
    for (int i = 0; i < 200 && !up; i++) {
        usleep(50000);
        ea.status(sa_);
        eb.status(sb_);
        up = sa_[0] == ST_CONNECTED && sb_[0] == ST_CONNECTED;
    }
    if (!up) {
        fprintf(stderr, "not connected\n%s\n", logDump().c_str());
        return 6;
    }
    printf("READY %d %d %s %s\n", (int)ca.pid, (int)cb.pid, ipStr(la.myIp).c_str(), ipStr(lb.myIp).c_str());
    printf("INFO_A %s\n", [&] { std::string s = ea.info(); for (char& c : s) if (c == '\n') c = ' '; return s; }().c_str());
    printf("INFO_B %s\n", [&] { std::string s = eb.info(); for (char& c : s) if (c == '\n') c = ' '; return s; }().c_str());
    fflush(stdout);
    pollfd pf{0, POLLIN, 0};
    for (;;) {
        int r = poll(&pf, 1, 1000);
        if (r > 0) {
            char b[64];
            if (read(0, b, sizeof b) <= 0) break;
        }
    }
    ea.status(sa_);
    eb.status(sb_);
    auto dump = [&](const char* tag, int64_t* s) {
        printf("STATS %s state=%lld rx=%lldB/%lldp tx=%lldB/%lldp bcastTx=%lld bcastRx=%lld mcastTx=%lld mcastRx=%lld auth=%lld dropped=%lld hs=%lld\n",
               tag, (long long)s[0], (long long)s[1], (long long)s[3], (long long)s[2], (long long)s[4], (long long)s[9],
               (long long)s[10], (long long)s[11], (long long)s[12], (long long)s[13], (long long)s[16], (long long)s[21]);
    };
    dump("A", sa_);
    dump("B", sb_);
    printf("FLOWS_A %s\n", [&] { std::string s = ea.flows(); for (char& c : s) if (c == '\n') c = '|'; return s; }().c_str());
    printf("FLOWS_B %s\n", [&] { std::string s = eb.flows(); for (char& c : s) if (c == '\n') c = '|'; return s; }().c_str());
    fflush(stdout);
    ea.stop();
    eb.stop();
    kill(ca.pid, SIGKILL);
    kill(cb.pid, SIGKILL);
    return 0;
}
