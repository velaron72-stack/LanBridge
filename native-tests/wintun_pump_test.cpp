// Windows only: the pumps between a Wintun session and the engine's TUN fd (wintun_win.cpp), run against fake_wintun.dll.
// Build and run: native-tests/run-win.sh (it does both).
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "plat.h"
#include "util.h"
#include "wintun_win.h"

using namespace lb;

static int g_pass = 0, g_fail = 0;
#define CHECK(c)                                                       \
    do {                                                               \
        if (c) g_pass++;                                               \
        else {                                                         \
            g_fail++;                                                  \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);      \
        }                                                              \
    } while (0)

typedef void(WINAPI* FnInject)(const uint8_t*, DWORD);
typedef DWORD(WINAPI* FnPop)(uint8_t*, DWORD);
typedef int(WINAPI* FnOpens)(void);

static FnInject fakeInject;
static FnPop fakePop;
static FnOpens fakeOpens;

static std::vector<uint8_t> pkt(int i, size_t len) {
    std::vector<uint8_t> p(len);
    for (size_t k = 0; k < len; k++) p[k] = (uint8_t)(i * 31 + k * 7);
    p[0] = 0x45;
    return p;
}

static bool readFd(int fd, std::vector<uint8_t>& out, int timeoutMs) {
    pollfd pf = plat::pollItem(fd, POLLIN);
    if (plat::pollFds(&pf, 1, timeoutMs) <= 0) return false;
    uint8_t b[4096];
    ssize_t n = plat::fdRead(fd, b, sizeof b);
    if (n <= 0) return false;
    out.assign(b, b + n);
    return true;
}

static bool popAdapter(std::vector<uint8_t>& out, int timeoutMs) {
    for (int waited = 0; waited <= timeoutMs; waited += 2) {
        uint8_t b[4096];
        DWORD n = fakePop(b, sizeof b);
        if (n) {
            out.assign(b, b + n);
            return true;
        }
        Sleep(2);
    }
    return false;
}

static const GUID kGuid = {0x7a1b8e3c, 0x5d44, 0x4f0b, {0x9c, 0x21, 0x6e, 0x0a, 0x5b, 0x7d, 0x2f, 0x11}};

int main() {
    printf("[wintun] load\n");
    HMODULE fake = LoadLibraryW(L"fake_wintun.dll");
    CHECK(fake != nullptr);
    if (!fake) return 1;
    fakeInject = (FnInject)(void*)GetProcAddress(fake, "FakeInject");
    fakePop = (FnPop)(void*)GetProcAddress(fake, "FakePop");
    fakeOpens = (FnOpens)(void*)GetProcAddress(fake, "FakeOpens");
    CHECK(fakeInject && fakePop && fakeOpens);

    CHECK(!wintun::load(L"no_such_wintun.dll").empty());  // a missing library is reported, not fatal
    CHECK(wintun::load(L"fake_wintun.dll").empty());

    std::string err;
    CHECK(wintun::swapPair(err) < 0);  // nothing open yet
    printf("[wintun] open and adapter -> engine\n");
    int fd = wintun::open(L"LanBridgeTest", kGuid, err);
    CHECK(fd >= 0);
    if (fd < 0) {
        printf("  %s\n", err.c_str());
        return 1;
    }
    CHECK(fakeOpens() == 1);
    CHECK(wintun::open(L"LanBridgeTest", kGuid, err) < 0);  // second open is refused

    std::vector<uint8_t> got;
    auto p1 = pkt(1, 1400);
    fakeInject(p1.data(), (DWORD)p1.size());
    CHECK(readFd(fd, got, 2000) && got == p1);

    int okIn = 0;
    for (int i = 0; i < 400; i++) {
        auto p = pkt(i, 40 + (size_t)(i * 37) % 1460);
        fakeInject(p.data(), (DWORD)p.size());
    }
    for (int i = 0; i < 400; i++) {
        auto p = pkt(i, 40 + (size_t)(i * 37) % 1460);
        if (readFd(fd, got, 2000) && got == p) okIn++;
    }
    CHECK(okIn == 400);  // all of them, in order, with the sizes intact

    printf("[wintun] engine -> adapter\n");
    int okOut = 0;
    for (int i = 0; i < 400; i++) {
        auto p = pkt(1000 + i, 20 + (size_t)(i * 53) % 1480);
        if (plat::fdWrite(fd, p.data(), p.size()) == (ssize_t)p.size()) {
            std::vector<uint8_t> o;
            if (popAdapter(o, 2000) && o == p) okOut++;
        }
    }
    CHECK(okOut == 400);

    printf("[wintun] replacing the pair (layout change)\n");
    int fd2 = wintun::swapPair(err);
    CHECK(fd2 >= 0 && fd2 != fd);
    plat::closeFd(fd);  // what Engine::swapTun does with the old descriptor
    auto p2 = pkt(7, 777);
    fakeInject(p2.data(), (DWORD)p2.size());
    CHECK(readFd(fd2, got, 2000) && got == p2);
    auto p3 = pkt(8, 555);
    CHECK(plat::fdWrite(fd2, p3.data(), p3.size()) == (ssize_t)p3.size());
    std::vector<uint8_t> o;
    CHECK(popAdapter(o, 2000) && o == p3);

    // Wine has no IP Helper address functions (it aborts on the call), and the fake adapter has no interface anyway:
    // this part only runs on a real Windows, where it must report instead of crashing.
    if (!GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version")) {
        printf("[wintun] configure without a real adapter reports instead of crashing\n");
        wintun::IpConfig c;
        c.ip4 = "10.77.1.2";
        c.ip6 = "fd00::2";
        std::string res = wintun::configure(c);
        CHECK(!res.empty());
        printf("  %s", res.c_str());
    } else {
        printf("[wintun] configure skipped (Wine)\n");
    }

    printf("[wintun] stats and close\n");
    CHECK(wintun::stats().find("из адаптера") != std::string::npos);
    wintun::close();
    plat::closeFd(fd2);
    wintun::close();  // twice is fine
    std::string e3;
    int fd3 = wintun::open(L"LanBridgeTest", kGuid, e3);
    CHECK(fd3 >= 0);  // the adapter can be opened again after close
    auto p4 = pkt(9, 99);
    fakeInject(p4.data(), (DWORD)p4.size());
    CHECK(readFd(fd3, got, 2000) && got == p4);
    wintun::close();
    plat::closeFd(fd3);

    printf("[wintun] helpers\n");
    std::string out;
    int code = wintun::runHidden(L"cmd.exe /c echo lanbridge-ok", 5000, out);
    CHECK(code == 0 && out.find("lanbridge-ok") != std::string::npos);
    code = wintun::runHidden(L"cmd.exe /c exit 3", 5000, out);
    CHECK(code == 3);
    code = wintun::runHidden(L"definitely_not_a_program.exe", 2000, out);
    CHECK(code == -1);
    CHECK(wintun::toUtf8(wintun::fromUtf8("LanBridge ёж")) == "LanBridge ёж");
    (void)wintun::isElevated();

    printf("\nresult: %d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
