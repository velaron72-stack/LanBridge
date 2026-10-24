#include "wintun_win.h"

#include <iphlpapi.h>
#include <netioapi.h>
#include <shellapi.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>

#include "util.h"

namespace lb {
namespace wintun {

namespace {

// ------------------------------------------------------------------ Wintun API (loaded at run time)

typedef void* WT_ADAPTER;
typedef void* WT_SESSION;
typedef WT_ADAPTER(WINAPI* PFN_CreateAdapter)(LPCWSTR, LPCWSTR, const GUID*);
typedef WT_ADAPTER(WINAPI* PFN_OpenAdapter)(LPCWSTR);
typedef void(WINAPI* PFN_CloseAdapter)(WT_ADAPTER);
typedef void(WINAPI* PFN_GetAdapterLUID)(WT_ADAPTER, NET_LUID*);
typedef WT_SESSION(WINAPI* PFN_StartSession)(WT_ADAPTER, DWORD);
typedef void(WINAPI* PFN_EndSession)(WT_SESSION);
typedef HANDLE(WINAPI* PFN_GetReadWaitEvent)(WT_SESSION);
typedef BYTE*(WINAPI* PFN_ReceivePacket)(WT_SESSION, DWORD*);
typedef void(WINAPI* PFN_ReleaseReceivePacket)(WT_SESSION, const BYTE*);
typedef BYTE*(WINAPI* PFN_AllocateSendPacket)(WT_SESSION, DWORD);
typedef void(WINAPI* PFN_SendPacket)(WT_SESSION, const BYTE*);
typedef void(WINAPI* PFN_Logger)(int level, DWORD64 timestamp, LPCWSTR msg);
typedef void(WINAPI* PFN_SetLogger)(PFN_Logger);
typedef DWORD(WINAPI* PFN_DriverVersion)(void);

struct Api {
    HMODULE dll = nullptr;
    PFN_CreateAdapter CreateAdapter = nullptr;
    PFN_OpenAdapter OpenAdapter = nullptr;
    PFN_CloseAdapter CloseAdapter = nullptr;
    PFN_GetAdapterLUID GetAdapterLUID = nullptr;
    PFN_StartSession StartSession = nullptr;
    PFN_EndSession EndSession = nullptr;
    PFN_GetReadWaitEvent GetReadWaitEvent = nullptr;
    PFN_ReceivePacket ReceivePacket = nullptr;
    PFN_ReleaseReceivePacket ReleaseReceivePacket = nullptr;
    PFN_AllocateSendPacket AllocateSendPacket = nullptr;
    PFN_SendPacket SendPacket = nullptr;
    PFN_SetLogger SetLogger = nullptr;
    PFN_DriverVersion DriverVersion = nullptr;
};

template <class T>
T sym(HMODULE h, const char* name) {
    return reinterpret_cast<T>(reinterpret_cast<void*>(GetProcAddress(h, name)));
}

constexpr DWORD kRingBytes = 0x400000;  // 4 MiB per direction (a power of two between 128 KiB and 64 MiB)
constexpr int kPairBuf = 4 << 20;

struct State {
    std::mutex mu;  // open/close/swap/configure
    Api api;
    WT_ADAPTER adapter = nullptr;
    bool created = false;
    WT_SESSION session = nullptr;
    HANDLE quitEvent = nullptr;
    HANDLE readEvent = nullptr;
    std::atomic<bool> running{false};
    std::thread rx, tx;
    std::mutex pumpMu;
    int pump = -1;  // the pump-side socket of the current pair
    std::atomic<uint64_t> fromAdapter{0}, toAdapter{0}, dropped{0};
};

State& S() {
    static State* s = new State();  // never destroyed: the pump threads may outlive static destruction
    return *s;
}

std::string winErr(DWORD e) {
    wchar_t buf[256];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0, buf, 256, nullptr);
    std::string t = n ? toUtf8(std::wstring(buf, n)) : std::string();
    while (!t.empty() && (t.back() == '\r' || t.back() == '\n' || t.back() == ' ' || t.back() == '.')) t.pop_back();
    return strfmt("%s (код %lu)", t.empty() ? "ошибка Windows" : t.c_str(), (unsigned long)e);
}

void WINAPI wintunLog(int level, DWORD64, LPCWSTR msg) {
    static const char* names[] = {"info", "warn", "err"};
    LBLOG("Wintun %s: %s", names[level >= 0 && level < 3 ? level : 0], toUtf8(msg ? msg : L"").c_str());
}

// ------------------------------------------------------------------ pumps

void rxLoop() {  // adapter -> engine
    State& s = S();
    while (s.running.load()) {
        DWORD size = 0;
        BYTE* p = s.api.ReceivePacket(s.session, &size);
        if (p) {
            {
                std::lock_guard<std::mutex> g(s.pumpMu);
                if (s.pump >= 0) {
                    ssize_t w = plat::fdWrite(s.pump, p, size);
                    if (w < 0) s.dropped++;
                    else s.fromAdapter++;
                }
            }
            s.api.ReleaseReceivePacket(s.session, p);
            continue;
        }
        DWORD e = GetLastError();
        if (e == ERROR_NO_MORE_ITEMS) {
            HANDLE h[2] = {s.readEvent, s.quitEvent};
            DWORD r = WaitForMultipleObjects(2, h, FALSE, INFINITE);
            if (r != WAIT_OBJECT_0) break;
        } else if (e == ERROR_HANDLE_EOF) {
            break;
        } else {
            LBLOG("Wintun: приём пакета: %s", winErr(e).c_str());
            Sleep(50);
        }
    }
}

void txLoop() {  // engine -> adapter
    State& s = S();
    std::vector<uint8_t> buf(65536);
    while (s.running.load()) {
        int ps;
        {
            std::lock_guard<std::mutex> g(s.pumpMu);
            ps = s.pump;
        }
        if (ps < 0) {
            Sleep(20);
            continue;
        }
        pollfd pf = plat::pollItem(ps, POLLIN);
        int r = plat::pollFds(&pf, 1, 100);
        if (!s.running.load()) break;
        if (r <= 0) continue;
        for (int i = 0; i < 256; i++) {
            ssize_t n;
            {
                std::lock_guard<std::mutex> g(s.pumpMu);
                if (s.pump != ps) break;  // the pair was replaced meanwhile
                n = plat::fdRead(ps, buf.data(), buf.size());
            }
            if (n < 0) {
                if (errno != EAGAIN && errno != EINTR) Sleep(5);
                break;
            }
            if (n == 0) continue;
            BYTE* d = s.api.AllocateSendPacket(s.session, (DWORD)n);
            if (!d) {  // ring full: drop like a congested interface does
                s.dropped++;
                continue;
            }
            memcpy(d, buf.data(), (size_t)n);
            s.api.SendPacket(s.session, d);
            s.toAdapter++;
        }
    }
}

void stopPumps(State& s) {
    s.running.store(false);
    if (s.quitEvent) SetEvent(s.quitEvent);
    if (s.rx.joinable()) s.rx.join();
    if (s.tx.joinable()) s.tx.join();
}

// ------------------------------------------------------------------ IP Helper

bool parseV4(const std::string& t, IN_ADDR& out) { return InetPtonA(AF_INET, t.c_str(), &out) == 1; }
bool parseV6(const std::string& t, IN6_ADDR& out) { return InetPtonA(AF_INET6, t.c_str(), &out) == 1; }

void addLine(std::string& out, const char* kind, const std::string& msg) {
    out += kind;
    out += msg;
    out += '\n';
}

// Removes what an earlier configure() put on the adapter (manual addresses; the system's link-local ones stay).
void clearManual(const NET_LUID& luid) {
    PMIB_UNICASTIPADDRESS_TABLE t = nullptr;
    if (GetUnicastIpAddressTable(AF_UNSPEC, &t) == NO_ERROR && t) {
        for (ULONG i = 0; i < t->NumEntries; i++) {
            MIB_UNICASTIPADDRESS_ROW& r = t->Table[i];
            if (r.InterfaceLuid.Value != luid.Value) continue;
            if (r.PrefixOrigin != IpPrefixOriginManual) continue;
            DeleteUnicastIpAddressEntry(&r);
        }
        FreeMibTable(t);
    }
}

DWORD setInterface(const NET_LUID& luid, ADDRESS_FAMILY fam, int mtu, int metric) {
    MIB_IPINTERFACE_ROW row;
    InitializeIpInterfaceEntry(&row);
    row.Family = fam;
    row.InterfaceLuid = luid;
    DWORD e = GetIpInterfaceEntry(&row);
    if (e != NO_ERROR) return e;
    row.SitePrefixLength = 0;  // the call is refused with a non-zero value left over from Get on IPv4
    row.UseAutomaticMetric = FALSE;
    row.Metric = (ULONG)metric;
    if (mtu > 0) row.NlMtu = (ULONG)mtu;
    if (fam == AF_INET6) {
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
    }
    return SetIpInterfaceEntry(&row);
}

}  // namespace

// ------------------------------------------------------------------ strings

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring fromUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

// ------------------------------------------------------------------ public

std::string load(const std::wstring& dllPath) {
    State& s = S();
    std::lock_guard<std::mutex> g(s.mu);
    if (s.api.dll) return std::string();
    HMODULE h = LoadLibraryExW(dllPath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h) return strfmt("wintun.dll не загружен (%s): %s", toUtf8(dllPath).c_str(), winErr(GetLastError()).c_str());
    Api a;
    a.dll = h;
#define LB_SYM(field, name)                                                              \
    a.field = sym<decltype(a.field)>(h, name);                                           \
    if (!a.field) {                                                                      \
        FreeLibrary(h);                                                                  \
        return std::string("в wintun.dll нет функции ") + name;                          \
    }
    LB_SYM(CreateAdapter, "WintunCreateAdapter")
    LB_SYM(OpenAdapter, "WintunOpenAdapter")
    LB_SYM(CloseAdapter, "WintunCloseAdapter")
    LB_SYM(GetAdapterLUID, "WintunGetAdapterLUID")
    LB_SYM(StartSession, "WintunStartSession")
    LB_SYM(EndSession, "WintunEndSession")
    LB_SYM(GetReadWaitEvent, "WintunGetReadWaitEvent")
    LB_SYM(ReceivePacket, "WintunReceivePacket")
    LB_SYM(ReleaseReceivePacket, "WintunReleaseReceivePacket")
    LB_SYM(AllocateSendPacket, "WintunAllocateSendPacket")
    LB_SYM(SendPacket, "WintunSendPacket")
#undef LB_SYM
    a.SetLogger = sym<PFN_SetLogger>(h, "WintunSetLogger");
    a.DriverVersion = sym<PFN_DriverVersion>(h, "WintunGetRunningDriverVersion");
    if (a.SetLogger) a.SetLogger(wintunLog);
    s.api = a;
    return std::string();
}

int open(const std::wstring& name, const GUID& guid, std::string& err) {
    State& s = S();
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.api.dll) {
        err = "wintun.dll не загружен";
        return -1;
    }
    if (s.running.load() || s.adapter) {
        err = "адаптер уже открыт";
        return -1;
    }
    if (!plat::init()) {
        err = "Winsock не запустился";
        return -1;
    }
    // A leftover adapter of that name (a previous run that did not exit cleanly) is taken over as it is.
    WT_ADAPTER ad = s.api.OpenAdapter(name.c_str());
    bool created = false;
    if (!ad) {
        ad = s.api.CreateAdapter(name.c_str(), L"LanBridge", &guid);
        created = ad != nullptr;
    }
    if (!ad) {
        DWORD e = GetLastError();
        err = strfmt("адаптер Wintun не создан: %s%s", winErr(e).c_str(),
                     e == ERROR_ACCESS_DENIED ? " — нужны права администратора" : "");
        return -1;
    }
    WT_SESSION ses = s.api.StartSession(ad, kRingBytes);
    if (!ses) {
        err = strfmt("сессия Wintun не открыта: %s", winErr(GetLastError()).c_str());
        s.api.CloseAdapter(ad);
        return -1;
    }
    int fds[2];
    if (!plat::datagramPair(fds, kPairBuf)) {
        err = strfmt("пара сокетов не создана: %s", plat::errStr(plat::sockErrno()).c_str());
        s.api.EndSession(ses);
        s.api.CloseAdapter(ad);
        return -1;
    }
    s.adapter = ad;
    s.created = created;
    s.session = ses;
    s.readEvent = s.api.GetReadWaitEvent(ses);
    s.quitEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    s.pump = fds[1];
    s.fromAdapter = s.toAdapter = s.dropped = 0;
    s.running.store(true);
    s.rx = std::thread(rxLoop);
    s.tx = std::thread(txLoop);
    LBLOG("Wintun: адаптер %s %s, драйвер %lu", toUtf8(name).c_str(), created ? "создан" : "взят существующий",
          s.api.DriverVersion ? (unsigned long)s.api.DriverVersion() : 0ul);
    return fds[0];
}

int swapPair(std::string& err) {
    State& s = S();
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.running.load()) {
        err = "адаптер не открыт";
        return -1;
    }
    int fds[2];
    if (!plat::datagramPair(fds, kPairBuf)) {
        err = strfmt("пара сокетов не создана: %s", plat::errStr(plat::sockErrno()).c_str());
        return -1;
    }
    int old;
    {
        std::lock_guard<std::mutex> pg(s.pumpMu);
        old = s.pump;
        s.pump = fds[1];
        if (old >= 0) plat::closeFd(old);
    }
    return fds[0];
}

std::string configure(const IpConfig& c) {
    State& s = S();
    std::lock_guard<std::mutex> g(s.mu);
    std::string out;
    if (!s.adapter) return "E:адаптер не открыт\n";
    NET_LUID luid;
    s.api.GetAdapterLUID(s.adapter, &luid);
    clearManual(luid);

    if (!c.ip4.empty()) {
        MIB_UNICASTIPADDRESS_ROW r;
        InitializeUnicastIpAddressEntry(&r);
        r.InterfaceLuid = luid;
        r.Address.si_family = AF_INET;
        if (!parseV4(c.ip4, r.Address.Ipv4.sin_addr)) {
            addLine(out, "E:", "неверный адрес IPv4: " + c.ip4);
        } else {
            r.OnLinkPrefixLength = (UINT8)c.prefix4;
            r.DadState = IpDadStatePreferred;
            r.ValidLifetime = 0xffffffffu;
            r.PreferredLifetime = 0xffffffffu;
            DWORD e = CreateUnicastIpAddressEntry(&r);
            if (e != NO_ERROR && e != ERROR_OBJECT_ALREADY_EXISTS)
                addLine(out, "E:", "адрес IPv4 " + c.ip4 + " не назначен: " + winErr(e));
        }
        DWORD e = setInterface(luid, AF_INET, c.mtu, c.metric);
        if (e != NO_ERROR) addLine(out, "W:", "параметры интерфейса IPv4 (MTU, метрика): " + winErr(e));
    }
    if (!c.ip6.empty()) {
        MIB_UNICASTIPADDRESS_ROW r;
        InitializeUnicastIpAddressEntry(&r);
        r.InterfaceLuid = luid;
        r.Address.si_family = AF_INET6;
        if (!parseV6(c.ip6, r.Address.Ipv6.sin6_addr)) {
            addLine(out, "W:", "неверный адрес IPv6: " + c.ip6);
        } else {
            r.OnLinkPrefixLength = (UINT8)c.prefix6;
            r.DadState = IpDadStatePreferred;
            r.ValidLifetime = 0xffffffffu;
            r.PreferredLifetime = 0xffffffffu;
            DWORD e = CreateUnicastIpAddressEntry(&r);
            if (e != NO_ERROR && e != ERROR_OBJECT_ALREADY_EXISTS)
                addLine(out, "W:", "адрес IPv6 " + c.ip6 + " не назначен: " + winErr(e));
        }
        DWORD e = setInterface(luid, AF_INET6, c.mtu < 1280 ? 1280 : c.mtu, c.metric);
        if (e != NO_ERROR) addLine(out, "W:", "параметры интерфейса IPv6 (MTU, метрика): " + winErr(e));
    }
    return out;
}

void close() {
    State& s = S();
    std::lock_guard<std::mutex> g(s.mu);
    if (!s.adapter && !s.running.load()) return;
    stopPumps(s);
    LBLOG("Wintun: %s", stats().c_str());
    {
        std::lock_guard<std::mutex> pg(s.pumpMu);
        if (s.pump >= 0) plat::closeFd(s.pump);
        s.pump = -1;
    }
    if (s.quitEvent) {
        CloseHandle(s.quitEvent);
        s.quitEvent = nullptr;
    }
    if (s.session) s.api.EndSession(s.session);
    if (s.adapter) s.api.CloseAdapter(s.adapter);  // removes the adapter if this process created it
    s.session = nullptr;
    s.adapter = nullptr;
    s.readEvent = nullptr;
    s.created = false;
}

std::string stats() {
    State& s = S();
    return strfmt("из адаптера %llu, в адаптер %llu, потеряно %llu", (unsigned long long)s.fromAdapter.load(),
                  (unsigned long long)s.toAdapter.load(), (unsigned long long)s.dropped.load());
}

bool isElevated() {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return false;
    TOKEN_ELEVATION e;
    DWORD got = 0;
    bool ok = GetTokenInformation(t, TokenElevation, &e, sizeof e, &got) && e.TokenIsElevated;
    CloseHandle(t);
    return ok;
}

bool relaunchElevated(const std::wstring& exe, const std::wstring& args) {
    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof sei);
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    sei.lpFile = exe.c_str();
    sei.lpParameters = args.empty() ? nullptr : args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

int runHidden(const std::wstring& cmdline, int timeoutMs, std::string& output) {
    output.clear();
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof sa;
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si;
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof pi);
    std::wstring cl = cmdline;  // CreateProcessW may modify the buffer
    cl.push_back(L'\0');
    BOOL ok = CreateProcessW(nullptr, &cl[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        CloseHandle(rd);
        return -1;
    }
    std::string raw;
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeoutMs < 0 ? 0 : timeoutMs);
    int code = -1;
    for (;;) {
        DWORD avail = 0;
        while (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            char b[1024];
            DWORD got = 0;
            if (!ReadFile(rd, b, sizeof b, &got, nullptr) || got == 0) break;
            raw.append(b, got);
            if (raw.size() > (1u << 20)) break;
        }
        DWORD w = WaitForSingleObject(pi.hProcess, 30);
        if (w == WAIT_OBJECT_0) {
            DWORD ec = 0;
            GetExitCodeProcess(pi.hProcess, &ec);
            code = (int)ec;
            DWORD avail2 = 0;
            while (PeekNamedPipe(rd, nullptr, 0, nullptr, &avail2, nullptr) && avail2 > 0) {
                char b[1024];
                DWORD got = 0;
                if (!ReadFile(rd, b, sizeof b, &got, nullptr) || got == 0) break;
                raw.append(b, got);
            }
            break;
        }
        if (GetTickCount64() >= deadline) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 1000);
            code = -2;
            break;
        }
    }
    CloseHandle(rd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    // Console programs print in the OEM code page.
    if (!raw.empty()) {
        int n = MultiByteToWideChar(GetOEMCP(), 0, raw.data(), (int)raw.size(), nullptr, 0);
        if (n > 0) {
            std::wstring w((size_t)n, L'\0');
            MultiByteToWideChar(GetOEMCP(), 0, raw.data(), (int)raw.size(), &w[0], n);
            output = toUtf8(w);
        }
    }
    return code;
}

namespace {
struct Awake {
    std::mutex mu;
    std::thread th;
    HANDLE ev = nullptr;
};
Awake& A() {
    static Awake* a = new Awake();
    return *a;
}
}  // namespace

void keepAwake(bool on) {
    Awake& a = A();
    std::lock_guard<std::mutex> g(a.mu);
    if (on) {
        if (a.th.joinable()) return;
        a.ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE ev = a.ev;
        // SetThreadExecutionState is per thread: a thread of its own holds the state until it is released.
        a.th = std::thread([ev] {
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
            WaitForSingleObject(ev, INFINITE);
            SetThreadExecutionState(ES_CONTINUOUS);
        });
    } else if (a.th.joinable()) {
        SetEvent(a.ev);
        a.th.join();
        CloseHandle(a.ev);
        a.ev = nullptr;
    }
}

}  // namespace wintun
}  // namespace lb
