// A stand-in for wintun.dll for tests: the same exported functions, backed by two in-memory queues. It lets the
// pumps of wintun_win.cpp be exercised on a machine without the Wintun driver (Wine, a CI runner without admin).
// FakeInject() puts a packet "arriving from the network" into the adapter, FakePop() takes a packet the program
// "sent into the network".
#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

namespace {
std::mutex g_mu;
std::deque<std::vector<uint8_t>> g_rx, g_tx;
HANDLE g_ev = nullptr;
int g_opens = 0;
}  // namespace

#define EXPORT extern "C" __declspec(dllexport)

EXPORT void* WINAPI WintunOpenAdapter(LPCWSTR) {
    SetLastError(ERROR_FILE_NOT_FOUND);
    return nullptr;
}

EXPORT void* WINAPI WintunCreateAdapter(LPCWSTR, LPCWSTR, const GUID*) {
    g_opens++;
    return (void*)0x1000;
}

EXPORT void WINAPI WintunCloseAdapter(void*) {}

EXPORT void WINAPI WintunGetAdapterLUID(void*, uint64_t* luid) { *luid = 0; }

EXPORT void* WINAPI WintunStartSession(void*, DWORD) {
    std::lock_guard<std::mutex> g(g_mu);
    if (!g_ev) g_ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_rx.clear();
    g_tx.clear();
    ResetEvent(g_ev);
    return (void*)0x2000;
}

EXPORT void WINAPI WintunEndSession(void*) {}

EXPORT HANDLE WINAPI WintunGetReadWaitEvent(void*) { return g_ev; }

EXPORT uint8_t* WINAPI WintunReceivePacket(void*, DWORD* size) {
    std::lock_guard<std::mutex> g(g_mu);
    if (g_rx.empty()) {
        ResetEvent(g_ev);
        SetLastError(ERROR_NO_MORE_ITEMS);
        return nullptr;
    }
    std::vector<uint8_t>& p = g_rx.front();
    uint8_t* m = (uint8_t*)malloc(p.size());
    memcpy(m, p.data(), p.size());
    *size = (DWORD)p.size();
    g_rx.pop_front();
    return m;
}

EXPORT void WINAPI WintunReleaseReceivePacket(void*, const uint8_t* p) { free((void*)p); }

EXPORT uint8_t* WINAPI WintunAllocateSendPacket(void*, DWORD size) {
    if (size == 0 || size > 0xFFFF) {
        SetLastError(ERROR_INVALID_USER_BUFFER);
        return nullptr;
    }
    uint8_t* m = (uint8_t*)malloc(size + 4);
    memcpy(m, &size, 4);
    return m + 4;
}

EXPORT void WINAPI WintunSendPacket(void*, const uint8_t* p) {
    DWORD size;
    memcpy(&size, p - 4, 4);
    {
        std::lock_guard<std::mutex> g(g_mu);
        g_tx.emplace_back(p, p + size);
    }
    free((void*)(p - 4));
}

EXPORT void WINAPI WintunSetLogger(void*) {}

EXPORT DWORD WINAPI WintunGetRunningDriverVersion(void) { return 0x000E0001; }

// ---- test side
EXPORT void WINAPI FakeInject(const uint8_t* p, DWORD n) {
    std::lock_guard<std::mutex> g(g_mu);
    g_rx.emplace_back(p, p + n);
    SetEvent(g_ev);
}

EXPORT DWORD WINAPI FakePop(uint8_t* out, DWORD cap) {
    std::lock_guard<std::mutex> g(g_mu);
    if (g_tx.empty()) return 0;
    std::vector<uint8_t>& p = g_tx.front();
    DWORD n = (DWORD)p.size();
    if (n > cap) n = cap;
    memcpy(out, p.data(), n);
    g_tx.pop_front();
    return n;
}

EXPORT int WINAPI FakeOpens(void) { return g_opens; }
