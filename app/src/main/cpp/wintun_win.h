// LanBridge native core (Windows only): the virtual network adapter.
//
// The engine reads and writes IP packets on a "TUN fd" with poll()/read()/write(), one packet per call. On Windows
// that fd is one end of a loopback UDP socket pair; the other end is served by two pump threads that move packets
// between the socket and a Wintun session (https://www.wintun.net, an L3 adapter driver signed by WireGuard LLC).
// The engine code is therefore exactly the code that runs on Android.
//
// Addresses and routes of the adapter are set through the IP Helper API (no netsh for them).
#pragma once

#ifndef _WIN32
#error "wintun_win.h is Windows only"
#endif

#include "plat.h"

#include <cstdint>
#include <string>
#include <vector>

namespace lb {
namespace wintun {

// Loads wintun.dll from [dllPath] (full path). Returns "" or the reason.
std::string load(const std::wstring& dllPath);

// Creates the adapter [name] (or takes over an existing one of that name), starts a session and the pumps.
// Returns the engine-side fd (>= 0) or -1 with [err] set. The adapter has no address until configure() is called.
int open(const std::wstring& name, const GUID& guid, std::string& err);

// A fresh socket pair for the same adapter: the pumps move to the new pair, the old pair is closed on the pump
// side. Returns the new engine-side fd or -1. The caller hands it to Engine::swapTun().
int swapPair(std::string& err);

struct IpConfig {
    std::string ip4;       // "10.1.2.3", empty = no IPv4
    int prefix4 = 24;
    std::string ip6;       // "fd00::1", empty = no IPv6
    int prefix6 = 64;
    int mtu = 1500;
    int metric = 1;        // interface metric (low: broadcast and multicast of games prefer this adapter)
    // Real addresses of the other devices. Phones send with their real address as the source (it is the primary
    // address of their tunnel), so the PC needs a host route to each of them through the adapter to answer. Addresses
    // that belong to this PC, its gateways or DNS servers are skipped.
    std::vector<std::string> alias4;
    std::vector<std::string> alias6;
};

// Replaces the manually configured addresses and routes of the adapter with [c]. Returns lines separated by '\n':
// "E:<fatal>", "W:<warning>" or "I:<what was done>"; "" when there is nothing to report.
std::string configure(const IpConfig& c);

// Ends the session, stops the pumps, removes the adapter if this process created it. Safe to call twice.
void close();

// "из адаптера N, в адаптер M, потеряно K"
std::string stats();

bool isElevated();
bool relaunchElevated(const std::wstring& exe, const std::wstring& args);

// Runs a command line without a console window and returns its exit code (or -1) and the text it printed (UTF-8).
int runHidden(const std::wstring& cmdline, int timeoutMs, std::string& output);

// ES_SYSTEM_REQUIRED for as long as [on] (the system does not sleep while the tunnel is up).
void keepAwake(bool on);

std::string toUtf8(const std::wstring& w);
std::wstring fromUtf8(const std::string& s);

}  // namespace wintun
}  // namespace lb
