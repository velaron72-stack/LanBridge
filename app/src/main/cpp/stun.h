// LanBridge native core: minimal STUN (RFC 5389) Binding client over IPv4 and IPv6.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "addr.h"
#include "udpio.h"

namespace lb {

struct StunServer {
    std::string name;
    Addr addr;
    bool ok = false;
    Addr mapped;  // the address the server saw (the family of the server)
    uint8_t txid[12];
    StunServer() {
        for (int i = 0; i < 12; i++) txid[i] = 0;
    }
};

// "host:port", "[v6literal]:port", a bare IPv4/IPv6 literal or a host name (default port 3478). A name can give one
// IPv4 and one IPv6 address; they are appended to `out`. False when nothing could be resolved.
bool stunResolve(const std::string& hostPort, std::vector<Addr>& out);
void stunBuildRequest(uint8_t out[20], const uint8_t txid[12]);
bool stunIsMessage(const uint8_t* p, size_t n);
bool stunGetTxid(const uint8_t* p, size_t n, uint8_t txid[12]);
// Reads XOR-MAPPED-ADDRESS (or MAPPED-ADDRESS) of family IPv4 or IPv6.
bool stunParseResponse(const uint8_t* p, size_t n, const uint8_t txid[12], Addr& out);

// Resolves all names in parallel; resolvers that miss the deadline are abandoned. One entry per distinct address.
std::vector<StunServer> stunResolveAll(const std::vector<std::string>& names, int timeoutMs);

// Sends Binding Requests from the socket of each server's family and collects answers for up to timeoutMs. Either
// socket may be null (its servers are skipped); a server whose address is unreachable is given up after two failed
// sends. The caller must be the only reader of the sockets. Returns the number of servers that answered.
int stunGather(UdpSocket* s4, UdpSocket* s6, std::vector<StunServer>& servers, int timeoutMs);

}  // namespace lb
