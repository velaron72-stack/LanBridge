// LanBridge native core: minimal STUN (RFC 5389) Binding client, IPv4 only.
#pragma once

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lb {

struct StunAddr {
    uint32_t ip = 0;  // host byte order
    uint16_t port = 0;
};

struct StunServer {
    std::string name;
    sockaddr_in addr;
    bool ok = false;
    StunAddr mapped;
    uint8_t txid[12];
    StunServer() {
        addr = sockaddr_in();
        for (int i = 0; i < 12; i++) txid[i] = 0;
    }
};

bool stunResolve(const std::string& hostPort, sockaddr_in& out);  // "host:port", default port 3478
void stunBuildRequest(uint8_t out[20], const uint8_t txid[12]);
bool stunIsMessage(const uint8_t* p, size_t n);
bool stunGetTxid(const uint8_t* p, size_t n, uint8_t txid[12]);
bool stunParseResponse(const uint8_t* p, size_t n, const uint8_t txid[12], StunAddr& out);

// Resolves all names in parallel; resolvers that miss the deadline are abandoned.
std::vector<StunServer> stunResolveAll(const std::vector<std::string>& names, int timeoutMs);

// Sends Binding Requests from `sock` (non-blocking UDP) and collects answers for up to timeoutMs.
// The caller must be the only reader of `sock`. Returns the number of servers that answered.
int stunGather(int sock, std::vector<StunServer>& servers, int timeoutMs);

}  // namespace lb
