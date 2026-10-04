// LanBridge native core: small utilities (time, random, byte order, logging).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lb {

uint64_t nowMs();   // monotonic clock, milliseconds
uint64_t wallMs();  // wall clock, milliseconds since the Unix epoch
void randomBytes(void* p, size_t n);

inline uint16_t be16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
inline uint32_t be32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
inline uint64_t be64(const uint8_t* p) { return ((uint64_t)be32(p) << 32) | (uint64_t)be32(p + 4); }
inline void putBe16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
inline void putBe32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
inline void putBe64(uint8_t* p, uint64_t v) {
    putBe32(p, (uint32_t)(v >> 32));
    putBe32(p + 4, (uint32_t)v);
}
inline uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t le64(const uint8_t* p) { return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32); }
inline void putLe32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}
inline void putLe64(uint8_t* p, uint64_t v) {
    putLe32(p, (uint32_t)v);
    putLe32(p + 4, (uint32_t)(v >> 32));
}

std::string ipStr(uint32_t ipHostOrder);
bool parseIp(const std::string& s, uint32_t& ipHostOrder);
std::string hexStr(const uint8_t* p, size_t n);
std::string sanitize(const std::string& s, size_t maxLen);
std::string strfmt(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
std::vector<std::string> splitList(const std::string& s);  // split on newline , ; space tab
bool isPrivateIp(uint32_t ipHostOrder);                    // RFC1918, loopback, link-local

void logWrite(const std::string& msg);
std::string logDump();
void logClear();

}  // namespace lb

#define LBLOG(...) ::lb::logWrite(::lb::strfmt(__VA_ARGS__))
