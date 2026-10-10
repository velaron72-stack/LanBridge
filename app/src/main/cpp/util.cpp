#include "util.h"

#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <random>

#ifdef __ANDROID__
#include <android/log.h>
#endif

namespace lb {

uint64_t nowMs() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

uint64_t wallMs() {
    timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

void randomBytes(void* p, size_t n) {
    static std::mutex m;
    static int fd = -2;
    std::lock_guard<std::mutex> g(m);
    if (fd == -2) fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    uint8_t* out = (uint8_t*)p;
    size_t done = 0;
    if (fd >= 0) {
        while (done < n) {
            ssize_t r = read(fd, out + done, n - done);
            if (r <= 0) break;
            done += (size_t)r;
        }
    }
    if (done < n) {  // last resort, should never happen
        std::random_device rd;
        while (done < n) out[done++] = (uint8_t)rd();
    }
}

std::string ipStr(uint32_t ip) {
    char b[24];
    snprintf(b, sizeof b, "%u.%u.%u.%u", (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return b;
}

bool parseIp(const std::string& s, uint32_t& ip) {
    unsigned a, b, c, d;
    char tail;
    if (sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    ip = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

std::string hexStr(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s.push_back(H[p[i] >> 4]);
        s.push_back(H[p[i] & 15]);
    }
    return s;
}

std::string sanitize(const std::string& s, size_t maxLen) {
    std::string o;
    for (unsigned char c : s) {
        if (o.size() >= maxLen) break;
        o.push_back((c < 0x20 || c == 0x7f) ? '?' : (char)c);
    }
    return o;
}

std::string strfmt(const char* fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return std::string();
    if ((size_t)n < sizeof buf) return std::string(buf, (size_t)n);
    std::string big((size_t)n + 1, '\0');
    va_start(ap, fmt);
    vsnprintf(&big[0], big.size(), fmt, ap);
    va_end(ap);
    big.resize((size_t)n);
    return big;
}

std::vector<std::string> splitList(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '\n' || c == '\r' || c == ',' || c == ';' || c == ' ' || c == '\t') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

bool isPrivateIp(uint32_t ip) {
    uint32_t a = ip >> 24, b = (ip >> 16) & 255;
    if (a == 10 || a == 127) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 169 && b == 254) return true;
    return false;
}

// ---- log ring buffer ----
static std::mutex g_logMu;
static std::deque<std::string> g_log;
static const size_t kLogMax = 600;

void logWrite(const std::string& msg) {
    uint64_t w = wallMs();
    time_t secs = (time_t)(w / 1000);
    tm t;
    localtime_r(&secs, &t);
    char head[32];
    snprintf(head, sizeof head, "%02d:%02d:%02d.%03d ", t.tm_hour, t.tm_min, t.tm_sec, (int)(w % 1000));
    std::string line = std::string(head) + msg;
    {
        std::lock_guard<std::mutex> g(g_logMu);
        g_log.push_back(line);
        while (g_log.size() > kLogMax) g_log.pop_front();
    }
#ifdef __ANDROID__
    __android_log_write(ANDROID_LOG_INFO, "LanBridge", msg.c_str());
#endif
}

std::string logDump() {
    std::lock_guard<std::mutex> g(g_logMu);
    std::string out;
    for (const auto& l : g_log) {
        out += l;
        out.push_back('\n');
    }
    return out;
}

void logClear() {
    std::lock_guard<std::mutex> g(g_logMu);
    g_log.clear();
}

}  // namespace lb
