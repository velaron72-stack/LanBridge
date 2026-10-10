#include "frag.h"

#include <cstring>

#include "protocol.h"

namespace lb {

bool FragReassembler::add(uint16_t id, uint8_t index, uint8_t count, const uint8_t* data, size_t len, uint64_t nowMs,
                          std::vector<uint8_t>& out) {
    if (count < 2 || count > FRAG_MAX || index >= count) return false;
    bool last = index == count - 1;
    if (last ? (len == 0 || len > FRAG_CHUNK) : len != FRAG_CHUNK) return false;

    Entry* e = nullptr;
    for (Entry& x : v_) {
        if (x.id == id) {
            e = &x;
            break;
        }
    }
    if (e && e->count != count) {  // the sender reused the id for a different packet
        v_.erase(v_.begin() + (e - v_.data()));
        e = nullptr;
    }
    if (!e) {
        if (v_.size() >= kMaxPackets) {  // evict the oldest incomplete packet
            size_t victim = 0;
            for (size_t i = 1; i < v_.size(); i++)
                if (v_[i].firstMs < v_[victim].firstMs) victim = i;
            v_.erase(v_.begin() + (long)victim);
            expired_++;
        }
        v_.emplace_back();
        e = &v_.back();
        e->id = id;
        e->count = count;
        e->firstMs = nowMs;
        e->buf.assign((size_t)count * FRAG_CHUNK, 0);
    }
    if (e->mask & (1u << index)) return false;  // duplicate
    memcpy(e->buf.data() + (size_t)index * FRAG_CHUNK, data, len);
    e->mask |= 1u << index;
    e->have++;
    if (last) e->lastLen = len;
    if (e->have < e->count) return false;

    size_t total = (size_t)(e->count - 1) * FRAG_CHUNK + e->lastLen;
    out.assign(e->buf.begin(), e->buf.begin() + (long)total);
    v_.erase(v_.begin() + (e - v_.data()));
    return true;
}

void FragReassembler::expire(uint64_t nowMs) {
    for (size_t i = 0; i < v_.size();) {
        if (nowMs - v_[i].firstMs >= kTimeoutMs) {
            v_.erase(v_.begin() + (long)i);
            expired_++;
        } else {
            i++;
        }
    }
}

void FragReassembler::clear() {
    v_.clear();
    expired_ = 0;
}

}  // namespace lb
