// LanBridge native core: reassembly of inner IP packets that the tunnel cut into chunks (see K_FRAG in protocol.h).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace lb {

class FragReassembler {
public:
    static constexpr size_t kMaxPackets = 16;       // incomplete packets kept at the same time
    static constexpr uint64_t kTimeoutMs = 3000;    // an incomplete packet is dropped after this long

    // Feeds one chunk. Returns true and fills `out` when the chunk completed a packet.
    // Invalid chunks are ignored: count must be 2..FRAG_MAX, index < count, every chunk except the last must be
    // exactly FRAG_CHUNK bytes long, the last one 1..FRAG_CHUNK bytes. A repeated chunk is ignored; a chunk that
    // contradicts the chunk count of an incomplete packet with the same id restarts that packet.
    bool add(uint16_t id, uint8_t index, uint8_t count, const uint8_t* data, size_t len, uint64_t nowMs,
             std::vector<uint8_t>& out);
    void expire(uint64_t nowMs);
    void clear();
    size_t pending() const { return v_.size(); }
    uint64_t expiredTotal() const { return expired_; }

private:
    struct Entry {
        uint16_t id = 0;
        uint8_t count = 0;
        uint8_t have = 0;
        uint32_t mask = 0;
        size_t lastLen = 0;
        uint64_t firstMs = 0;
        std::vector<uint8_t> buf;
    };
    std::vector<Entry> v_;
    uint64_t expired_ = 0;
};

}  // namespace lb
