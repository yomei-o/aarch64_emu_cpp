// Guest physical memory for a 64-bit address space.
//
// x86_emu_cpp could get away with one flat array because a 32-bit guest fits in
// 4 GiB. An AArch64 Linux process cannot: the image sits near 0x400000, the brk
// heap grows above it, mmap comes down from 0x7f_0000_0000, and the stack lives
// just under 0x8000_0000_0000. Those are terabytes apart and almost all of it is
// never touched, so memory is paged: 64 KiB pages allocated on first use, held in
// a hash map, with a one-entry cache in front because guest accesses are
// overwhelmingly to the page they just used.
//
// Unmapped reads return zero and unmapped writes allocate, which is deliberately
// permissive. A real kernel would fault; we would rather run the program and have
// `--strict` (later) turn silent growth into an error, than refuse to boot over an
// access some libc makes speculatively.
#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace a64 {

class Memory {
public:
    static constexpr uint64_t kPageBits = 16;
    static constexpr uint64_t kPageSize = 1ull << kPageBits;
    static constexpr uint64_t kPageMask = kPageSize - 1;

    uint8_t* page(uint64_t addr) {
        const uint64_t vpn = addr >> kPageBits;
        if (vpn == cache_vpn_ && cache_) return cache_;
        auto it = pages_.find(vpn);
        if (it == pages_.end()) {
            auto p = std::make_unique<uint8_t[]>(kPageSize);
            std::memset(p.get(), 0, kPageSize);
            it = pages_.emplace(vpn, std::move(p)).first;
        }
        cache_vpn_ = vpn; cache_ = it->second.get();
        return cache_;
    }

    // Reads and writes never straddle a page here: guest accesses are at most 16
    // bytes and pages are 64 KiB, so only the rare unaligned access near a page
    // edge needs the slow path, which byte-copies.
    template <typename T> T read(uint64_t a) {
        if (((a & kPageMask) + sizeof(T)) <= kPageSize) {
            T v; std::memcpy(&v, page(a) + (a & kPageMask), sizeof(T)); return v;
        }
        T v; read_bytes(a, &v, sizeof(T)); return v;
    }
    template <typename T> void write(uint64_t a, T v) {
        if (((a & kPageMask) + sizeof(T)) <= kPageSize) {
            std::memcpy(page(a) + (a & kPageMask), &v, sizeof(T)); return;
        }
        write_bytes(a, &v, sizeof(T));
    }

    void read_bytes(uint64_t a, void* dst, uint64_t n) {
        auto* d = static_cast<uint8_t*>(dst);
        while (n) {
            const uint64_t off = a & kPageMask;
            const uint64_t k = std::min(n, kPageSize - off);
            std::memcpy(d, page(a) + off, k);
            a += k; d += k; n -= k;
        }
    }
    void write_bytes(uint64_t a, const void* src, uint64_t n) {
        const auto* s = static_cast<const uint8_t*>(src);
        while (n) {
            const uint64_t off = a & kPageMask;
            const uint64_t k = std::min(n, kPageSize - off);
            std::memcpy(page(a) + off, s, k);
            a += k; s += k; n -= k;
        }
    }
    void set(uint64_t a, uint8_t byte, uint64_t n) {
        while (n) {
            const uint64_t off = a & kPageMask;
            const uint64_t k = std::min(n, kPageSize - off);
            std::memset(page(a) + off, byte, k);
            a += k; n -= k;
        }
    }

    std::string read_cstr(uint64_t a, uint64_t limit = 4096) {
        std::string s;
        for (uint64_t i = 0; i < limit; ++i) {
            const char c = static_cast<char>(read<uint8_t>(a + i));
            if (!c) break;
            s += c;
        }
        return s;
    }

    uint64_t mapped_pages() const { return pages_.size(); }

private:
    std::unordered_map<uint64_t, std::unique_ptr<uint8_t[]>> pages_;
    uint64_t cache_vpn_ = ~0ull;
    uint8_t* cache_ = nullptr;
};

}  // namespace a64
