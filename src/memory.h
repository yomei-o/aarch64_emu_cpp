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
#include <functional>
#include <map>
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

    // The page a *write* is about to land on. Identical to `page()` except that it
    // records the page's previous contents in every open journal, which is what makes
    // `fork` honest -- see begin_journal().
    uint8_t* page_for_write(uint64_t addr) {
        if (!journals_.empty()) {
            const uint64_t vpn = addr >> kPageBits;
            const bool existed = pages_.find(vpn) != pages_.end();
            for (auto& j : journals_) {
                if (j.count(vpn)) continue;          // already saved under this journal
                if (!existed) {
                    j.emplace(vpn, nullptr);         // null = "did not exist; erase it"
                } else {
                    auto copy = std::make_unique<uint8_t[]>(kPageSize);
                    std::memcpy(copy.get(), pages_[vpn].get(), kPageSize);
                    j.emplace(vpn, std::move(copy));
                }
            }
        }
        return page(addr);
    }

    // Undo logs, for `fork`.
    //
    // A forked child has to be unable to affect its parent's memory, and copying the
    // whole address space to guarantee that costs hundreds of megabytes for a guest
    // like CPython. What the parent actually needs is only the pages the child *wrote*,
    // which is a handful: between fork and exec a child sets up descriptors, and even
    // Darwin's `_libSystem_atfork_child()` only touches malloc's and libdispatch's
    // globals. So this records the previous contents of each page on its first write
    // and puts them back afterwards.
    //
    // Nested, because a child may fork again -- `make` runs `gcc` runs `cc1`. A page is
    // saved into *every* open journal rather than only the innermost, so an inner
    // rollback and an inner discard are both correct without the outer one knowing
    // which happened.
    void begin_journal() { journals_.emplace_back(); }
    void rollback_journal() {
        if (journals_.empty()) return;
        for (auto& kv : journals_.back()) {
            if (kv.second) std::memcpy(page(kv.first << kPageBits), kv.second.get(), kPageSize);
            else pages_.erase(kv.first);
        }
        journals_.pop_back();
        cache_ = nullptr;                            // the one-entry lookup cache may
        cache_vpn_ = ~0ull;                          // point at a page just erased
    }
    void discard_journal() { if (!journals_.empty()) journals_.pop_back(); }

    // `--strict`: a guest access to a page nothing ever mapped is a fault, not a zero.
    //
    // The permissive default is still the right default -- a libc that reads
    // speculatively past something should not stop the machine -- but it hides the one
    // class of bug that is hardest to find afterwards. A wild pointer reads zero, the
    // guest computes with it, and the failure surfaces tens of thousands of instructions
    // later somewhere unrelated: the mmap/interpreter address collision took 90,000.
    //
    // Only *guest* loads and stores are checked. The bulk helpers below (`read_bytes`,
    // `write_bytes`, `set`) are how the host maps things in the first place -- the loader
    // writing segments, mmap zeroing, the stack -- so they always allocate, and `map()`
    // exists for the regions the host synthesises out of nothing.
    bool strict = false;
    std::function<void(uint64_t addr, bool is_write)> on_unmapped;
    void map(uint64_t addr, uint64_t len) {
        for (uint64_t a = addr & ~kPageMask; a < addr + len; a += kPageSize) (void)page(a);
    }
    bool is_mapped(uint64_t addr) const {
        return pages_.find(addr >> kPageBits) != pages_.end();
    }

    // Reads and writes never straddle a page here: guest accesses are at most 16
    // bytes and pages are 64 KiB, so only the rare unaligned access near a page
    // edge needs the slow path, which byte-copies.
    // An optional watch on an address range, reported through `on_watch`. Off by
    // default and one predictable branch when off.
    //
    // This exists because of a specific class of question that guessing cannot
    // answer: a guest read a zero from somewhere and computed nonsense from it, and
    // the useful thing to know is *which address* it read. Reasoning about which
    // structure "should" have supplied the value is how an afternoon goes missing.
    uint64_t watch_lo = 0, watch_hi = 0;
    std::function<void(uint64_t addr, unsigned size, uint64_t value, bool is_write)> on_watch;

    template <typename T> T read(uint64_t a) {
        T v;
        if (strict && !is_mapped(a) && on_unmapped) on_unmapped(a, false);
        if (((a & kPageMask) + sizeof(T)) <= kPageSize)
            std::memcpy(&v, page(a) + (a & kPageMask), sizeof(T));
        else
            read_bytes(a, &v, sizeof(T));
        if (watch_hi && a >= watch_lo && a < watch_hi && on_watch) {
            uint64_t as_u64 = 0;
            std::memcpy(&as_u64, &v, sizeof(T) > 8 ? 8 : sizeof(T));
            on_watch(a, sizeof(T), as_u64, false);
        }
        return v;
    }
    template <typename T> void write(uint64_t a, T v) {
        if (strict && !is_mapped(a) && on_unmapped) on_unmapped(a, true);
        if (watch_hi && a >= watch_lo && a < watch_hi && on_watch) {
            uint64_t as_u64 = 0;
            std::memcpy(&as_u64, &v, sizeof(T) > 8 ? 8 : sizeof(T));
            on_watch(a, sizeof(T), as_u64, true);
        }
        if (((a & kPageMask) + sizeof(T)) <= kPageSize) {
            std::memcpy(page_for_write(a) + (a & kPageMask), &v, sizeof(T)); return;
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
            std::memcpy(page_for_write(a) + off, s, k);
            a += k; s += k; n -= k;
        }
    }
    void set(uint64_t a, uint8_t byte, uint64_t n) {
        while (n) {
            const uint64_t off = a & kPageMask;
            const uint64_t k = std::min(n, kPageSize - off);
            std::memset(page_for_write(a) + off, byte, k);
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
    // One undo log per open journal; see begin_journal().
    std::vector<std::map<uint64_t, std::unique_ptr<uint8_t[]>>> journals_;
    uint64_t cache_vpn_ = ~0ull;
    uint8_t* cache_ = nullptr;
};

}  // namespace a64
