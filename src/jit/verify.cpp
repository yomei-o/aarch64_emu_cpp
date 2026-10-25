// JIT_VERIFY=1: run every block twice, translated and then interpreted from the
// same starting state, and stop at the first difference.
//
// This is how the translator is checked against the interpreter on code nobody
// wrote a test for.  What it compares is what the rest of the emulator can see
// when a block ends: the registers, the program counter, the flags (a block must
// leave them exact at its end even though it skips writes nobody reads inside
// it), whatever else the guest keeps (Glue::diff), and every page either run wrote.
//
// Blocks containing an instruction with outside effects - a system call, an
// interrupt - are run once and not compared: doing them twice would be visible.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "engine.h"

namespace jit {

using Cpu = GCpu;
using Memory = GMemory;

bool Engine::run_verified(Block* b) {
    if (b->effects) return run_plain(b);
    GuestState s0, s1, s2;
    Glue::take(cpu, s0);

    mem.journal_begin();
    try {
        run_plain(b);
    } catch (...) {
        mem.journal_end();
        throw;
    }
    mem.journal_end();
    Glue::take(cpu, s1);
    const uint64_t n = s1.icount - s0.icount;

    // What the translated run left in every page it wrote; then put it all back.
    auto old1 = std::move(mem.journal());
    std::unordered_map<uint64_t, std::vector<uint8_t>> after;
    for (auto& kv : old1) {
        uint8_t* p = mem.page_ptr(kv.first);
        after[kv.first].assign(p, p + Memory::kPageSize);
        std::memcpy(p, kv.second->data(), Memory::kPageSize);
    }
    Glue::put(cpu, s0);

    mem.journal_begin();
    try {
        for (uint64_t i = 0; i < n; ++i) Glue::step(cpu);
    } catch (...) {
        mem.journal_end();
        throw;
    }
    mem.journal_end();
    Glue::take(cpu, s2);

    std::string diff = Glue::diff(s1, s2);
    char buf[256];

    auto cmp_page = [&](uint64_t page, const uint8_t* jit_img) {
        const uint8_t* cur = mem.page_ptr(page);
        if (std::memcmp(jit_img, cur, Memory::kPageSize) == 0) return;
        for (uint64_t k = 0; k < Memory::kPageSize; ++k) {
            if (jit_img[k] != cur[k]) {
                std::snprintf(buf, sizeof buf, "  memory %016llX: jit %02X  interp %02X\n",
                              (unsigned long long)((page << Memory::kPageBits) + k), jit_img[k],
                              cur[k]);
                diff += buf;
                break;
            }
        }
    };
    for (auto& kv : after) cmp_page(kv.first, kv.second.data());
    for (auto& kv : mem.journal())
        if (!after.count(kv.first)) cmp_page(kv.first, kv.second->data());

    if (!diff.empty()) {
        std::string bytes;
        for (uint32_t i = 0; i < b->guest_bytes && i < 96; ++i) {
            std::snprintf(buf, sizeof buf, "%02X ", Glue::rd8(mem, b->start + i));
            bytes += buf;
        }
        std::fprintf(stderr, "jit verify: block at %016llX (%u native insns) differs\n%s  bytes: %s\n",
                     (unsigned long long)b->start, b->insns, diff.c_str(), bytes.c_str());
        std::abort();
    }
    return true;
}

}  // namespace jit
