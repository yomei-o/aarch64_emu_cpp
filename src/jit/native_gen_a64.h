// What a guest's own emitters are given by the AArch64 native backend: the assembler, the
// state of the block being generated, and the primitives every op uses.  The twin of
// native_gen.h for hosts that are AArch64.
//
// Registers while generated code runs: x19 = the guest register file (env), x20 = the
// translator context, x21 = instructions finished so far, x22 = the budget, x23 / x24 =
// the guest's read / write page cache.  x0-x15 are scratch; x16 and x17 are reserved for
// the assembler and calls.
#pragma once

#include <deque>
#include <functional>

#include "engine.h"
#include "native_a64.h"
#include "native_host.h"

namespace jit {

#ifdef JIT_NATIVE_A64
#define JIT_HAVE_NATIVE_A64 1

namespace ra {   // register roles
constexpr int ENV = 19, CTX = 20, COUNT = 21, LIMIT = 22, TLBR = 23, TLBW = 24;
}

struct NativeGenA {
    a64::Asm& a;
    Engine& eng;
    Block& blk;
    const GuestSlots& s;
    uint64_t start;       // guest address of the block
    int insns;            // the block's instruction count
    const uint8_t* leave; // the shared exit
    std::function<void()> fallback;               // runs the current op through its threaded handler (result in w0)
    std::function<uintptr_t*()> next_cell;        // the next static-exit word
    bool failed = false;
    std::vector<std::function<void()>> stubs;     // out-of-line code, emitted after the block
    std::deque<a64::Label> labels;                // (stable addresses, for the stubs)
    bool inline_tlb = false;

    void ld(int r, int off) { a.ldr64(r, ra::ENV, off); }
    void st(int off, int r) { a.str64(r, ra::ENV, off); }
    void ld_sz(int r, int off, int sz) {          // zero extended
        if (sz == 1) a.ldrb(r, ra::ENV, off);
        else if (sz == 2) a.ldrh(r, ra::ENV, off);
        else if (sz == 4) a.ldr32(r, ra::ENV, off);
        else a.ldr64(r, ra::ENV, off);
    }
    void st_imm(int off, int64_t v) {
        if (v == 0) { st(off, a64::XZR); return; }
        a.mov_imm(0, static_cast<uint64_t>(v));
        st(off, 0);
    }

    // A conditional branch to the far exit (which may be out of reach of a B.cond): branch over
    // an unconditional one on the opposite condition.
    void b_cond_leave(int cc) {
        a64::Label skip;
        a.b_cond(cc ^ 1, skip);
        a.b_abs(leave);
        a.bind(skip);
    }
    void cbnz_leave(bool x, int rt) {
        a64::Label skip;
        a.cbz(x, rt, skip);
        a.b_abs(leave);
        a.bind(skip);
    }
    void check_fault() {
        a.ldr32(16, ra::CTX, static_cast<int32_t>(offsetof(Ctx, nfault)));
        cbnz_leave(false, 16);
    }
    void call(const void* fn) {
        a.mov_imm(16, reinterpret_cast<uintptr_t>(fn));
        a.blr(16);
    }

    // Leave the whole chain here, having finished `ni` more instructions; rip must be set.
    void leave_with(int ni) {
        add_count(ni);
        a.b_abs(leave);
    }
    void add_count(int n) {
        if (n < 4096) a.add_imm(true, ra::COUNT, ra::COUNT, static_cast<uint32_t>(n));
        else { a.mov_imm(16, static_cast<uint64_t>(n)); a.alu(a64::ADD, true, ra::COUNT, ra::COUNT, 16); }
    }
    // rip = target, then on to the block for it if it has run; otherwise back to the engine,
    // which finds (or translates) it and fills in the word for next time.
    void exit_static(uint64_t target, int ni) {
        st_imm(s.rip, static_cast<int64_t>(target));
        add_count(ni);
        a.cmp(true, ra::COUNT, ra::LIMIT);
        b_cond_leave(a64::GE);
        uintptr_t* cell = next_cell();
        a.mov_imm(1, reinterpret_cast<uintptr_t>(cell));
        a.ldr64(1, 1, 0);
        a64::Label miss;
        a.cbz(true, 1, miss);
        a.br(1);
        a.bind(miss);
        a.mov_imm(1, reinterpret_cast<uintptr_t>(cell));
        a.str64(1, ra::CTX, static_cast<int32_t>(offsetof(Ctx, npending)));
        a.b_abs(leave);
    }

    // After a store that asked for it: leave, at the next instruction, if translated code was
    // invalidated.
    void chk_flush(uint64_t next_pc, int ni) {
        labels.emplace_back();
        a64::Label* l = &labels.back();
        a.mov_imm(0, reinterpret_cast<uintptr_t>(&eng.epoch));
        a.ldr64(0, 0, 0);
        a.ldr64(1, ra::CTX, static_cast<int32_t>(offsetof(Ctx, epoch0)));
        a.cmp(true, 0, 1);
        a.b_cond(a64::NE, *l);
        stubs.push_back([this, l, next_pc, ni] {
            a.bind(*l);
            st_imm(s.rip, static_cast<int64_t>(next_pc));
            leave_with(ni);
        });
    }

    // Reads `size` bytes at the guest address in x0, zero extended, into x0.  Probes the page
    // cache inline; a miss (or an access across a page boundary) calls C++.
    void mem_read(int size, uint64_t rip);
    // Writes the low `size` bytes of x4 to the guest address in x0.
    void mem_write(int size, uint64_t rip);
};

// Guest hooks.  The first generates native code for `o` and returns true, or returns false
// to have the op run through its threaded handler.  The second says how many static exits
// the op makes.
bool guest_native_emit(NativeGenA& g, const Op& o);
int guest_native_cells(const Op& o);

#endif  // JIT_NATIVE_A64

}  // namespace jit
