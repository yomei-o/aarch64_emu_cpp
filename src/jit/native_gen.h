// What a guest's own emitters are given by the native backend: the assembler, the
// state of the block being generated, and the primitives every op uses (slot access,
// exits, calling the op's threaded handler).
//
// Registers while generated code runs: rbx = the guest register file (env), r12 = the
// translator context, r13 = instructions finished so far, r14 = the budget.  rax, rcx
// and rdx (and r8-r11) are scratch.
#pragma once

#include <deque>
#include <functional>

#include "engine.h"
#include "native_host.h"
#include "native_x64.h"

namespace jit {

#ifdef JIT_NATIVE_X64
#define JIT_HAVE_NATIVE 1
#endif

#ifdef JIT_HAVE_NATIVE

struct NativeGen {
    x64::Asm& a;
    Engine& eng;
    Block& blk;
    const GuestSlots& s;
    uint64_t start;       // guest address of the block
    int insns;            // the block's instruction count
    const uint8_t* leave; // the shared exit
    std::function<void()> fallback;               // runs the current op through its threaded handler
    std::function<uintptr_t*()> next_cell;        // the next static-exit word
    bool failed = false;                          // something could not be generated: use the threaded block
    std::vector<std::function<void()>> stubs;     // out-of-line code, emitted after the block
    std::deque<x64::Label> labels;                // (stable addresses, for the stubs)
    bool inline_tlb = false;                      // the guest has a page cache the code can probe (r15 / rbp hold it)


    // Reads `size` bytes at the guest address in rax, zero extended, into rax.  Probes the
    // page cache inline; a miss (or an access across a page boundary) calls C++.
    void mem_read(int size, uint64_t rip);
    // Writes the low `size` bytes of r9 to the guest address in rax.
    void mem_write(int size, uint64_t rip);

    // After a store that asked for it: leave, at the next instruction, if translated code was
    // invalidated.
    void chk_flush(uint64_t next_pc, int ni) {
        labels.emplace_back();
        x64::Label* l = &labels.back();
        a.movi(x64::RAX, static_cast<int64_t>(reinterpret_cast<uintptr_t>(&eng.epoch)));
        a.load64(x64::RAX, x64::RAX, 0);
        a.alu_rm(x64::CMP, true, x64::RAX, x64::R12, static_cast<int32_t>(offsetof(Ctx, epoch0)));
        a.jcc(x64::NE, *l);
        stubs.push_back([this, l, next_pc, ni] {
            a.bind(*l);
            st_imm(s.rip, static_cast<int64_t>(next_pc));
            leave_with(ni);
        });
    }

    // slots
    void ld(int r, int off) { a.load64(r, x64::RBX, off); }
    void st(int off, int r) { a.store64(x64::RBX, off, r); }
    void ld_sz(int r, int off, int sz) {          // zero extended
        if (sz == 1) a.load8u(r, x64::RBX, off);
        else if (sz == 2) a.load16u(r, x64::RBX, off);
        else if (sz == 4) a.load32(r, x64::RBX, off);
        else a.load64(r, x64::RBX, off);
    }
    void movi(int r, int64_t v) { a.movi(r, v); }
    void st_imm(int off, int64_t v) {
        if (v >= INT32_MIN && v <= INT32_MAX) a.store64_imm(x64::RBX, off, static_cast<int32_t>(v));
        else { a.movi(x64::RAX, v); st(off, x64::RAX); }
    }

    // Leave if a helper called from the code caught an exception.
    void check_fault() {
        a.cmp_m32_imm(x64::R12, static_cast<int32_t>(offsetof(Ctx, nfault)), 0);
        a.jcc_abs(x64::NE, leave);
    }

    // Leave the whole chain here, having finished `ni` more instructions; rip must be set.
    void leave_with(int ni) {
        a.alu_ri(x64::ADD, true, x64::R13, ni);
        a.jmp_abs(leave);
    }
    // rip = target, then on to the block for it if it has run; otherwise back to the engine,
    // which finds (or translates) it and fills in `cell` for next time.
    void exit_static(uint64_t target, int ni) {
        st_imm(s.rip, static_cast<int64_t>(target));
        a.alu_ri(x64::ADD, true, x64::R13, ni);
        a.alu_rr(x64::CMP, true, x64::R13, x64::R14);
        a.jcc_abs(x64::GE, leave);
        uintptr_t* cell = next_cell();
        a.movi(x64::RAX, static_cast<int64_t>(reinterpret_cast<uintptr_t>(cell)));
        a.load64(x64::RAX, x64::RAX, 0);
        a.test_rr(true, x64::RAX, x64::RAX);
        x64::Label miss;
        a.jcc(x64::E, miss);
        a.jmp_r(x64::RAX);
        a.bind(miss);
        a.movi(x64::RAX, static_cast<int64_t>(reinterpret_cast<uintptr_t>(cell)));
        a.store64(x64::R12, static_cast<int32_t>(offsetof(Ctx, npending)), x64::RAX);
        a.jmp_abs(leave);
    }
};

// Guest hooks.  The first generates native code for `o` and returns true, or returns
// false to have the op run through its threaded handler.  The second says how many static
// exits (words to jump through) the op makes.
bool guest_native_emit(NativeGen& g, const Op& o);
int guest_native_cells(const Op& o);

#endif  // JIT_HAVE_NATIVE

}  // namespace jit
