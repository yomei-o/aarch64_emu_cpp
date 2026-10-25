// The WebAssembly assembler and the code generator's primitives, shared by the
// generic part of the wasm backend and by each guest's own op emitters.
//
// Every generated function has the same shape: parameters (env, ctx) - the guest
// register file and the translator's context - and a fixed set of locals; guest
// registers are 64-bit cells at byte offsets from `env`.  A block returns an i64:
// instructions finished in the low half, the next block's table index in the high.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <vector>

#include "engine.h"

namespace jit {

struct Buf {
    std::vector<uint8_t> b;
    void u8(uint8_t v) { b.push_back(v); }
    void uleb(uint64_t v) {
        do {
            uint8_t x = v & 0x7F;
            v >>= 7;
            if (v) x |= 0x80;
            b.push_back(x);
        } while (v);
    }
    void sleb(int64_t v) {
        bool more = true;
        while (more) {
            uint8_t x = v & 0x7F;
            v >>= 7;
            if ((v == 0 && !(x & 0x40)) || (v == -1 && (x & 0x40))) more = false;
            else x |= 0x80;
            b.push_back(x);
        }
    }
    void bytes(const void* p, size_t n) {
        const uint8_t* s = static_cast<const uint8_t*>(p);
        b.insert(b.end(), s, s + n);
    }
    void name(const char* s) {
        size_t n = std::strlen(s);
        uleb(n);
        bytes(s, n);
    }
    void append(const Buf& o) { b.insert(b.end(), o.b.begin(), o.b.end()); }
};

// Local variable numbers in every generated function.
enum : int { L_ENV = 0, L_CTX = 1, L_E = 2, L_O = 3, L_T = 4, L_A = 5, L_PG = 6, L_V = 7, L_X = 8, L_Y = 9 };

// Function types: 0 = (i32, i32) -> i32 (a block, and jit_generic), 1 = the slow
// read, 2 = the slow write.
enum : int { T_BLOCK = 0, T_READ = 1, T_WRITE = 2, T_EXTRA = 3, T_GENERIC = 4, T_CHAIN = 5 };

// Everything the generator needs to know about the process it generates for.
struct Env {
    uint32_t tlb_read, tlb_write;     // addresses of the page caches
    uint32_t mem_ptr;                 // the Memory object
    uint32_t epoch_addr;              // &Engine::epoch
    uint32_t read_fn, write_fn, generic_fn;   // table indices of the helpers above
    uint32_t extra_base;                      // index of the first function the guest adds (see guest_wasm_extras)
    GuestSlots slots;
};

struct Gen {
    Buf& w;               // the function body being written
    const Env& e;
    uint64_t start = 0;   // guest address of the block being generated
    Gen(const Env& env, Buf& buf) : w(buf), e(env) {}
    // Another view of the same function body: a guest's emitter derives its own
    // generator from this to add helpers for its ISA.
    explicit Gen(Gen& o) : w(o.w), e(o.e), start(o.start) {}

    void op(uint8_t o) { w.u8(o); }
    void get(int l) { w.u8(0x20); w.uleb(l); }
    void set(int l) { w.u8(0x21); w.uleb(l); }
    void tee(int l) { w.u8(0x22); w.uleb(l); }
    void i32c(int32_t v) { w.u8(0x41); w.sleb(v); }
    void i64c(int64_t v) { w.u8(0x42); w.sleb(v); }
    void ld64(uint32_t off) { w.u8(0x29); w.uleb(3); w.uleb(off); }
    void st64(uint32_t off) { w.u8(0x37); w.uleb(3); w.uleb(off); }
    void ld32(uint32_t off) { w.u8(0x28); w.uleb(2); w.uleb(off); }
    void st32(uint32_t off) { w.u8(0x36); w.uleb(2); w.uleb(off); }
    void call_indirect(int type) { w.u8(0x11); w.uleb(type); w.uleb(0); }

    // i64 / i32 arithmetic opcodes used below
    static constexpr uint8_t I64_EQZ = 0x50, I64_EQ = 0x51, I64_NE = 0x52, I64_LT_S = 0x53, I64_LT_U = 0x54,
                             I64_GT_S = 0x55, I64_GT_U = 0x56, I64_LE_S = 0x57, I64_LE_U = 0x58,
                             I64_GE_S = 0x59, I64_GE_U = 0x5A, I64_POPCNT = 0x7B, I64_ADD = 0x7C,
                             I64_SUB = 0x7D, I64_MUL = 0x7E, I64_AND = 0x83, I64_OR = 0x84, I64_XOR = 0x85,
                             I64_SHL = 0x86, I64_SHR_S = 0x87, I64_SHR_U = 0x88, I32_WRAP = 0xA7,
                             I64_EXT_U = 0xAD, I64_EXT8 = 0xC2, I64_EXT16 = 0xC3, I64_EXT32 = 0xC4;
    static constexpr uint8_t I32_EQZ = 0x45, I32_EQ = 0x46, I32_NE = 0x47, I32_LT_S = 0x48, I32_LE_U = 0x4D,
                             I32_ADD = 0x6A, I32_AND = 0x71, I32_OR = 0x72, I32_XOR = 0x73, I32_SHL = 0x74,
                             I32_SHR_U = 0x76;

    void slot_get(int off) { get(L_ENV); ld64(static_cast<uint32_t>(off)); }

    // Leaves slot `off` masked to `sz` bytes on the stack.
    void slot_masked(int off, int sz) {
        slot_get(off);
        mask(sz);
    }
    void mask(int sz) {
        if (sz >= 8) return;
        i64c(sz == 1 ? 0xFF : sz == 2 ? 0xFFFF : 0xFFFFFFFFll);
        op(I64_AND);
    }
    void imm_masked(int64_t v, int sz) {
        if (sz == 1) v &= 0xFF;
        else if (sz == 2) v &= 0xFFFF;
        else if (sz == 4) v &= 0xFFFFFFFFll;
        i64c(v);
    }

    // A block returns an i64: the count of native instructions it finished in the
    // low half, and in the high half the table index of the block to run next, if
    // it knows one (0: go back to C++, which will look rip up).
    void ret(int n) { i64c(n); op(0x0F); }

    // Leave through a static exit: `cell` is the address of a word that holds the
    // function index of the target block once there is one.  When there is not,
    // the address is left in the context so that C++ can fill it in after it
    // has run the target.  (Leaves nothing on the stack: it returns.)
    void leave_static(uint32_t cell, int insns) {
        i32c(static_cast<int32_t>(cell)); ld32(0); tee(L_O);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        get(L_CTX); i32c(static_cast<int32_t>(cell)); st32(offsetof(Ctx, pending_cell));
        w.u8(0x0B);
        get(L_O); op(I64_EXT_U); i64c(32); op(I64_SHL); i64c(insns); op(I64_OR);
        op(0x0F);
    }

    // rip = (cond on the stack, an i32) ? taken : fall; then leave by the matching cell.
    void jump_cond(int64_t taken, int64_t fall, int insns, uint32_t cell_taken, uint32_t cell_fall) {
        // stack: cond(i32).  select wants (val1, val2, cond): park the condition.
        set(L_T);
        get(L_ENV);
        i64c(taken);
        i64c(fall);
        get(L_T);
        op(0x1B);   // select
        st64(static_cast<uint32_t>(e.slots.rip));
        // the cell for the side taken
        i32c(static_cast<int32_t>(cell_taken));
        i32c(static_cast<int32_t>(cell_fall));
        get(L_T);
        op(0x1B);
        set(L_E);
        get(L_E); ld32(0); tee(L_O);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        get(L_CTX); get(L_E); st32(offsetof(Ctx, pending_cell));
        w.u8(0x0B);
        get(L_O); op(I64_EXT_U); i64c(32); op(I64_SHL); i64c(insns); op(I64_OR);
        op(0x0F);
    }


    // Probe the page cache for the address in L_A.  On a hit the host address of
    // the byte is left in L_E + L_O (E = entry, O = offset in the page) and the
    // code in `hit` runs; on a miss, `miss` does.  Both leave the same stack.
    template <typename Hit, typename Miss>
    void probe(uint32_t tlb, int size, int result_type, Hit hit, Miss miss) {
        if (!tlb) {   // the guest has no page cache we can probe: always ask C++
            miss();
            return;
        }
        get(L_A); i64c(kTlbPageBits); op(I64_SHR_U); set(L_PG);
        get(L_PG); op(I32_WRAP); i32c((1 << kTlbBits) - 1); op(I32_AND); i32c(4); op(I32_SHL);
        i32c(static_cast<int32_t>(tlb)); op(I32_ADD); set(L_E);
        get(L_E); ld64(0); get(L_PG); op(I64_EQ);
        get(L_A); op(I32_WRAP); i32c((1 << kTlbPageBits) - 1); op(I32_AND); tee(L_O); i32c(size); op(I32_ADD);
        i32c(1 << kTlbPageBits); op(I32_LE_U);
        op(I32_AND);
        w.u8(0x04); w.u8(static_cast<uint8_t>(result_type));   // if
        hit();
        w.u8(0x05);                                            // else
        miss();
        w.u8(0x0B);                                            // end
    }

    // Value of the guest memory read at L_A, zero extended, left on the stack.
    void emit_read(int size, int pc) {
        probe(e.tlb_read, size, 0x7E,
              [&] {
                  get(L_E); ld32(8); get(L_O); op(I32_ADD);
                  switch (size) {
                      case 1: w.u8(0x31); w.uleb(0); break;
                      case 2: w.u8(0x33); w.uleb(1); break;
                      case 4: w.u8(0x35); w.uleb(2); break;
                      default: w.u8(0x29); w.uleb(3); break;
                  }
                  w.uleb(0);
              },
              [&] {
                  get(L_CTX); i64c(static_cast<int64_t>(start + pc)); w.u8(0x37); w.uleb(3); w.uleb(offsetof(Ctx, fault_rip));
                  i32c(static_cast<int32_t>(e.mem_ptr)); get(L_A); i32c(size);
                  i32c(static_cast<int32_t>(e.read_fn)); call_indirect(T_READ);
              });
    }

    // Store L_V (low `size` bytes) at the guest address L_A.
    void emit_write(int size, int pc) {
        probe(e.tlb_write, size, 0x40,
              [&] {
                  get(L_E); ld32(8); get(L_O); op(I32_ADD); get(L_V);
                  switch (size) {
                      case 1: w.u8(0x3C); w.uleb(0); break;
                      case 2: w.u8(0x3D); w.uleb(1); break;
                      case 4: w.u8(0x3E); w.uleb(2); break;
                      default: w.u8(0x37); w.uleb(3); break;
                  }
                  w.uleb(0);
              },
              [&] {
                  get(L_CTX); i64c(static_cast<int64_t>(start + pc)); w.u8(0x37); w.uleb(3); w.uleb(offsetof(Ctx, fault_rip));
                  i32c(static_cast<int32_t>(e.mem_ptr)); get(L_A); i32c(size); get(L_V);
                  i32c(static_cast<int32_t>(e.write_fn)); call_indirect(T_WRITE);
              });
    }

    // Leave the block, at rip = next, if this store invalidated translated code.
    void chk_flush(const Op& o) {
        if (!(o.flags & kFlagChk)) return;
        i32c(static_cast<int32_t>(e.epoch_addr)); ld64(0);
        get(L_CTX); ld64(offsetof(Ctx, epoch0));
        op(I64_NE);
        w.u8(0x04); w.u8(0x40);
        get(L_ENV); i64c(o.imm2); st64(static_cast<uint32_t>(e.slots.rip));
        ret(o.ni);
        w.u8(0x0B);
    }

    // address = a + (c << cc) + imm, masked for 32-bit addressing, into L_A
    void address(const Op& o) {
        slot_get(o.a);
        slot_get(o.c); i64c(o.cc); op(I64_SHL); op(I64_ADD);
        if (o.imm) { i64c(o.imm); op(I64_ADD); }
        if (o.flags & kFlagA32) { i64c(0xFFFFFFFFll); op(I64_AND); }
        set(L_A);
    }

    // Run `idx`-th single-op program through its threaded handler.
    void generic(const Uop* single, int insns) {
        get(L_CTX); i32c(static_cast<int32_t>(reinterpret_cast<uintptr_t>(single)));
        i32c(static_cast<int32_t>(e.generic_fn)); call_indirect(T_GENERIC);
        op(I32_EQZ);
        w.u8(0x04); w.u8(0x40);
        // The op ended the block.  It says how far it got, if it knows.
        get(L_CTX); ld32(offsetof(Ctx, partial)); tee(L_T); i32c(0); op(I32_LT_S);
        w.u8(0x04); w.u8(0x7F);
        i32c(insns);
        w.u8(0x05);
        get(L_T);
        w.u8(0x0B);
        op(I64_EXT_U);
        op(0x0F);
        w.u8(0x0B);
    }

};

// What a guest's emitter is given for one op.
struct BlockGen {
    Gen& g;
    const Env& env;
    Block* b;
    const Op& o;
    int pc;                              // offset of the op's instruction from the block start
    int insns;                           // native instructions in the block
    bool eager;                          // the op carries kFlagEager
    std::function<uint32_t()> next_cell; // address of the block's next link cell (static exits)
    std::function<void()> fallback;      // run this op through its threaded handler instead
};

// A guest's own ops, emitted as wasm.  Returns false for an op it does not
// translate; the caller then runs the op's threaded handler.
bool guest_wasm_emit(BlockGen& bg);
// How many link cells the guest's op needs (one per static exit).
int guest_wasm_cells(const Op& o);
// Extra functions the guest wants in every module, after the blocks; each is a
// function body of type T_EXTRA, callable by index env.extra_base + i.
void guest_wasm_extras(std::vector<Buf>& bodies);

}  // namespace jit
