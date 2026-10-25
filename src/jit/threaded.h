// What the threaded handlers have in common, whichever guest they serve: the way a
// handler reads its operands (slots in the register file), hands over to the next
// op, and checks whether a store invalidated translated code.
#pragma once

#include <cstdint>

#include "engine.h"

namespace jit {

using Fn = const Uop* (*)(Ctx*, const Uop*);

#define S(o) (*reinterpret_cast<uint64_t*>(c->env + (o)))

// After a store that asked for it: leave the block if the store invalidated
// translated code, at the next instruction (imm2).
#define CHK_FLUSH()                                                  \
    do {                                                             \
        if ((u->flags & kFlagChk) && c->eng->epoch != c->epoch0) {   \
            c->partial = u->ni;                                      \
            Glue::set_pc(*c->cpu, static_cast<uint64_t>(u->imm2));   \
            return nullptr;                                          \
        }                                                            \
    } while (0)

// How a handler hands over to the next op.  With tail calls each handler ends in
// its own indirect jump, which a branch predictor can learn per handler; a loop
// that calls every handler from one place gives it a single jump to guess for
// the whole program.  Where the compiler cannot promise the tail call, the
// handler returns the next op and run() loops.
#if defined(JIT_NO_MUSTTAIL) || !(defined(__clang__) || (defined(__GNUC__) && __GNUC__ >= 15))
#define NEXT() return u + 1
#else
#define NEXT() [[gnu::musttail]] return (u + 1)->fn(c, u + 1)
#endif

template <int SZ> constexpr uint64_t mask_of() {
    return SZ == 8 ? ~0ull : ((1ull << (SZ * 8)) - 1);
}
template <int SZ> constexpr uint64_t sign_of() { return 1ull << (SZ * 8 - 1); }

template <int SZ>
inline int64_t sext_n(uint64_t v) {
    if (SZ == 1) return static_cast<int8_t>(v);
    if (SZ == 2) return static_cast<int16_t>(v);
    if (SZ == 4) return static_cast<int32_t>(v);
    return static_cast<int64_t>(v);
}

// The generic integer operations (BinOp / UnOp / Cond), written once so that every
// guest's handlers - and the flag-setting ones in ops_a64.cpp - compute them
// identically.  Operands are masked to SZ bytes here; the result is too.
template <BinOp OP, int SZ>
inline uint64_t bin_eval(uint64_t a, uint64_t b) {
    constexpr uint64_t M = mask_of<SZ>();
    constexpr unsigned bits = SZ * 8;
    a &= M;
    switch (OP) {
        case BinOp::Add: return (a + b) & M;
        case BinOp::Sub: return (a - b) & M;
        case BinOp::And: return a & b & M;
        case BinOp::Or: return (a | b) & M;
        case BinOp::Xor: return (a ^ b) & M;
        case BinOp::Andn: return a & ~b & M;
        case BinOp::Orn: return (a | ~b) & M;
        case BinOp::Eon: return (a ^ ~b) & M;
        case BinOp::Mul: return (a * b) & M;
        case BinOp::Shl: return (a << (b & (bits - 1))) & M;
        case BinOp::Shr: return a >> (b & (bits - 1));
        case BinOp::Sar: return static_cast<uint64_t>(sext_n<SZ>(a) >> (b & (bits - 1))) & M;
        case BinOp::Ror: {
            const unsigned n = static_cast<unsigned>(b & (bits - 1));
            return n ? (((a >> n) | (a << (bits - n))) & M) : a;
        }
        case BinOp::UDiv0: b &= M; return b ? a / b : 0;
        default: {   // SDiv0: x / 0 is 0, and the one overflowing case wraps
            const int64_t sa = sext_n<SZ>(a), sb = sext_n<SZ>(b & M);
            if (sb == 0) return 0;
            if (sb == -1) return static_cast<uint64_t>(0 - sa) & M;
            return static_cast<uint64_t>(sa / sb) & M;
        }
    }
}

template <UnOp OP, int SZ>
inline uint64_t un_eval(uint64_t a) {
    constexpr uint64_t M = mask_of<SZ>();
    constexpr unsigned bits = SZ * 8;
    a &= M;
    switch (OP) {
        case UnOp::Clz: {
            unsigned n = 0;
            for (unsigned i = bits; i-- > 0;) { if ((a >> i) & 1) break; ++n; }
            return n;
        }
        case UnOp::Rbit: {
            uint64_t r = 0;
            for (unsigned i = 0; i < bits; ++i) r |= ((a >> i) & 1) << (bits - 1 - i);
            return r;
        }
        case UnOp::Rev: {
            uint64_t r = 0;
            for (unsigned i = 0; i < SZ; ++i) r |= ((a >> (8 * i)) & 0xFF) << (8 * (SZ - 1 - i));
            return r;
        }
        case UnOp::Rev16: {
            uint64_t r = 0;
            for (unsigned i = 0; i < SZ; i += 2) r |= (((a >> (8 * i)) & 0xFF) << (8 * (i + 1))) | (((a >> (8 * (i + 1))) & 0xFF) << (8 * i));
            return r;
        }
        default: {   // Rev32: bytes reversed within each 32-bit half (64-bit operands)
            uint64_t r = 0;
            for (unsigned h = 0; h < SZ; h += 4)
                for (unsigned i = 0; i < 4; ++i) r |= ((a >> (8 * (h + i))) & 0xFF) << (8 * (h + 3 - i));
            return r;
        }
    }
}

template <Cond C, int SZ>
inline bool cond_eval(uint64_t a, uint64_t b) {
    constexpr uint64_t M = mask_of<SZ>();
    a &= M;
    b &= M;
    switch (C) {
        case Cond::Eq: return a == b;
        case Cond::Ne: return a != b;
        case Cond::Ltu: return a < b;
        case Cond::Geu: return a >= b;
        case Cond::Leu: return a <= b;
        case Cond::Gtu: return a > b;
        case Cond::Lts: return sext_n<SZ>(a) < sext_n<SZ>(b);
        case Cond::Ges: return sext_n<SZ>(a) >= sext_n<SZ>(b);
        case Cond::Les: return sext_n<SZ>(a) <= sext_n<SZ>(b);
        case Cond::Gts: return sext_n<SZ>(a) > sext_n<SZ>(b);
        case Cond::Tst: return (a & b) != 0;
        default: return (a & b) == 0;
    }
}

// A guest's own ops.  Returns the handler for `o`, or nullptr if `o` is not one
// of the guest's (the backend then reports the op as unknown).
Fn guest_select(const Op& o);

}  // namespace jit
