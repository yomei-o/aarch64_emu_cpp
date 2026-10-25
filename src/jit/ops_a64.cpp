// The A64 guest's ops for the threaded backend: the instructions that set or read
// NZCV, and the bitfield moves.  Their arithmetic follows cpu.cpp's, line for line
// (AddWithCarry, the condition table), so that the two cannot disagree.
//
// NZCV is kept exact in the CPU's n, z, c, v after every flag-setting op - there is
// no deferred form here - so the interpreter, hooks and the verifier always see the
// real thing.
#include <cstdio>
#include <cstdlib>

#include "threaded.h"

namespace jit {

namespace {

using a64::Cpu;

// AddWithCarry, as cpu.cpp's addc().
struct AddOut { uint64_t v; bool carry, ovf; };

template <int SZ>
inline AddOut add_with_carry(uint64_t a, uint64_t b, bool cin) {
    if (SZ == 8) {
        const uint64_t r = a + b + (cin ? 1 : 0);
        const bool carry = (r < a) || (cin && r == a);
        const bool ovf = ((~(a ^ b) & (a ^ r)) >> 63) & 1;
        return {r, carry, ovf};
    }
    const uint32_t a32 = static_cast<uint32_t>(a), b32 = static_cast<uint32_t>(b);
    const uint64_t full = static_cast<uint64_t>(a32) + b32 + (cin ? 1 : 0);
    const uint32_t r = static_cast<uint32_t>(full);
    const bool ovf = ((~(a32 ^ b32) & (a32 ^ r)) >> 31) & 1;
    return {r, ((full >> 32) & 1) != 0, ovf};
}

template <int SZ>
inline void set_nzcv(Cpu* cpu, uint64_t result, bool carry, bool ovf) {
    cpu->n = SZ == 8 ? ((result >> 63) & 1) : ((result >> 31) & 1);
    cpu->z = (SZ == 8 ? result : (result & 0xFFFFFFFFull)) == 0;
    cpu->c = carry;
    cpu->v = ovf;
}

// d = a OP b with the flags of the A64 flag-setting forms.  OP: Add, Sub, And, Andn.
template <BinOp OP, int SZ, bool FL>
inline uint64_t flag_op(Cpu* cpu, uint64_t a, uint64_t b) {
    constexpr uint64_t M = mask_of<SZ>();
    a &= M;
    uint64_t r;
    if (OP == BinOp::Add) {
        const AddOut o = add_with_carry<SZ>(a, b, false);
        r = o.v & M;
        if (FL) set_nzcv<SZ>(cpu, o.v, o.carry, o.ovf);
    } else if (OP == BinOp::Sub) {
        const AddOut o = add_with_carry<SZ>(a, ~b, true);
        r = o.v & M;
        if (FL) set_nzcv<SZ>(cpu, o.v, o.carry, o.ovf);
    } else {
        r = (OP == BinOp::And ? (a & b) : (a & ~b)) & M;
        if (FL) set_nzcv<SZ>(cpu, r, false, false);
    }
    return r;
}

template <BinOp OP, int SZ, bool FL>
const Uop* h_flagop(Ctx* c, const Uop* u) {
    S(u->d) = flag_op<OP, SZ, FL>(c->cpu, S(u->a), S(u->b));
    NEXT();
}
template <BinOp OP, int SZ, bool FL>
const Uop* h_flagopi(Ctx* c, const Uop* u) {
    S(u->d) = flag_op<OP, SZ, FL>(c->cpu, S(u->a), static_cast<uint64_t>(u->imm));
    NEXT();
}

// Cpu::cond_holds
inline bool cond_holds(const Cpu* cpu, unsigned cond) {
    bool r;
    switch (cond >> 1) {
        case 0: r = cpu->z; break;
        case 1: r = cpu->c; break;
        case 2: r = cpu->n; break;
        case 3: r = cpu->v; break;
        case 4: r = cpu->c && !cpu->z; break;
        case 5: r = cpu->n == cpu->v; break;
        case 6: r = (cpu->n == cpu->v) && !cpu->z; break;
        default: r = true; break;
    }
    return (cond & 1) && cond != 0xF ? !r : r;
}

template <int SZ>
const Uop* h_csel(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    uint64_t res;
    if (cond_holds(c->cpu, u->cc)) {
        res = S(u->a);
    } else {
        const uint64_t b = S(u->b) & M;
        switch (u->imm) {
            case 0: res = b; break;                              // CSEL
            case 1: res = b + 1; break;                          // CSINC
            case 2: res = ~b; break;                             // CSINV
            default: res = 0 - b; break;                         // CSNEG
        }
    }
    S(u->d) = res & M;
    NEXT();
}

const Uop* h_jcc(Ctx* c, const Uop* u) {
    c->cpu->pc = static_cast<uint64_t>(cond_holds(c->cpu, u->cc) ? u->imm : u->imm2);
    return nullptr;
}

// CCMP / CCMN: compare if the condition holds, else load NZCV from the instruction.
template <int SZ, bool IMM>
const Uop* h_ccmp(Ctx* c, const Uop* u) {
    Cpu* cpu = c->cpu;
    if (cond_holds(cpu, u->cc)) {
        constexpr uint64_t M = mask_of<SZ>();
        const uint64_t a = S(u->a) & M;
        const uint64_t b = IMM ? static_cast<uint64_t>(static_cast<uint32_t>(u->d)) : (S(u->b) & M);
        const AddOut o = u->imm ? add_with_carry<SZ>(a, b, false) : add_with_carry<SZ>(a, ~b, true);
        set_nzcv<SZ>(cpu, o.v, o.carry, o.ovf);
    } else {
        const unsigned f = static_cast<unsigned>(u->imm2);
        cpu->n = (f >> 3) & 1;
        cpu->z = (f >> 2) & 1;
        cpu->c = (f >> 1) & 1;
        cpu->v = f & 1;
    }
    NEXT();
}

inline uint64_t ror_w(uint64_t v, unsigned amount, unsigned width) {
    amount %= width;
    if (!amount) return v;
    const uint64_t mask = width == 64 ? ~0ull : ((1ull << width) - 1);
    v &= mask;
    return ((v >> amount) | (v << (width - amount))) & mask;
}

// Bitfield moves (Cpu::exec_bitfield).  imm = wmask, imm2 = tmask, c = immr, cc = imms.
template <int SZ>
const Uop* h_sbfm(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    const uint64_t src = S(u->a) & M;
    const uint64_t wmask = static_cast<uint64_t>(u->imm), tmask = static_cast<uint64_t>(u->imm2);
    const uint64_t rotated = ror_w(src, static_cast<unsigned>(u->c), SZ * 8);
    const uint64_t top = ((src >> u->cc) & 1) ? ~0ull : 0ull;
    S(u->d) = ((top & ~tmask) | (rotated & wmask & tmask)) & M;
    NEXT();
}
template <int SZ>
const Uop* h_ubfm(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    const uint64_t src = S(u->a) & M;
    const uint64_t wmask = static_cast<uint64_t>(u->imm), tmask = static_cast<uint64_t>(u->imm2);
    S(u->d) = (ror_w(src, static_cast<unsigned>(u->c), SZ * 8) & wmask & tmask) & M;
    NEXT();
}
template <int SZ>
const Uop* h_bfm(Ctx* c, const Uop* u) {
    constexpr uint64_t M = mask_of<SZ>();
    const uint64_t src = S(u->a) & M;
    const uint64_t dst = S(u->b) & M;
    const uint64_t wmask = static_cast<uint64_t>(u->imm), tmask = static_cast<uint64_t>(u->imm2);
    const uint64_t rotated = ror_w(src, static_cast<unsigned>(u->c), SZ * 8);
    const uint64_t bot = (dst & ~wmask) | (rotated & wmask);
    S(u->d) = ((dst & ~tmask) | (bot & tmask)) & M;
    NEXT();
}

// ---- selection ---------------------------------------------------------------

template <BinOp OP, int SZ>
Fn pick_flagop_fl(bool fl, bool imm) {
    if (fl) return imm ? &h_flagopi<OP, SZ, true> : &h_flagop<OP, SZ, true>;
    return imm ? &h_flagopi<OP, SZ, false> : &h_flagop<OP, SZ, false>;
}
template <BinOp OP>
Fn pick_flagop(int sz, bool fl, bool imm) {
    return sz == 4 ? pick_flagop_fl<OP, 4>(fl, imm) : pick_flagop_fl<OP, 8>(fl, imm);
}

Fn select_a64(const Op& o) {
    const bool fl = (o.flags & kFlagEager) != 0;
    switch (o.kind) {
        case OpKind::A64BinS:
        case OpKind::A64BinSI: {
            const bool imm = o.kind == OpKind::A64BinSI;
            switch (static_cast<BinOp>(o.cc)) {
                case BinOp::Add: return pick_flagop<BinOp::Add>(o.sz, fl, imm);
                case BinOp::Sub: return pick_flagop<BinOp::Sub>(o.sz, fl, imm);
                case BinOp::And: return pick_flagop<BinOp::And>(o.sz, fl, imm);
                default: return pick_flagop<BinOp::Andn>(o.sz, fl, imm);
            }
        }
        case OpKind::A64Csel: return o.sz == 4 ? &h_csel<4> : &h_csel<8>;
        case OpKind::A64Jcc: return h_jcc;
        case OpKind::A64Ccmp: return o.sz == 4 ? &h_ccmp<4, false> : &h_ccmp<8, false>;
        case OpKind::A64CcmpI: return o.sz == 4 ? &h_ccmp<4, true> : &h_ccmp<8, true>;
        case OpKind::A64Sbfm: return o.sz == 4 ? &h_sbfm<4> : &h_sbfm<8>;
        case OpKind::A64Bfm: return o.sz == 4 ? &h_bfm<4> : &h_bfm<8>;
        case OpKind::A64Ubfm: return o.sz == 4 ? &h_ubfm<4> : &h_ubfm<8>;
        default: return nullptr;
    }
}

}  // namespace

Fn guest_select(const Op& o) { return select_a64(o); }

}  // namespace jit
