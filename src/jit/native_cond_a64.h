// The ARM / AArch64 condition codes, evaluated on the guest's N, Z, C, V bytes, for guests
// that keep their flags that way (AArch64 and 32-bit ARM).  The AArch64 host's version; needs
// GuestSlots::fl_n / fl_z / fl_c / fl_v.
#pragma once

#include "native_gen_a64.h"

namespace jit {

#ifdef JIT_NATIVE_A64

// Tests condition `cc` (0 EQ .. 13 LE, 14 AL).  Returns the host condition that holds exactly
// when it does, or -1 for "always".  Clobbers x5-x7.
inline int arm_cond(NativeGenA& g, int cc) {
    using namespace a64;
    Asm& a = g.a;
    const GuestSlots& s = g.s;
    auto ldb = [&](int reg, int off) { a.ldrb(reg, ra::ENV, off); };
    int pos;   // the host condition when the "positive" form of the pair holds
    switch (cc >> 1) {
        case 0: ldb(5, s.fl_z); a.cmp_imm(false, 5, 0); pos = NE; break;              // EQ / NE
        case 1: ldb(5, s.fl_c); a.cmp_imm(false, 5, 0); pos = NE; break;              // CS / CC
        case 2: ldb(5, s.fl_n); a.cmp_imm(false, 5, 0); pos = NE; break;              // MI / PL
        case 3: ldb(5, s.fl_v); a.cmp_imm(false, 5, 0); pos = NE; break;              // VS / VC
        case 4:                                                                       // HI / LS: C and not Z
            ldb(5, s.fl_c); ldb(6, s.fl_z); a.alu(BIC, false, 5, 5, 6); a.cmp_imm(false, 5, 0); pos = NE;
            break;
        case 5:                                                                       // GE / LT: N == V
            ldb(5, s.fl_n); ldb(6, s.fl_v); a.alu(EOR, false, 5, 5, 6); a.cmp_imm(false, 5, 0); pos = EQ;
            break;
        case 6:                                                                       // GT / LE: not Z and N == V
            ldb(5, s.fl_n); ldb(6, s.fl_v); a.alu(EOR, false, 5, 5, 6);
            ldb(7, s.fl_z); a.alu(ORR, false, 5, 5, 7); a.cmp_imm(false, 5, 0); pos = EQ;
            break;
        default: return -1;
    }
    return (cc & 1) ? (pos ^ 1) : pos;
}

#endif  // JIT_NATIVE_A64

}  // namespace jit
