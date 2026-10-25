// The ARM / AArch64 condition codes, evaluated on the guest's N, Z, C, V bytes, for guests
// that keep their flags that way (AArch64 and 32-bit ARM).  The x86-64 host's version; needs
// GuestSlots::fl_n / fl_z / fl_c / fl_v.
#pragma once

#include "native_gen.h"

namespace jit {

#ifdef JIT_HAVE_NATIVE

// Tests condition `cc` (0 EQ .. 13 LE, 14 AL).  Returns the host condition that holds exactly
// when it does, or -1 for "always".  Clobbers r8-r10.
inline int arm_cond(NativeGen& g, int cc) {
    using namespace x64;
    Asm& a = g.a;
    const GuestSlots& s = g.s;
    auto ldb = [&](int reg, int off) { a.load8u(reg, RBX, off); };
    int pos;   // the host condition when the "positive" form of the pair holds
    switch (cc >> 1) {
        case 0: ldb(R8, s.fl_z); a.test_rr(false, R8, R8); pos = NE; break;               // EQ / NE
        case 1: ldb(R8, s.fl_c); a.test_rr(false, R8, R8); pos = NE; break;               // CS / CC
        case 2: ldb(R8, s.fl_n); a.test_rr(false, R8, R8); pos = NE; break;               // MI / PL
        case 3: ldb(R8, s.fl_v); a.test_rr(false, R8, R8); pos = NE; break;               // VS / VC
        case 4:                                                                           // HI / LS: C and not Z
            ldb(R8, s.fl_c); ldb(R9, s.fl_z); a.alu_ri(XOR, false, R9, 1); a.alu_rr(AND, false, R8, R9);
            a.test_rr(false, R8, R8); pos = NE;
            break;
        case 5:                                                                           // GE / LT: N == V
            ldb(R8, s.fl_n); ldb(R9, s.fl_v); a.alu_rr(XOR, false, R8, R9); a.test_rr(false, R8, R8); pos = E;
            break;
        case 6:                                                                           // GT / LE: not Z and N == V
            ldb(R8, s.fl_n); ldb(R9, s.fl_v); a.alu_rr(XOR, false, R8, R9);
            ldb(R10, s.fl_z); a.alu_rr(OR, false, R8, R10); a.test_rr(false, R8, R8); pos = E;
            break;
        default: return -1;
    }
    return (cc & 1) ? (pos ^ 1) : pos;
}

#endif  // JIT_HAVE_NATIVE

}  // namespace jit
