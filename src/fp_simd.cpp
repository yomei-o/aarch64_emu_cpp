// FP and Advanced SIMD.
//
// Grown strictly by demand: an instruction goes in here when a real guest
// executes it and the decoder stops. That is not laziness — an FP instruction
// implemented from the manual but never exercised is untested code that will be
// trusted, and a *wrong* one is worse than a missing one because the guest keeps
// running on the bad value. `exec_fp_simd` still fails loudly for anything not
// listed, printing the encoding, which is the whole bring-up loop.
//
// First entries came from `__builtin_popcountll`, which clang lowers to
// CNT + UADDLV + FMOV rather than a scalar loop.
#include "cpu.h"
#include <cstdio>
#include <cstring>

namespace a64 {

namespace {

// Element accessors over a V128 treated as a vector of `esize` bytes.
uint64_t velem(const V128& v, unsigned esize, unsigned idx) {
    const uint64_t half = idx * esize >= 8 ? v.hi : v.lo;
    const unsigned shift = (idx * esize) % 8 * 8;
    const uint64_t mask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
    return (half >> shift) & mask;
}
void set_velem(V128& v, unsigned esize, unsigned idx, uint64_t val) {
    uint64_t& half = (idx * esize >= 8) ? v.hi : v.lo;
    const unsigned shift = (idx * esize) % 8 * 8;
    const uint64_t mask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
    half = (half & ~(mask << shift)) | ((val & mask) << shift);
}

}  // namespace

void Cpu::exec_fp_simd(uint32_t insn) {
    // ---- FMOV between a general register and a vector register ----------------
    // Also the gateway for SCVTF/FCVTZS later: same encoding, different opcode.
    if (((insn >> 24) & 0x1F) == 0x1E && ((insn >> 21) & 1) && ((insn >> 10) & 0x3F) == 0) {
        const bool sf = (insn >> 31) & 1;
        const unsigned type = (insn >> 22) & 3, rmode = (insn >> 19) & 3;
        const unsigned opcode = (insn >> 16) & 7, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (opcode == 6 && rmode == 0) {                       // FMOV to general
            if (!sf && type == 0) { setw(rd, static_cast<uint32_t>(vreg[rn].lo)); return; }
            if (sf && type == 1) { setx(rd, vreg[rn].lo); return; }
        }
        if (opcode == 7 && rmode == 0) {                       // FMOV from general
            if (!sf && type == 0) { vreg[rd] = {static_cast<uint32_t>(wr(rn)), 0}; return; }
            if (sf && type == 1) { vreg[rd] = {xr(rn), 0}; return; }
        }
        if (opcode == 6 && rmode == 1 && sf && type == 2) {    // FMOV Xd, Vn.D[1]
            setx(rd, vreg[rn].hi); return;
        }
        if (opcode == 7 && rmode == 1 && sf && type == 2) {    // FMOV Vd.D[1], Xn
            vreg[rd].hi = xr(rn); return;
        }
    }

    // ---- Advanced SIMD, two-register miscellaneous ----------------------------
    if ((insn & 0x9F3E0C00u) == 0x0E200800u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (!u && size == 0 && opcode == 0x05) {               // CNT: per-byte population count
            V128 out{};
            const unsigned lanes = q ? 16u : 8u;
            for (unsigned i = 0; i < lanes; ++i) {
                unsigned b = static_cast<unsigned>(velem(vreg[rn], 1, i)), n8 = 0;
                while (b) { n8 += b & 1; b >>= 1; }
                set_velem(out, 1, i, n8);
            }
            vreg[rd] = out;
            return;
        }
    }

    // ---- Advanced SIMD, across lanes ------------------------------------------
    if ((insn & 0x9F3E0C00u) == 0x0E300800u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const unsigned esize = 1u << size;
        const unsigned lanes = (q ? 16u : 8u) / esize;
        if (opcode == 0x03) {                                  // SADDLV / UADDLV: widening sum
            uint64_t sum = 0;
            for (unsigned i = 0; i < lanes; ++i) {
                uint64_t e = velem(vreg[rn], esize, i);
                if (!u) {                                      // signed: sign-extend the element
                    const uint64_t sign = 1ull << (esize * 8 - 1);
                    e = (e ^ sign) - sign;
                }
                sum += e;
            }
            vreg[rd] = {sum, 0};                               // result is scalar in the low half
            return;
        }
        if (opcode == 0x1B && !u) {                            // ADDV: same width
            uint64_t sum = 0;
            for (unsigned i = 0; i < lanes; ++i) sum += velem(vreg[rn], esize, i);
            const uint64_t mask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
            vreg[rd] = {sum & mask, 0};
            return;
        }
    }

    if (on_undefined) on_undefined(insn, pc - 4);
    fail("unimplemented FP/SIMD instruction", insn);
}

}  // namespace a64
