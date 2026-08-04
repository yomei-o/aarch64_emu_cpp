// FP and Advanced SIMD.
//
// Grown strictly by demand: an instruction goes in here when a real guest executes
// it and the decoder stops. That is not laziness — an FP instruction implemented
// from the manual but never exercised is untested code that will be trusted, and a
// *wrong* one is worse than a missing one because the guest keeps running on the
// bad value. `exec_fp_simd` fails loudly for anything not listed, printing the
// encoding, which is the whole bring-up loop.
//
// The first entries came from `__builtin_popcountll` (CNT + UADDLV + FMOV). The
// rest arrived the moment a real musl binary ran: its `strlen`, `memset` and
// `memchr` are all NEON, so a static busybox reaches DUP within forty
// instructions of its entry point.
#include "cpu.h"
#include <cstdio>
#include <cstring>

namespace a64 {

namespace {

// Element accessors over a V128 treated as a vector of `esize`-byte lanes.
uint64_t velem(const V128& v, unsigned esize, unsigned idx) {
    const uint64_t half = (idx * esize >= 8) ? v.hi : v.lo;
    const unsigned shift = ((idx * esize) % 8) * 8;
    const uint64_t mask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
    return (half >> shift) & mask;
}
void set_velem(V128& v, unsigned esize, unsigned idx, uint64_t val) {
    uint64_t& half = (idx * esize >= 8) ? v.hi : v.lo;
    const unsigned shift = ((idx * esize) % 8) * 8;
    const uint64_t mask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
    half = (half & ~(mask << shift)) | ((val & mask) << shift);
}

}  // namespace

void Cpu::exec_fp_simd(uint32_t insn) {
    // ---- FMOV between a general register and a vector register ----------------
    if (((insn >> 24) & 0x1F) == 0x1E && ((insn >> 21) & 1) && ((insn >> 10) & 0x3F) == 0) {
        const bool sf = (insn >> 31) & 1;
        const unsigned type = (insn >> 22) & 3, rmode = (insn >> 19) & 3;
        const unsigned opcode = (insn >> 16) & 7, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (opcode == 6 && rmode == 0) {                        // FMOV to general
            if (!sf && type == 0) { setw(rd, static_cast<uint32_t>(vreg[rn].lo)); return; }
            if (sf && type == 1) { setx(rd, vreg[rn].lo); return; }
        }
        if (opcode == 7 && rmode == 0) {                        // FMOV from general
            if (!sf && type == 0) { vreg[rd] = {static_cast<uint32_t>(wr(rn)), 0}; return; }
            if (sf && type == 1) { vreg[rd] = {xr(rn), 0}; return; }
        }
        if (opcode == 6 && rmode == 1 && sf && type == 2) { setx(rd, vreg[rn].hi); return; }
        if (opcode == 7 && rmode == 1 && sf && type == 2) { vreg[rd].hi = xr(rn); return; }
    }

    // ---- DUP / INS / UMOV / SMOV ----------------------------------------------
    // imm5 encodes the element size *and* the index together: the lowest set bit
    // says which size, the bits above it are the index.
    if ((insn & 0xBFE0FC00u) == 0x0E000C00u ||                  // DUP (general)
        (insn & 0xBFE0FC00u) == 0x0E000400u ||                  // DUP (element)
        (insn & 0xBFE0FC00u) == 0x0E002C00u ||                  // SMOV
        (insn & 0xBFE0FC00u) == 0x0E003C00u ||                  // UMOV
        (insn & 0xFFE0FC00u) == 0x4E001C00u) {                  // INS (general)
        const bool q = (insn >> 30) & 1;
        const unsigned imm5 = (insn >> 16) & 0x1F, op = (insn >> 11) & 0xF;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        unsigned size = 0;
        while (size < 4 && !((imm5 >> size) & 1)) ++size;
        if (size >= 4) fail("reserved imm5 in DUP/INS/UMOV", insn);
        const unsigned esize = 1u << size, index = imm5 >> (size + 1);
        const unsigned lanes = (q ? 16u : 8u) / esize;

        if (op == 1) {                                          // DUP general
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) set_velem(out, esize, i, xr(rn));
            vreg[rd] = out; return;
        }
        if (op == 0) {                                          // DUP element
            const uint64_t e = velem(vreg[rn], esize, index);
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) set_velem(out, esize, i, e);
            vreg[rd] = out; return;
        }
        if (op == 3) { set_velem(vreg[rd], esize, index, xr(rn)); return; }      // INS general
        if (op == 7) {                                          // UMOV
            const uint64_t e = velem(vreg[rn], esize, index);
            if (esize == 8) setx(rd, e); else setw(rd, static_cast<uint32_t>(e));
            return;
        }
        if (op == 5) {                                          // SMOV
            uint64_t e = velem(vreg[rn], esize, index);
            const uint64_t s = 1ull << (esize * 8 - 1);
            e = (e ^ s) - s;
            if (q) setx(rd, e); else setw(rd, static_cast<uint32_t>(e));
            return;
        }
    }

    // ---- INS (element to element) ---------------------------------------------
    if ((insn & 0xFFE08400u) == 0x6E000400u) {
        const unsigned imm5 = (insn >> 16) & 0x1F, imm4 = (insn >> 11) & 0xF;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        unsigned size = 0;
        while (size < 4 && !((imm5 >> size) & 1)) ++size;
        if (size >= 4) fail("reserved imm5 in INS", insn);
        const unsigned esize = 1u << size;
        set_velem(vreg[rd], esize, imm5 >> (size + 1), velem(vreg[rn], esize, imm4 >> size));
        return;
    }

    // ---- Advanced SIMD, three registers of the same shape ----------------------
    if ((insn & 0x9F200400u) == 0x0E200400u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, rm = (insn >> 16) & 0x1F;
        const unsigned opcode = (insn >> 11) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const V128 a = vreg[rn], b = vreg[rm];

        if (opcode == 0x03) {                                   // the logical family
            V128 out{};
            switch ((u << 2) | size) {
                case 0: out = {a.lo & b.lo, a.hi & b.hi}; break;                 // AND
                case 1: out = {a.lo & ~b.lo, a.hi & ~b.hi}; break;               // BIC
                case 2: out = {a.lo | b.lo, a.hi | b.hi}; break;                 // ORR
                case 3: out = {a.lo | ~b.lo, a.hi | ~b.hi}; break;               // ORN
                case 4: out = {a.lo ^ b.lo, a.hi ^ b.hi}; break;                 // EOR
                case 5: { const V128 d = vreg[rd];                               // BSL
                          out = {(b.lo & ~d.lo) | (a.lo & d.lo),
                                 (b.hi & ~d.hi) | (a.hi & d.hi)}; break; }
                case 6: { const V128 d = vreg[rd];                               // BIT
                          out = {(d.lo & ~b.lo) | (a.lo & b.lo),
                                 (d.hi & ~b.hi) | (a.hi & b.hi)}; break; }
                default: { const V128 d = vreg[rd];                              // BIF
                          out = {(d.lo & b.lo) | (a.lo & ~b.lo),
                                 (d.hi & b.hi) | (a.hi & ~b.hi)}; break; }
            }
            if (!q) out.hi = 0;
            vreg[rd] = out;
            return;
        }

        const unsigned esize = 1u << size;
        const unsigned lanes = (q ? 16u : 8u) / esize;
        const uint64_t emask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
        auto sx = [&](uint64_t e) {
            const uint64_t s = 1ull << (esize * 8 - 1);
            return static_cast<int64_t>((e ^ s) - s);
        };
        V128 out{};
        bool ok = true;
        for (unsigned i = 0; i < lanes && ok; ++i) {
            const uint64_t x = velem(a, esize, i), y = velem(b, esize, i);
            uint64_t r = 0;
            switch (opcode) {
                case 0x10: r = u ? (x - y) : (x + y); break;                     // SUB / ADD
                case 0x11: r = u ? ((x == y) ? emask : 0)                        // CMEQ
                                 : (((x & y) != 0) ? emask : 0); break;          // CMTST
                case 0x0C: r = u ? (x > y ? x : y) : (sx(x) > sx(y) ? x : y); break;   // UMAX/SMAX
                case 0x0D: r = u ? (x < y ? x : y) : (sx(x) < sx(y) ? x : y); break;   // UMIN/SMIN
                case 0x06: r = u ? ((x >= y) ? emask : 0)                        // CMHS / CMGE
                                 : ((sx(x) >= sx(y)) ? emask : 0); break;
                case 0x07: r = u ? ((x > y) ? emask : 0)                         // CMHI / CMGT
                                 : ((sx(x) > sx(y)) ? emask : 0); break;
                default: ok = false; break;
            }
            if (ok) set_velem(out, esize, i, r);
        }
        if (ok) { vreg[rd] = out; return; }
    }

    // ---- Advanced SIMD, two-register miscellaneous -----------------------------
    if ((insn & 0x9F3E0C00u) == 0x0E200800u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (!u && size == 0 && opcode == 0x05) {                // CNT
            V128 out{};
            const unsigned lanes = q ? 16u : 8u;
            for (unsigned i = 0; i < lanes; ++i) {
                unsigned bits = static_cast<unsigned>(velem(vreg[rn], 1, i)), k = 0;
                while (bits) { k += bits & 1; bits >>= 1; }
                set_velem(out, 1, i, k);
            }
            vreg[rd] = out; return;
        }
        const unsigned esize = 1u << size;
        const unsigned lanes = (q ? 16u : 8u) / esize;
        const uint64_t emask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
        if (opcode == 0x09 || opcode == 0x0A) {                 // CMEQ/CMGE/CMGT/CMLE #0
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t e = velem(vreg[rn], esize, i);
                const uint64_t s = 1ull << (esize * 8 - 1);
                const int64_t se = static_cast<int64_t>((e ^ s) - s);
                bool t;
                if (opcode == 0x09) t = u ? (se <= 0) : (se >= 0);               // CMLE / CMGE
                else                t = u ? (se < 0) : (se > 0);                 // CMLT / CMGT
                set_velem(out, esize, i, t ? emask : 0);
            }
            vreg[rd] = out; return;
        }
        if (opcode == 0x05 && u) {                              // NOT / MVN (size==00)
            V128 out = {~vreg[rn].lo, ~vreg[rn].hi};
            if (!q) out.hi = 0;
            vreg[rd] = out; return;
        }
    }

    // ---- Advanced SIMD, across lanes ------------------------------------------
    if ((insn & 0x9F3E0C00u) == 0x0E300800u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const unsigned esize = 1u << size;
        const unsigned lanes = (q ? 16u : 8u) / esize;
        const uint64_t emask = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
        auto sx = [&](uint64_t e) {
            const uint64_t s = 1ull << (esize * 8 - 1);
            return static_cast<int64_t>((e ^ s) - s);
        };
        if (opcode == 0x03) {                                   // SADDLV / UADDLV
            uint64_t sum = 0;
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t e = velem(vreg[rn], esize, i);
                sum += u ? e : static_cast<uint64_t>(sx(e));
            }
            vreg[rd] = {sum, 0}; return;
        }
        if (opcode == 0x0A || opcode == 0x1A || opcode == 0x1B) {
            uint64_t acc = velem(vreg[rn], esize, 0);
            for (unsigned i = 1; i < lanes; ++i) {
                const uint64_t e = velem(vreg[rn], esize, i);
                if (opcode == 0x1B) acc += e;                                    // ADDV
                else if (opcode == 0x0A) acc = u ? (e > acc ? e : acc)           // UMAXV/SMAXV
                                                 : (sx(e) > sx(acc) ? e : acc);
                else acc = u ? (e < acc ? e : acc) : (sx(e) < sx(acc) ? e : acc);// UMINV/SMINV
            }
            vreg[rd] = {acc & emask, 0}; return;
        }
    }

    // ---- MOVI / MVNI -----------------------------------------------------------
    if ((insn & 0x9FF80400u) == 0x0F000400u) {
        const bool q = (insn >> 30) & 1, op = (insn >> 29) & 1;
        const unsigned cmode = (insn >> 12) & 0xF, rd = insn & 0x1F;
        const uint64_t imm8 = (((insn >> 16) & 7) << 5) | ((insn >> 5) & 0x1F);
        uint64_t imm64 = 0;
        if ((cmode & 0xE) == 0xE && op) {                       // MOVI Dd, #imm: bit per byte
            for (int i = 0; i < 8; ++i) if ((imm8 >> i) & 1) imm64 |= 0xFFull << (i * 8);
        } else if ((cmode & 0xE) == 0xE) {                      // 8-bit replicate
            for (int i = 0; i < 8; ++i) imm64 |= imm8 << (i * 8);
        } else if ((cmode & 0x8) == 0) {                        // 32-bit, shifted
            uint64_t v32 = imm8 << (((cmode >> 1) & 3) * 8);
            if (cmode & 1) v32 = ~v32 & 0xFFFFFFFFull;
            v32 &= 0xFFFFFFFFull;
            imm64 = v32 | (v32 << 32);
        } else {                                                // 16-bit, shifted
            const uint64_t v16 = (imm8 << (((cmode >> 1) & 1) * 8)) & 0xFFFF;
            for (int i = 0; i < 4; ++i) imm64 |= v16 << (i * 16);
        }
        if (op && (cmode & 0xE) != 0xE) imm64 = ~imm64;         // MVNI
        vreg[rd] = {imm64, q ? imm64 : 0};
        return;
    }

    // ---- Advanced SIMD, shift by immediate -------------------------------------
    // immh is doing double duty: it selects the element size *and* carries the top
    // of the shift amount. immh == 0 is the MOVI group above, which is why that has
    // to be tested first.
    if ((insn & 0x9F800400u) == 0x0F000400u && ((insn >> 19) & 0xF) != 0) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned immh = (insn >> 19) & 0xF, immb = (insn >> 16) & 7;
        const unsigned opcode = (insn >> 11) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        unsigned size = 3;
        while (size && !((immh >> size) & 1)) --size;
        const unsigned esize = 1u << size;
        const unsigned bits = esize * 8;
        const unsigned imm = (immh << 3) | immb;

        if (opcode == 0x14) {                                   // SSHLL / USHLL (and SXTL)
            const unsigned shift = imm - bits;
            const unsigned lanes = 8u / esize;                  // the *source* half
            const unsigned base = q ? lanes : 0;                // SSHLL2 takes the top half
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                uint64_t e = velem(vreg[rn], esize, base + i);
                if (!u) { const uint64_t s = 1ull << (bits - 1); e = (e ^ s) - s; }
                set_velem(out, esize * 2, i, e << shift);
            }
            vreg[rd] = out; return;
        }
        const unsigned lanes = (q ? 16u : 8u) / esize;
        V128 out{};
        if (opcode == 0x0A) {                                   // SHL
            const unsigned shift = imm - bits;
            for (unsigned i = 0; i < lanes; ++i)
                set_velem(out, esize, i, velem(vreg[rn], esize, i) << shift);
            vreg[rd] = out; return;
        }
        if (opcode == 0x00) {                                   // SSHR / USHR
            const unsigned shift = 2 * bits - imm;
            for (unsigned i = 0; i < lanes; ++i) {
                uint64_t e = velem(vreg[rn], esize, i);
                if (u) e >>= (shift >= bits ? bits - 1 : shift);
                else {
                    const uint64_t s = 1ull << (bits - 1);
                    const int64_t se = static_cast<int64_t>((e ^ s) - s);
                    e = static_cast<uint64_t>(se >> (shift >= bits ? bits - 1 : shift));
                }
                set_velem(out, esize, i, e);
            }
            vreg[rd] = out; return;
        }
    }

    // ---- scalar floating point -------------------------------------------------
    // S values live in the low 32 bits of the register, D values in the low 64. The
    // architecture leaves the rest of the register zeroed on a scalar write, and so
    // do we — a guest that reads back a stale high half would see it.
    {
        const unsigned type = (insn >> 22) & 3;                 // 00 = single, 01 = double
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F, rm = (insn >> 16) & 0x1F;
        const bool dbl = (type == 1);
        auto rdf = [&](unsigned r) -> double {
            if (dbl) { double d; std::memcpy(&d, &vreg[r].lo, 8); return d; }
            float f; const uint32_t b = static_cast<uint32_t>(vreg[r].lo);
            std::memcpy(&f, &b, 4); return f;
        };
        auto wrf = [&](unsigned r, double val) {
            if (dbl) { uint64_t b; std::memcpy(&b, &val, 8); vreg[r] = {b, 0}; }
            else { const float f = static_cast<float>(val); uint32_t b;
                   std::memcpy(&b, &f, 4); vreg[r] = {b, 0}; }
        };

        if (type < 2) {
            // FP data processing, two sources
            if ((insn & 0x5F200C00u) == 0x1E200800u) {
                const unsigned opcode = (insn >> 12) & 0xF;
                const double a = rdf(rn), b = rdf(rm);
                switch (opcode) {
                    case 0x0: wrf(rd, a * b); return;                       // FMUL
                    case 0x1: wrf(rd, a / b); return;                       // FDIV
                    case 0x2: wrf(rd, a + b); return;                       // FADD
                    case 0x3: wrf(rd, a - b); return;                       // FSUB
                    case 0x4: wrf(rd, a > b ? a : b); return;               // FMAX
                    case 0x5: wrf(rd, a < b ? a : b); return;               // FMIN
                    case 0x6: wrf(rd, a > b ? a : b); return;               // FMAXNM
                    case 0x7: wrf(rd, a < b ? a : b); return;               // FMINNM
                    case 0x8: wrf(rd, -(a * b)); return;                    // FNMUL
                    default: break;
                }
            }
            // FP data processing, one source
            if ((insn & 0x5F207C00u) == 0x1E204000u) {
                const unsigned opcode = (insn >> 15) & 0x3F;
                switch (opcode) {
                    case 0x0: wrf(rd, rdf(rn)); return;                     // FMOV
                    case 0x1: wrf(rd, rdf(rn) < 0 ? -rdf(rn) : rdf(rn)); return;   // FABS
                    case 0x2: wrf(rd, -rdf(rn)); return;                    // FNEG
                    case 0x3: {                                             // FSQRT
                        const double v = rdf(rn);
                        double q = v; if (v > 0) { q = v; for (int k = 0; k < 60; ++k) q = 0.5 * (q + v / q); }
                        else if (v == 0) q = v;
                        wrf(rd, q); return;
                    }
                    case 0x4: {                                             // FCVT S -> D
                        if (type == 0) { const double v = rdf(rn); uint64_t b;
                                         std::memcpy(&b, &v, 8); vreg[rd] = {b, 0}; return; }
                        break;
                    }
                    case 0x5: {                                             // FCVT D -> S
                        if (type == 1) { const float f = static_cast<float>(rdf(rn)); uint32_t b;
                                         std::memcpy(&b, &f, 4); vreg[rd] = {b, 0}; return; }
                        break;
                    }
                    default: break;
                }
            }
            // FP compare. The four NZCV patterns are fixed by the architecture, and
            // "unordered" is its own case: a NaN sets C and V, not just Z.
            if ((insn & 0x5F203C00u) == 0x1E202000u && (insn & 0x7) == 0) {
                const bool cmp_zero = (insn >> 3) & 1;   // bit 4 is FCMPE, which we treat the same
                const double a = rdf(rn), b = cmp_zero ? 0.0 : rdf(rm);
                if (a != a || b != b) { n = false; z = false; c = true; v = true; }
                else if (a < b) { n = true; z = false; c = false; v = false; }
                else if (a == b) { n = false; z = true; c = true; v = false; }
                else { n = false; z = false; c = true; v = false; }
                return;
            }
            // FP conditional select
            if ((insn & 0x5F200C00u) == 0x1E200C00u) {
                const unsigned cond = (insn >> 12) & 0xF;
                wrf(rd, cond_holds(cond) ? rdf(rn) : rdf(rm));
                return;
            }
            // FP immediate: an 8-bit form giving sign, a 3-bit exponent and 4 mantissa bits
            if ((insn & 0x5F201C00u) == 0x1E201000u) {
                const unsigned imm8 = (insn >> 13) & 0xFF;
                // VFPExpandImm, built as a bit pattern rather than approximated with
                // arithmetic. The exponent is NOT(b6) : Replicate(b6, E-3) : b5:b4 —
                // an encoding that is easy to "nearly" implement and then be wrong by
                // a factor of two somewhere in the middle of the range.
                const uint64_t sign = (imm8 >> 7) & 1, b6 = (imm8 >> 6) & 1;
                const uint64_t lowexp = (imm8 >> 4) & 3, frac = imm8 & 0xF;
                if (dbl) {
                    const uint64_t exp = ((~b6 & 1) << 10) | ((b6 ? 0xFFull : 0ull) << 2) | lowexp;
                    const uint64_t bits = (sign << 63) | (exp << 52) | (frac << 48);
                    vreg[rd] = {bits, 0};
                } else {
                    const uint32_t exp = static_cast<uint32_t>(((~b6 & 1) << 7) |
                                         ((b6 ? 0x1Full : 0ull) << 2) | lowexp);
                    const uint32_t bits = static_cast<uint32_t>((sign << 31) | (exp << 23) |
                                          (frac << 19));
                    vreg[rd] = {bits, 0};
                }
                return;
            }

            // FP data processing, three sources: FMADD / FMSUB / FNMADD / FNMSUB.
            if ((insn & 0x5F000000u) == 0x1F000000u) {
                const unsigned ra = (insn >> 10) & 0x1F;
                const bool o1 = (insn >> 21) & 1, o0 = (insn >> 15) & 1;
                const double prod = rdf(rn) * rdf(rm), acc = rdf(ra);
                double res = o0 ? (acc - prod) : (acc + prod);
                if (o1) res = -res;
                wrf(rd, res);
                return;
            }
        }

        // Conversions between FP and integer, and rounding to integer.
        if ((insn & 0x5F20FC00u) == 0x1E200000u) {
            const bool sf = (insn >> 31) & 1;
            const unsigned rmode = (insn >> 19) & 3, opcode = (insn >> 16) & 7;
            if (opcode == 2 || opcode == 3) {                    // SCVTF / UCVTF
                const double val = (opcode == 2)
                    ? static_cast<double>(sf ? static_cast<int64_t>(xr(rn))
                                             : static_cast<int64_t>(static_cast<int32_t>(wr(rn))))
                    : static_cast<double>(sf ? xr(rn) : static_cast<uint64_t>(wr(rn)));
                wrf(rd, val);
                return;
            }
            if ((opcode == 0 || opcode == 1) && rmode == 3) {    // FCVTZS / FCVTZU (toward zero)
                const double val = rdf(rn);
                if (opcode == 0) {
                    const int64_t iv = static_cast<int64_t>(val);
                    if (sf) setx(rd, static_cast<uint64_t>(iv));
                    else setw(rd, static_cast<uint32_t>(static_cast<int32_t>(iv)));
                } else {
                    const uint64_t uv = val <= 0 ? 0 : static_cast<uint64_t>(val);
                    if (sf) setx(rd, uv); else setw(rd, static_cast<uint32_t>(uv));
                }
                return;
            }
        }
    }

    if (on_undefined) on_undefined(insn, pc - 4);
    fail("unimplemented FP/SIMD instruction", insn);
}

}  // namespace a64
