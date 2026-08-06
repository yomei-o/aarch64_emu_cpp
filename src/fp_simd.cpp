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
#include <cmath>
#include <cstdint>

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
    if (exec_crypto(insn)) return;
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

    // ---- DUP (scalar element), also written MOV Bd, Vn.B[i] --------------------
    // The scalar sibling of DUP (element): one lane out of Vn into the bottom of Vd
    // with the rest of the register zeroed, which is what "scalar" means here. Same
    // imm5 encoding, different group — bits 28..24 are 11110 rather than 01110, so the
    // vector pattern below correctly does not match it and it needs saying separately.
    // libcorecrypto's AES key expansion reaches it immediately after AESE.
    if ((insn & 0xFFE0FC00u) == 0x5E000400u) {
        const unsigned imm5 = (insn >> 16) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        unsigned size = 0;
        while (size < 4 && !((imm5 >> size) & 1)) ++size;
        if (size >= 4) fail("reserved imm5 in scalar DUP", insn);
        const unsigned esize = 1u << size, index = imm5 >> (size + 1);
        vreg[rd] = {velem(vreg[rn], esize, index), 0};
        return;
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

    // ---- EXT: a byte window across a pair of registers -------------------------
    // Neither operand of EXT nor TBL sets bit 21, which is what keeps them out of
    // the three-same group below; they have to be tested first all the same,
    // because their opcode fields overlap.
    if ((insn & 0xBFE08400u) == 0x2E000000u) {
        const bool q = (insn >> 30) & 1;
        const unsigned imm4 = (insn >> 11) & 0xF;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const unsigned width = q ? 16u : 8u;
        const V128 a = vreg[rn], b = vreg[rm];
        V128 out{};
        for (unsigned i = 0; i < width; ++i) {
            const unsigned src = imm4 + i;
            const uint64_t byte = (src < width) ? velem(a, 1, src) : velem(b, 1, src - width);
            set_velem(out, 1, i, byte);
        }
        vreg[rd] = out;
        return;
    }

    // ---- TBL / TBX: byte table lookup over one to four consecutive registers ----
    if ((insn & 0xBF208C00u) == 0x0E000000u) {
        const bool q = (insn >> 30) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, len = (insn >> 13) & 3;
        const bool tbx = (insn >> 12) & 1;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const unsigned width = q ? 16u : 8u;
        const unsigned table_bytes = (len + 1) * 16;
        V128 out = tbx ? vreg[rd] : V128{};
        for (unsigned i = 0; i < width; ++i) {
            const unsigned idx = static_cast<unsigned>(velem(vreg[rm], 1, i));
            if (idx < table_bytes) {
                const V128& t = vreg[(rn + idx / 16) & 31];
                set_velem(out, 1, i, velem(t, 1, idx % 16));
            } else if (!tbx) {
                set_velem(out, 1, i, 0);           // TBL zeroes out-of-range, TBX keeps
            }
        }
        if (!q) out.hi = 0;
        vreg[rd] = out;
        return;
    }

    // ---- Advanced SIMD vector x indexed element: MUL / MLA / MLS ----------------
    // One lane of Vm multiplies every lane of Vn.  gcc 11's vectoriser emits
    // `mul v7.4s, v3.4s, v1.s[0]` inside cc1's own code (the ira pass), which
    // is how the group earned its place; the FP and widening forms still fail
    // loudly below.
    if ((insn & 0x9F000400u) == 0x0F000000u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3;
        const unsigned L = (insn >> 21) & 1, M = (insn >> 20) & 1, rm4 = (insn >> 16) & 0xF;
        const unsigned opcode = (insn >> 12) & 0xF, H = (insn >> 11) & 1;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const bool mul = (opcode == 0x8 && !u), mla = (opcode == 0x0 && u),
                   mls = (opcode == 0x4 && u);
        if ((mul || mla || mls) && (size == 1 || size == 2)) {
            unsigned index, vm;
            if (size == 1) { index = (H << 2) | (L << 1) | M; vm = rm4; }
            else { index = (H << 1) | L; vm = (M << 4) | rm4; }
            const unsigned esize = 1u << size;
            const unsigned lanes = (q ? 16u : 8u) / esize;
            const uint64_t emask = (1ull << (esize * 8)) - 1;
            const uint64_t e = velem(vreg[vm], esize, index);
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t x = velem(vreg[rn], esize, i);
                const uint64_t acc = velem(vreg[rd], esize, i);
                const uint64_t r = mul ? x * e : mla ? acc + x * e : acc - x * e;
                set_velem(out, esize, i, r & emask);
            }
            if (!q) out.hi = 0;
            vreg[rd] = out;
            return;
        }
        // Anything else in the group (FMLA/FMUL by element, the widening
        // forms) falls through to the failure at the end.
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

        // The pairwise integer ops read lanes across the *concatenation* of the
        // two sources, so they do not fit the per-lane loop below.  ADDP is how
        // glibc's aarch64 strlen narrows a comparison mask.
        if (opcode == 0x17 || opcode == 0x14 || opcode == 0x15) {  // ADDP, SMAXP/UMAXP, SMINP/UMINP
            if (opcode == 0x17 && u) fail("three-same opcode 0x17 with U set", insn);
            V128 pout{};
            for (unsigned i = 0; i < lanes; ++i) {
                const bool from_b = (2 * i) >= lanes;
                const V128& src = from_b ? b : a;
                const unsigned base = from_b ? 2 * i - lanes : 2 * i;
                const uint64_t x = velem(src, esize, base), y = velem(src, esize, base + 1);
                uint64_t r;
                if (opcode == 0x17)
                    r = x + y;
                else if (opcode == 0x14)
                    r = u ? (x > y ? x : y)
                          : static_cast<uint64_t>(sx(x) > sx(y) ? sx(x) : sx(y));
                else
                    r = u ? (x < y ? x : y)
                          : static_cast<uint64_t>(sx(x) < sx(y) ? sx(x) : sx(y));
                set_velem(pout, esize, i, r & emask);
            }
            if (!q) pout.hi = 0;
            vreg[rd] = pout;
            return;
        }

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
                // 0x06 is the strict comparison and 0x07 the inclusive one -- the
                // other way round from the order they read in the manual's list, and
                // easy to transcribe backwards.
                case 0x06: r = u ? ((x > y) ? emask : 0)                         // CMHI / CMGT
                                 : ((sx(x) > sx(y)) ? emask : 0); break;
                case 0x07: r = u ? ((x >= y) ? emask : 0)                        // CMHS / CMGE
                                 : ((sx(x) >= sx(y)) ? emask : 0); break;
                case 0x08: {                                                     // USHL / SSHL
                    // The shift amount is a *signed* byte in the matching lane of
                    // the second operand: negative means shift right.
                    const int8_t sh = static_cast<int8_t>(y & 0xFF);
                    if (sh >= 0) r = (sh >= static_cast<int>(esize * 8)) ? 0 : (x << sh);
                    else {
                        const unsigned k = static_cast<unsigned>(-sh);
                        if (u) r = (k >= esize * 8) ? 0 : (x >> k);
                        else {
                            const int64_t sv = sx(x);
                            r = static_cast<uint64_t>(sv >> (k >= esize * 8 ? esize * 8 - 1 : k));
                        }
                    }
                    break;
                }
                case 0x0E: r = u ? (x > y ? x - y : y - x)                       // UABD / SABD
                                 : static_cast<uint64_t>(sx(x) > sx(y) ? sx(x) - sx(y)
                                                                       : sx(y) - sx(x)); break;
                // MUL / PMUL, MLA / MLS, and SABA / UABA -- the three that read Rd's
                // existing value as an operand rather than only writing it. `out` is a
                // fresh register, so vreg[rd] still holds what it had.
                case 0x13:
                    if (!u) { r = x * y; }                                        // MUL
                    else {                                                       // PMUL (8-bit only)
                        if (esize != 1) { ok = false; break; }
                        uint64_t p = 0;
                        for (unsigned k = 0; k < 8; ++k) if ((y >> k) & 1) p ^= x << k;
                        r = p;
                    }
                    break;
                case 0x12: {                                                     // MLA / MLS
                    const uint64_t acc = velem(vreg[rd], esize, i);
                    r = u ? (acc - x * y) : (acc + x * y);
                    break;
                }
                case 0x0F: {                                                     // SABA / UABA
                    const uint64_t acc = velem(vreg[rd], esize, i);
                    const uint64_t d = u ? (x > y ? x - y : y - x)
                                         : static_cast<uint64_t>(sx(x) > sx(y) ? sx(x) - sx(y)
                                                                               : sx(y) - sx(x));
                    r = acc + d;
                    break;
                }
                // The saturating add and subtract, which unlike everything above here do
                // have a 64-bit element form -- so they cannot be computed one width up and
                // clamped. At 64 bits the overflow test is the classic sign comparison; at
                // the narrower widths clamping the wide result is simpler and equivalent.
                case 0x01: case 0x05: {                                          // SQADD/UQADD, SQSUB/UQSUB
                    const bool sub = (opcode == 0x05);
                    const unsigned b = esize * 8;
                    if (u) {
                        if (sub) r = (y > x) ? 0 : x - y;
                        else { const uint64_t s = x + y;
                               r = (b == 64) ? ((s < x) ? ~0ull : s)
                                             : ((s > emask) ? emask : s); }
                    } else if (b == 64) {
                        const int64_t a64 = static_cast<int64_t>(x), b64 = static_cast<int64_t>(y);
                        const int64_t s = sub ? static_cast<int64_t>(x - y)
                                              : static_cast<int64_t>(x + y);
                        const bool ovf = sub ? (((a64 ^ b64) & (a64 ^ s)) < 0)
                                             : (((~(a64 ^ b64)) & (a64 ^ s)) < 0);
                        r = ovf ? (a64 < 0 ? static_cast<uint64_t>(INT64_MIN)
                                           : static_cast<uint64_t>(INT64_MAX))
                                : static_cast<uint64_t>(s);
                    } else {
                        const int64_t s = sub ? sx(x) - sx(y) : sx(x) + sx(y);
                        const int64_t hi = static_cast<int64_t>((1ull << (b - 1)) - 1);
                        const int64_t lo = -static_cast<int64_t>(1ull << (b - 1));
                        r = static_cast<uint64_t>(s > hi ? hi : s < lo ? lo : s);
                    }
                    break;
                }
                // The halving adds and subtracts. No 64-bit form exists, so one width up is
                // always available; SRHADD/URHADD round by adding one before halving.
                case 0x00: case 0x02: case 0x04: {
                    if (esize == 8) { ok = false; break; }
                    const bool sub = (opcode == 0x04), round = (opcode == 0x02);
                    const int64_t s = u ? static_cast<int64_t>(sub ? x - y : x + y + (round ? 1 : 0))
                                        : (sub ? sx(x) - sx(y) : sx(x) + sx(y) + (round ? 1 : 0));
                    r = static_cast<uint64_t>(u ? static_cast<uint64_t>(s) >> 1
                                                : static_cast<uint64_t>(s >> 1));
                    break;
                }
                default: ok = false; break;
            }
            if (ok) set_velem(out, esize, i, r);
        }
        if (ok) { vreg[rd] = out; return; }
    }

    // ---- Advanced SIMD, three registers of different shapes --------------------
    if ((insn & 0x9F200C00u) == 0x0E200000u) {
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0xF;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        // The widening group: the second operand's lanes are half the width of the
        // result's, and `q` selects which half of it to take.
        if (opcode == 0x0 || opcode == 0x1 || opcode == 0x2 || opcode == 0x3 ||
            opcode == 0x5 || opcode == 0x7 || opcode == 0x8 || opcode == 0xA ||
            opcode == 0xC) {
            const unsigned esize = 1u << size;                  // the *narrow* element
            const unsigned lanes = 8u / esize;
            const unsigned base = q ? lanes : 0;
            auto sxn = [&](uint64_t e) {
                if (u) return e;
                const uint64_t s = 1ull << (esize * 8 - 1);
                return (e ^ s) - s;
            };
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t wide = velem(vreg[rn], esize * 2, i);         // already wide
                const uint64_t narrow = sxn(velem(vreg[rm], esize, base + i));
                const uint64_t nn = sxn(velem(vreg[rn], esize, base + i));
                // The accumulating forms read the destination lane, which is
                // already the wide width - the same lane `wide` names for the
                // W-forms, but taken from rd rather than rn.
                const uint64_t acc = velem(vreg[rd], esize * 2, i);
                auto absdiff = [&] {
                    const int64_t d = static_cast<int64_t>(nn) - static_cast<int64_t>(narrow);
                    return static_cast<uint64_t>(d < 0 ? -d : d);
                };
                uint64_t r = 0;
                switch (opcode) {
                    case 0x0: r = nn + narrow; break;                        // SADDL / UADDL
                    case 0x1: r = wide + narrow; break;                      // SADDW / UADDW
                    case 0x2: r = nn - narrow; break;                        // SSUBL / USUBL
                    case 0x3: r = wide - narrow; break;                      // SSUBW / USUBW
                    case 0x5: r = acc + absdiff(); break;                    // SABAL / UABAL
                    case 0x7: r = absdiff(); break;                          // SABDL / UABDL
                    case 0x8: r = acc + nn * narrow; break;                  // SMLAL / UMLAL
                    case 0xA: r = acc - nn * narrow; break;                  // SMLSL / UMLSL
                    case 0xC: r = nn * narrow; break;                        // SMULL / UMULL
                    default: r = 0; break;
                }
                set_velem(out, esize * 2, i, r);
            }
            vreg[rd] = out;
            return;
        }
        if (opcode == 0xE && !u) {                              // PMULL / PMULL2
            // Carry-less multiply: the same shape as an ordinary multiply with XOR
            // where the additions would be. CRC32 and the hash code in a Python
            // build reach it almost immediately.
            const unsigned esize = 1u << size;
            const unsigned lanes = 8u / esize;
            const unsigned base = q ? lanes : 0;                // PMULL2 takes the top half
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t x = velem(vreg[rn], esize, base + i);
                const uint64_t y = velem(vreg[rm], esize, base + i);
                uint64_t lo = 0, hi = 0;
                for (unsigned bit = 0; bit < esize * 8; ++bit) {
                    if (!((y >> bit) & 1)) continue;
                    lo ^= (bit ? (x << bit) : x);
                    if (bit) hi ^= (x >> (64 - bit));
                }
                if (esize == 8) { out.lo = lo; out.hi = hi; }
                else set_velem(out, esize * 2, i, lo);
            }
            vreg[rd] = out;
            return;
        }
    }

    // ---- ZIP / UZP / TRN: the permute group ------------------------------------
    // 0 Q 001110 size 0 Rm 0 opcode 10 Rn Rd
    if ((insn & 0xBF208C00u) == 0x0E000800u) {
        const bool q = (insn >> 30) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 7;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const unsigned esize = 1u << size;
        const unsigned lanes = (q ? 16u : 8u) / esize;
        const V128 a = vreg[rn], b = vreg[rm];
        V128 out{};
        auto pick = [&](unsigned idx) {
            return idx < lanes ? velem(a, esize, idx) : velem(b, esize, idx - lanes);
        };
        bool ok = true;
        for (unsigned i = 0; i < lanes; ++i) {
            uint64_t val = 0;
            switch (opcode) {
                case 1: val = pick(2 * i); break;                          // UZP1: even
                case 5: val = pick(2 * i + 1); break;                      // UZP2: odd
                case 2: val = (i & 1) ? velem(b, esize, i & ~1u)           // TRN1
                                      : velem(a, esize, i);
                        break;
                case 6: val = (i & 1) ? velem(b, esize, i)                 // TRN2
                                      : velem(a, esize, i | 1u);
                        break;
                case 3: val = (i & 1) ? velem(b, esize, i / 2)             // ZIP1
                                      : velem(a, esize, i / 2);
                        break;
                case 7: val = (i & 1) ? velem(b, esize, lanes / 2 + i / 2) // ZIP2
                                      : velem(a, esize, lanes / 2 + i / 2);
                        break;
                default: ok = false; break;
            }
            if (!ok) break;
            set_velem(out, esize, i, val);
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
        // SADDLP/UADDLP (and the accumulating SADALP/UADALP): add each pair of
        // adjacent elements into one element of twice the width. gcc's cc1 uses
        // it as the middle of a popcount reduction -- CNT, then this, then ADDV.
        // size==11 is unallocated: the widest source lane is 32 bits.
        if ((opcode == 0x02 || opcode == 0x06) && size != 3) {
            const unsigned out_lanes = lanes / 2;
            V128 out = (opcode == 0x06) ? vreg[rd] : V128{};
            if (!q) out.hi = 0;
            for (unsigned i = 0; i < out_lanes; ++i) {
                auto wide = [&](uint64_t e) -> uint64_t {
                    if (u) return e;
                    const uint64_t s = 1ull << (esize * 8 - 1);
                    return static_cast<uint64_t>(static_cast<int64_t>((e ^ s) - s));
                };
                const uint64_t sum = wide(velem(vreg[rn], esize, 2 * i)) +
                                     wide(velem(vreg[rn], esize, 2 * i + 1));
                const uint64_t acc = (opcode == 0x06) ? velem(out, esize * 2, i) : 0;
                set_velem(out, esize * 2, i, acc + sum);
            }
            vreg[rd] = out; return;
        }
        // SHLL / SHLL2: widen the low (or, with Q, high) half and shift each
        // element left by exactly its old width.  gcc's vectorised loops pair
        // it with UXTL to spread 32-bit counters into 64-bit accumulators.
        if (u && opcode == 0x13 && size != 3) {
            const unsigned nlanes = 8u / esize;
            const unsigned base = q ? nlanes : 0;
            V128 out{};
            for (unsigned i = 0; i < nlanes; ++i)
                set_velem(out, esize * 2, i,
                          velem(vreg[rn], esize, base + i) << (esize * 8));
            vreg[rd] = out; return;
        }
        // The compares against zero. The opcode/U table, verified against a
        // disassembler rather than recalled -- an earlier version had 9/U=0 as
        // CMGE and A/U=0 as CMGT, which are answers to *different questions*:
        //     opcode 8:  U=0 CMGT   U=1 CMGE
        //     opcode 9:  U=0 CMEQ   U=1 CMLE
        //     opcode A:  U=0 CMLT   (U=1 unallocated)
        if (opcode == 0x08 || opcode == 0x09 || opcode == 0x0A) {
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t e = velem(vreg[rn], esize, i);
                const uint64_t s = 1ull << (esize * 8 - 1);
                const int64_t se = static_cast<int64_t>((e ^ s) - s);
                bool t;
                if (opcode == 0x08)      t = u ? (se >= 0) : (se > 0);           // CMGE / CMGT
                else if (opcode == 0x09) t = u ? (se <= 0) : (se == 0);          // CMLE / CMEQ
                else                     t = (se < 0);                           // CMLT
                set_velem(out, esize, i, t ? emask : 0);
            }
            vreg[rd] = out; return;
        }
        if (opcode == 0x0B) {                                   // ABS / NEG (vector)
            V128 out{};
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t e = velem(vreg[rn], esize, i);
                const uint64_t s = 1ull << (esize * 8 - 1);
                const int64_t se = static_cast<int64_t>((e ^ s) - s);
                const int64_t v = u ? -se : (se < 0 ? -se : se);
                set_velem(out, esize, i, static_cast<uint64_t>(v) & emask);
            }
            vreg[rd] = out; return;
        }
        // REV64 / REV32 / REV16: reverse the byte order of each element within a
        // container of the given width. `size` is the element size and the opcode
        // picks the container.
        if (opcode == 0x00 || opcode == 0x01) {
            const unsigned container = (opcode == 0x00) ? (u ? 32u : 64u) : 16u;
            const unsigned per = container / (esize * 8);
            V128 out{};
            for (unsigned g = 0; g < lanes / per; ++g)
                for (unsigned k = 0; k < per; ++k)
                    set_velem(out, esize, g * per + k, velem(vreg[rn], esize, g * per + (per - 1 - k)));
            vreg[rd] = out; return;
        }
        // XTN / XTN2: narrow each element to half its width, keeping the low bits.
        // XTN2 writes the top half of the destination and leaves the bottom alone.
        if (opcode == 0x12 && !u) {
            const unsigned out_lanes = 8u / esize;
            V128 out = q ? vreg[rd] : V128{};
            for (unsigned i = 0; i < out_lanes; ++i)
                set_velem(out, esize, q ? out_lanes + i : i, velem(vreg[rn], esize * 2, i));
            vreg[rd] = out; return;
        }
        if (opcode == 0x05 && u) {                              // NOT / MVN (size==00)
            V128 out = {~vreg[rn].lo, ~vreg[rn].hi};
            if (!q) out.hi = 0;
            vreg[rd] = out; return;
        }
    }

    // ---- Advanced SIMD scalar three-same: the integer forms ---------------------
    //
    // `add d0, d0, d1` -- the tail of cc1's popcount loop, folding two ADDV results.
    // The vector three-same group above at 0x0E200400 with bit 28 set; the integer
    // forms are allocated only at size==11, a single 64-bit lane.
    if ((insn & 0xDF200400u) == 0x5E200400u && ((insn >> 22) & 3) == 3 &&
        ((insn >> 10) & 1)) {
        const bool u = (insn >> 29) & 1;
        const unsigned opcode = (insn >> 11) & 0x1F;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F,
                       rd = insn & 0x1F;
        const uint64_t x = vreg[rn].lo, y = vreg[rm].lo;
        const int64_t sx = static_cast<int64_t>(x), sy = static_cast<int64_t>(y);
        uint64_t r;
        bool ok = true;
        switch (opcode) {
            case 0x10: r = u ? (x - y) : (x + y); break;                 // SUB / ADD
            case 0x11: r = u ? ((x == y) ? ~0ull : 0)                    // CMEQ
                             : (((x & y) != 0) ? ~0ull : 0); break;      // CMTST
            case 0x06: r = (u ? (x > y) : (sx > sy)) ? ~0ull : 0; break; // CMHI / CMGT
            case 0x07: r = (u ? (x >= y) : (sx >= sy)) ? ~0ull : 0; break; // CMHS / CMGE
            case 0x08: {                                                 // USHL / SSHL
                const int8_t sh = static_cast<int8_t>(y & 0xFF);
                if (sh >= 0) r = (sh >= 64) ? 0 : (x << sh);
                else {
                    const unsigned k = static_cast<unsigned>(-sh);
                    if (u) r = (k >= 64) ? 0 : (x >> k);
                    else r = static_cast<uint64_t>(sx >> (k >= 64 ? 63 : k));
                }
                break;
            }
            default: ok = false; r = 0; break;
        }
        if (ok) { vreg[rd] = {r, 0}; return; }
    }

    // ---- Advanced SIMD scalar two-register misc: the integer forms --------------
    //
    // `cmge d0, d0, #0` -- gcc's cc1 branches on it inside the C preprocessor's
    // search loops. Same opcode table as the vector compares above, but scalar,
    // and only size==11 (a single 64-bit lane) is allocated. Handled *before* the
    // FP-conversion block below because that one keys on bit 23 being clear, and
    // these have it set.
    if ((insn & 0xDF3E0C00u) == 0x5E200800u && ((insn >> 22) & 3) == 3) {
        const bool u = (insn >> 29) & 1;
        const unsigned opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const int64_t se = static_cast<int64_t>(vreg[rn].lo);
        if (opcode == 0x08 || opcode == 0x09 || (opcode == 0x0A && !u)) {
            bool t;
            if (opcode == 0x08)      t = u ? (se >= 0) : (se > 0);   // CMGE / CMGT
            else if (opcode == 0x09) t = u ? (se <= 0) : (se == 0);  // CMLE / CMEQ
            else                     t = (se < 0);                   // CMLT
            vreg[rd] = {t ? ~0ull : 0ull, 0}; return;
        }
        if (opcode == 0x0B) {                                        // ABS / NEG
            vreg[rd] = {static_cast<uint64_t>(u ? -se : (se < 0 ? -se : se)), 0};
            return;
        }
    }

    // ---- Advanced SIMD scalar two-register misc: the FP/integer conversions ----
    //
    // `ucvtf d0, d8` -- an integer that is already in a vector register turned into a
    // double in place. It is not the `ucvtf d0, x8` form (which is the FP/integer
    // group below and was implemented long ago); the operand never passes through a
    // general register. CPython emits it converting a 64-bit count to a float.
    //
    // Encoding: 01 U 11110 0 sz 10000 opcode 10 Rn Rd. Bit 28 is what keeps the
    // *vector* two-register-misc group (01110) from matching.
    if ((insn & 0xDFBE0C00u) == 0x5E200800u) {
        const bool u = (insn >> 29) & 1, dbl = (insn >> 22) & 1;
        const unsigned opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        auto put = [&](double v) {
            if (dbl) { uint64_t b; std::memcpy(&b, &v, 8); vreg[rd] = {b, 0}; }
            else { const float f = static_cast<float>(v); uint32_t b;
                   std::memcpy(&b, &f, 4); vreg[rd] = {b, 0}; }
        };
        auto get = [&]() -> double {
            if (dbl) { double d; std::memcpy(&d, &vreg[rn].lo, 8); return d; }
            float f; const uint32_t b = static_cast<uint32_t>(vreg[rn].lo);
            std::memcpy(&f, &b, 4);
            return f;
        };
        if (opcode == 0x1D) {                                   // SCVTF / UCVTF
            if (dbl) {
                const uint64_t bits = vreg[rn].lo;
                put(u ? static_cast<double>(bits)
                      : static_cast<double>(static_cast<int64_t>(bits)));
            } else {
                const uint32_t bits = static_cast<uint32_t>(vreg[rn].lo);
                put(u ? static_cast<double>(bits)
                      : static_cast<double>(static_cast<int32_t>(bits)));
            }
            return;
        }
        if (opcode == 0x1B) {                                   // FCVTZS / FCVTZU
            // Toward zero, and saturating: C++'s conversion of an out-of-range double
            // to an integer is undefined, where AArch64's is defined to clamp. A guest
            // that converts a huge float would otherwise get whatever the host's
            // instruction happened to leave behind.
            const double v = get();
            const unsigned bits = dbl ? 64 : 32;
            if (u) {
                const double hi = std::ldexp(1.0, static_cast<int>(bits));
                const uint64_t r = !(v > 0) ? 0
                                 : (v >= hi ? (bits == 64 ? ~0ull : 0xFFFFFFFFull)
                                            : static_cast<uint64_t>(v));
                vreg[rd] = {dbl ? r : (r & 0xFFFFFFFFull), 0};
            } else {
                const double hi = std::ldexp(1.0, static_cast<int>(bits - 1));
                const int64_t r = !(v > -hi - 1) ? (bits == 64 ? INT64_MIN : INT32_MIN)
                                : (v >= hi ? (bits == 64 ? INT64_MAX : INT32_MAX)
                                           : static_cast<int64_t>(v));
                vreg[rd] = {dbl ? static_cast<uint64_t>(r)
                                : (static_cast<uint64_t>(r) & 0xFFFFFFFFull), 0};
            }
            return;
        }
        fail("unimplemented scalar two-register misc", insn);
    }

    // ---- Advanced SIMD scalar pairwise: ADDP Dd, Vn.2D and the FP reductions ---
    //
    // The last step of a vectorised reduction: the loop leaves a partial sum in each
    // lane and this folds the two halves together. clang emits it for something as
    // ordinary as `for (i) total += a[i]` over longs, which is how it turned up --
    // in a four-line test program, not in anything exotic.
    if ((insn & 0xDF3E0C00u) == 0x5E300800u) {
        const bool u = (insn >> 29) & 1;
        const unsigned size = (insn >> 22) & 3, opcode = (insn >> 12) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const V128 n = vreg[rn];
        if (!u && opcode == 0x1B && size == 3) {                // ADDP Dd, Vn.2D
            vreg[rd] = {n.lo + n.hi, 0};
            return;
        }
        if (u) {
            // The FP forms. `size` bit 0 picks single or double; bit 1 selects the
            // MIN group, which is why FMAXP and FMINP share an opcode.
            const bool dbl = (size & 1) != 0;
            const bool is_min = (size & 2) != 0;
            auto f = [&](uint64_t bits) -> double {
                if (dbl) { double d; std::memcpy(&d, &bits, 8); return d; }
                float g; const uint32_t b = static_cast<uint32_t>(bits);
                std::memcpy(&g, &b, 4);
                return g;
            };
            const uint64_t a = dbl ? n.lo : (n.lo & 0xFFFFFFFFull);
            const uint64_t b = dbl ? n.hi : ((n.lo >> 32) & 0xFFFFFFFFull);
            double r0;
            if (opcode == 0x0D) r0 = f(a) + f(b);                       // FADDP
            else if (opcode == 0x0C) r0 = is_min ? (f(a) < f(b) ? f(a) : f(b))
                                                 : (f(a) > f(b) ? f(a) : f(b));  // FMAXNMP/FMINNMP
            else if (opcode == 0x0F) r0 = is_min ? (f(a) < f(b) ? f(a) : f(b))
                                                 : (f(a) > f(b) ? f(a) : f(b));  // FMAXP/FMINP
            else fail("unimplemented scalar pairwise", insn);
            if (dbl) { uint64_t b; std::memcpy(&b, &r0, 8); vreg[rd] = {b, 0}; }
            else { const float g = static_cast<float>(r0); uint32_t b;
                   std::memcpy(&b, &g, 4); vreg[rd] = {b, 0}; }
            return;
        }
        fail("unimplemented scalar pairwise", insn);
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

    // ---- MOVI / MVNI / ORR / BIC (vector, immediate) ----------------------------
    // One encoding group, four operations: cmode<0> with a 32- or 16-bit shifted
    // immediate selects ORR (op=0) or BIC (op=1) *onto the existing register*,
    // which the first version of this block executed as MOVI/MVNI - replacing
    // glibc strlen's NUL mask with a constant, so every strlen came out short.
    if ((insn & 0x9FF80400u) == 0x0F000400u) {
        const bool q = (insn >> 30) & 1, op = (insn >> 29) & 1;
        const unsigned cmode = (insn >> 12) & 0xF, rd = insn & 0x1F;
        const uint64_t imm8 = (((insn >> 16) & 7) << 5) | ((insn >> 5) & 0x1F);
        uint64_t imm64 = 0;
        bool logical = false;  // ORR/BIC rather than MOVI/MVNI
        bool invert = op;      // MVNI / BIC complement the expanded immediate
        if ((cmode & 0x8) == 0) {                               // 32-bit, shifted
            uint64_t v32 = (imm8 << (((cmode >> 1) & 3) * 8)) & 0xFFFFFFFFull;
            imm64 = v32 | (v32 << 32);
            logical = (cmode & 1) != 0;
        } else if ((cmode & 0xC) == 0x8) {                      // 16-bit, shifted
            const uint64_t v16 = (imm8 << (((cmode >> 1) & 1) * 8)) & 0xFFFF;
            for (int i = 0; i < 4; ++i) imm64 |= v16 << (i * 16);
            logical = (cmode & 1) != 0;
        } else if ((cmode & 0xE) == 0xC) {                      // 32-bit, shifting ones (MSL)
            const unsigned sh = (cmode & 1) ? 16 : 8;
            uint64_t v32 = ((imm8 << sh) | ((1ull << sh) - 1)) & 0xFFFFFFFFull;
            imm64 = v32 | (v32 << 32);
        } else if (cmode == 0xE && op) {                        // MOVI Dd/2D: bit per byte
            for (int i = 0; i < 8; ++i) if ((imm8 >> i) & 1) imm64 |= 0xFFull << (i * 8);
            invert = false;
        } else if (cmode == 0xE) {                              // 8-bit replicate
            for (int i = 0; i < 8; ++i) imm64 |= imm8 << (i * 8);
        } else {                                                // cmode 0xF: FMOV immediate
            if (op && !q) fail("reserved modified-immediate form", insn);
            const uint64_t s = imm8 >> 7, b6 = (imm8 >> 6) & 1;
            if (op) {                                           // FMOV Vd.2D (VFPExpandImm 64)
                imm64 = (s << 63) | ((b6 ^ 1) << 62) |
                        ((b6 ? 0xFFull : 0) << 54) | ((imm8 & 0x3F) << 48);
            } else {                                            // FMOV Vd.<T>s (VFPExpandImm 32)
                const uint32_t v32 = static_cast<uint32_t>(
                    (s << 31) | ((b6 ^ 1) << 30) | ((b6 ? 0x1Fu : 0) << 25) |
                    ((imm8 & 0x3F) << 19));
                imm64 = (static_cast<uint64_t>(v32) << 32) | v32;
            }
            invert = false;
        }
        if (invert && !logical) imm64 = ~imm64;                 // MVNI
        V128 out;
        if (logical) {
            const V128 d = vreg[rd];
            if (op) out = {d.lo & ~imm64, d.hi & ~imm64};       // BIC
            else out = {d.lo | imm64, d.hi | imm64};            // ORR
        } else {
            out = {imm64, imm64};
        }
        if (!q) out.hi = 0;
        vreg[rd] = out;
        return;
    }

    // ---- Advanced SIMD, shift by immediate -------------------------------------
    // immh is doing double duty: it selects the element size *and* carries the top
    // of the shift amount. immh == 0 is the MOVI group above, which is why that has
    // to be tested first.
    if (((insn & 0x9F800400u) == 0x0F000400u ||
         (insn & 0xDF800400u) == 0x5F000400u) &&                // the scalar sibling (SSHR Dd, Dn, #n)
        ((insn >> 19) & 0xF) != 0) {
        const bool scalar = ((insn >> 28) & 1) != 0;
        const bool q = (insn >> 30) & 1, u = (insn >> 29) & 1;
        const unsigned immh = (insn >> 19) & 0xF, immb = (insn >> 16) & 7;
        const unsigned opcode = (insn >> 11) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        unsigned size = 3;
        while (size && !((immh >> size) & 1)) --size;
        const unsigned esize = 1u << size;
        const unsigned bits = esize * 8;
        const unsigned imm = (immh << 3) | immb;
        // Scalar covers only the plain shift family here; the saturating
        // narrows and widening forms keep failing loudly until needed.
        if (scalar && !(opcode <= 0x06 || opcode == 0x08 || opcode == 0x0A))
            fail("unimplemented scalar shift-immediate form", insn);

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
        const unsigned lanes = scalar ? 1u : (q ? 16u : 8u) / esize;
        V128 out{};
        if (opcode == 0x0A) {                                   // SHL
            const unsigned shift = imm - bits;
            for (unsigned i = 0; i < lanes; ++i)
                set_velem(out, esize, i, velem(vreg[rn], esize, i) << shift);
            vreg[rd] = out; return;
        }
        // The right-shift amount, for every opcode that shifts right. `imm` counts *up*
        // from the element size, so the shift is what is left over; a shift of `bits` is
        // encoded and means "shift everything out", which C++ would make undefined, so the
        // arithmetic forms clamp to bits-1 (the sign bit smeared, which is the same answer)
        // and the logical ones are given zero directly.
        const unsigned rshift = 2 * bits - imm;
        const uint64_t emask = bits == 64 ? ~0ull : ((1ull << bits) - 1);
        // One element, read as signed or unsigned according to U.
        auto lane = [&](unsigned r, unsigned es, unsigned i) -> int64_t {
            const uint64_t e = velem(vreg[r], es, i);
            if (u) return static_cast<int64_t>(e);
            const unsigned b = es * 8;
            const uint64_t s = 1ull << (b - 1);
            return static_cast<int64_t>((e ^ s) - s);
        };
        // A right shift by `sh`, optionally rounding to nearest (add half first), on a
        // value already widened to int64_t. Rounding is *before* the shift, which is why it
        // has to happen at the wide width: at the narrow one the addend would overflow.
        auto shr = [&](int64_t v, unsigned sh, bool round) -> uint64_t {
            if (round && sh > 0 && sh < 64) v += static_cast<int64_t>(1ull << (sh - 1));
            if (sh >= 64) return u ? 0ull : static_cast<uint64_t>(v >> 63);
            return u ? (static_cast<uint64_t>(v) >> sh) : static_cast<uint64_t>(v >> sh);
        };

        if (opcode == 0x00 || opcode == 0x02 || opcode == 0x04 || opcode == 0x06) {
            // SSHR/USHR, SSRA/USRA (accumulate), SRSHR/URSHR (round), SRSRA/URSRA (both).
            const bool round = (opcode & 4) != 0, acc = (opcode & 2) != 0;
            for (unsigned i = 0; i < lanes; ++i) {
                uint64_t e = shr(lane(rn, esize, i), rshift >= bits && !round ? bits - 1 : rshift, round);
                if (acc) e += velem(vreg[rd], esize, i);
                set_velem(out, esize, i, e & emask);
            }
            vreg[rd] = out; return;
        }
        if (u && (opcode == 0x08 || opcode == 0x0A)) {
            // SRI / SLI: shift and *insert*, so the bits the shift vacates keep whatever
            // the destination already had. The only two opcodes here that read Rd for its
            // value rather than to accumulate.
            const bool left = (opcode == 0x0A);
            const unsigned sh = left ? imm - bits : rshift;
            for (unsigned i = 0; i < lanes; ++i) {
                const uint64_t src = velem(vreg[rn], esize, i), dst = velem(vreg[rd], esize, i);
                if (sh >= bits) { set_velem(out, esize, i, dst); continue; }
                const uint64_t keep = left ? ((1ull << sh) - 1) : ~((emask >> sh)) & emask;
                const uint64_t moved = left ? (src << sh) : (src >> sh);
                set_velem(out, esize, i, ((dst & keep) | moved) & emask);
            }
            vreg[rd] = out; return;
        }
        if (opcode >= 0x10 && opcode <= 0x13) {
            // The narrowing right shifts. `size` here is the *destination* element size, so
            // the source elements are twice as wide and there are always 8/esize of them --
            // a full 128-bit source producing a 64-bit half. Q selects which half of the
            // destination gets it, which is what the `2` in SHRN2 means; the other half is
            // left alone rather than zeroed.
            //
            //   10  SHRN / SQSHRUN      11  RSHRN / SQRSHRUN
            //   12  SQSHRN / UQSHRN     13  SQRSHRN / UQRSHRN
            //
            // Saturation and signedness do not line up the way U alone suggests: 10/11 with
            // U=1 read *signed* and saturate to *unsigned*, which is the "UN" in SQSHRUN.
            const bool round = (opcode & 1) != 0;
            const bool saturating = opcode >= 0x12 || u;
            const bool src_signed = (opcode >= 0x12) ? !u : true;   // 10/11 U=1: signed in
            const bool dst_signed = (opcode >= 0x12) && !u;
            const unsigned sesize = esize * 2;
            const unsigned nlanes = 8u / esize;
            const int64_t smax = static_cast<int64_t>((1ull << (bits - 1)) - 1);
            const int64_t smin = -static_cast<int64_t>(1ull << (bits - 1));
            const uint64_t umax = emask;
            V128 res = vreg[rd];                      // the untouched half survives
            for (unsigned i = 0; i < nlanes; ++i) {
                uint64_t raw = velem(vreg[rn], sesize, i);
                int64_t v;
                if (src_signed && sesize < 8) {
                    const uint64_t s = 1ull << (sesize * 8 - 1);
                    v = static_cast<int64_t>((raw ^ s) - s);
                } else {
                    v = static_cast<int64_t>(raw);
                }
                if (round && rshift > 0 && rshift < 64) v += static_cast<int64_t>(1ull << (rshift - 1));
                uint64_t narrowed;
                if (src_signed) narrowed = static_cast<uint64_t>(v >> (rshift >= 64 ? 63 : rshift));
                else            narrowed = static_cast<uint64_t>(v) >> (rshift >= 64 ? 63 : rshift);
                if (saturating) {
                    if (dst_signed) {
                        const int64_t sv = static_cast<int64_t>(narrowed);
                        narrowed = static_cast<uint64_t>(sv > smax ? smax : sv < smin ? smin : sv);
                    } else if (src_signed) {                       // signed in, unsigned out
                        const int64_t sv = static_cast<int64_t>(narrowed);
                        narrowed = sv < 0 ? 0ull : (static_cast<uint64_t>(sv) > umax ? umax : static_cast<uint64_t>(sv));
                    } else {
                        if (narrowed > umax) narrowed = umax;
                    }
                }
                set_velem(res, esize, (q ? nlanes : 0) + i, narrowed & emask);
            }
            vreg[rd] = res; return;
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
                    // FCVT: the low two bits of the opcode are the *destination*
                    // type, not the source — `fcvt s0, d0` is opcode 000100 with
                    // type=01. Reading it the other way round converts the wrong
                    // direction and produces a number, which is the worst outcome.
                    case 0x4: {                                             // FCVT to single
                        const float f = static_cast<float>(rdf(rn));
                        uint32_t b; std::memcpy(&b, &f, 4);
                        vreg[rd] = {b, 0}; return;
                    }
                    case 0x5: {                                             // FCVT to double
                        const double d = rdf(rn);
                        uint64_t b; std::memcpy(&b, &d, 8);
                        vreg[rd] = {b, 0}; return;
                    }
                    // The rounding family. All of them round to an integral value
                    // and keep the floating-point type.
                    case 0x8: wrf(rd, std::nearbyint(rdf(rn))); return;     // FRINTN
                    case 0x9: wrf(rd, std::ceil(rdf(rn))); return;          // FRINTP
                    case 0xA: wrf(rd, std::floor(rdf(rn))); return;         // FRINTM
                    case 0xB: wrf(rd, std::trunc(rdf(rn))); return;         // FRINTZ
                    case 0xC: wrf(rd, std::round(rdf(rn))); return;         // FRINTA
                    case 0xE: case 0xF: wrf(rd, std::nearbyint(rdf(rn))); return;  // FRINTX/I
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

        // Conversions between FP and **fixed**-point. The same four operations as
        // the integer group below, distinguished only by bit 21 being 0, with a
        // scale field where that group has zeros: the value is read or written as
        // if the binary point sat `fbits` places up from the bottom.
        //
        // CPython reaches this converting a float timeout into a lock deadline, so
        // it turns up the moment a program waits on anything.
        if ((insn & 0x5F200000u) == 0x1E000000u) {
            const bool sf = (insn >> 31) & 1;
            const unsigned rmode = (insn >> 19) & 3, opcode = (insn >> 16) & 7;
            const unsigned scale = (insn >> 10) & 0x3F;
            const unsigned fbits = 64 - scale;               // 1..64
            // ldexp rather than a shift: fbits reaches 64, and 1ull << 64 is
            // undefined -- on x86 it is a shift by 0, which would make the scale
            // vanish and the answer merely wrong.
            const double factor = std::ldexp(1.0, static_cast<int>(fbits));
            if (rmode == 0 && (opcode == 2 || opcode == 3)) {    // SCVTF / UCVTF
                const double raw = (opcode == 2)
                    ? static_cast<double>(sf ? static_cast<int64_t>(xr(rn))
                                             : static_cast<int64_t>(static_cast<int32_t>(wr(rn))))
                    : static_cast<double>(sf ? xr(rn) : static_cast<uint64_t>(wr(rn)));
                wrf(rd, raw / factor);
                return;
            }
            if (rmode == 3 && (opcode == 0 || opcode == 1)) {    // FCVTZS / FCVTZU
                const double val = rdf(rn) * factor;
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
            // FCVT{N,P,M,Z,A}{S,U}: one instruction per rounding mode, which is
            // why the mode is in the encoding rather than in FPCR.  `rmode`
            // selects it for opcode 0/1; opcode 4/5 is the "A" form (ties away
            // from zero) and ignores rmode.  Only the Z pair used to be here,
            // and clang's own code reaches FCVTPU within five million
            // instructions - LLVM rounds sizes up all over.
            if (opcode == 0 || opcode == 1 || opcode == 4 || opcode == 5) {
                const bool is_signed = (opcode & 1) == 0;
                const double val = rdf(rn);
                double r;
                if (opcode >= 4)      r = std::round(val);    // A: ties away from zero
                else if (rmode == 0)  r = std::nearbyint(val);// N: ties to even
                else if (rmode == 1)  r = std::ceil(val);     // P: toward +infinity
                else if (rmode == 2)  r = std::floor(val);    // M: toward -infinity
                else                  r = std::trunc(val);    // Z: toward zero

                // ARM saturates rather than leaving the result undefined, and
                // maps NaN to zero.  Doing that here rather than casting keeps
                // an out-of-range convert from being host-defined behaviour -
                // which on x86 yields 0x8000000000000000 and looks like data.
                if (std::isnan(r)) {
                    if (sf) setx(rd, 0); else setw(rd, 0);
                } else if (is_signed) {
                    const double lo = sf ? -9223372036854775808.0 : -2147483648.0;
                    const double hi = sf ?  9223372036854775808.0 :  2147483648.0;
                    int64_t iv;
                    if (r <= lo)      iv = sf ? INT64_MIN : INT32_MIN;
                    else if (r >= hi) iv = sf ? INT64_MAX : INT32_MAX;
                    else              iv = static_cast<int64_t>(r);
                    if (sf) setx(rd, static_cast<uint64_t>(iv));
                    else setw(rd, static_cast<uint32_t>(static_cast<int32_t>(iv)));
                } else {
                    const double hi = sf ? 18446744073709551616.0 : 4294967296.0;
                    uint64_t uv;
                    if (r <= 0)       uv = 0;
                    else if (r >= hi) uv = sf ? UINT64_MAX : UINT32_MAX;
                    else              uv = static_cast<uint64_t>(r);
                    if (sf) setx(rd, uv); else setw(rd, static_cast<uint32_t>(uv));
                }
                return;
            }
        }
    }

    if (on_undefined && on_undefined(insn, pc - 4)) return;
    fail("unimplemented FP/SIMD instruction", insn);
}

}  // namespace a64
