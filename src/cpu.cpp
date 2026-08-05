// The A64 interpreter. Organised in the order the ARM ARM organises the encoding
// space, so an instruction can be located by the group name the manual uses:
// bits 28..25 pick the group, then each group sub-decodes on its own fields.
#include "cpu.h"
#include <cstdio>

namespace a64 {

void Cpu::fail(const std::string& why, uint32_t insn) const {
    char buf[192];
    std::snprintf(buf, sizeof buf, "%s: %08X at PC %016llX", why.c_str(), insn,
                  static_cast<unsigned long long>(pc - 4));
    throw CpuError{buf, pc - 4, insn};
}

// ---- arithmetic helpers ----------------------------------------------------

namespace {

// Byte reversal and the high half of a 64x64 product, written out rather than taken from
// the compiler. `__builtin_bswap*` and `__int128` are GCC/Clang extensions, and MSVC has
// neither — it was the only thing standing between this and building with cl.exe, which
// CMakeLists.txt already claimed to support. Both compile to the same one or two
// instructions everywhere; REV and UMULH are not where an interpreter spends its time.
inline uint32_t bswap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0x0000FF00u) | ((v << 8) & 0x00FF0000u) | (v << 24);
}
inline uint64_t bswap64(uint64_t v) {
    return (static_cast<uint64_t>(bswap32(static_cast<uint32_t>(v))) << 32)
         | bswap32(static_cast<uint32_t>(v >> 32));
}
// Schoolbook 32x32 partial products. `mid` carries the low half's overflow into the high.
inline uint64_t umulh(uint64_t a, uint64_t b) {
    const uint64_t al = a & 0xFFFFFFFFu, ah = a >> 32;
    const uint64_t bl = b & 0xFFFFFFFFu, bh = b >> 32;
    const uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    const uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFFu) + (hl & 0xFFFFFFFFu);
    return hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}
// Signed from unsigned: a signed operand is its unsigned value minus 2^64, so each
// negative one subtracts the *other* operand from the high half. The 2^128 term when both
// are negative falls off the top.
inline uint64_t smulh(int64_t a, int64_t b) {
    uint64_t h = umulh(static_cast<uint64_t>(a), static_cast<uint64_t>(b));
    if (a < 0) h -= static_cast<uint64_t>(b);
    if (b < 0) h -= static_cast<uint64_t>(a);
    return h;
}

struct AddOut { uint64_t v; bool carry, ovf; };

// The architecture's AddWithCarry, which is where NZCV comes from. Subtraction is
// the same primitive with the operand inverted and carry in set, which is why SUBS
// leaves C set when there is *no* borrow — a sign convention that trips everyone
// up once and then never again.
AddOut addc(uint64_t a, uint64_t b, bool cin, bool is64) {
    if (is64) {
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

uint64_t ror64(uint64_t v, unsigned amount, unsigned width) {
    amount %= width;
    if (!amount) return v;
    const uint64_t mask = width == 64 ? ~0ull : ((1ull << width) - 1);
    v &= mask;
    return ((v >> amount) | (v << (width - amount))) & mask;
}

uint64_t shift_reg(uint64_t v, unsigned type, unsigned amount, bool is64) {
    const unsigned width = is64 ? 64 : 32;
    if (!is64) v &= 0xFFFFFFFFull;
    switch (type) {
        case 0: return amount >= width ? 0 : (v << amount);                      // LSL
        case 1: return amount >= width ? 0 : (v >> amount);                      // LSR
        case 2: {                                                                // ASR
            const int64_t s = is64 ? static_cast<int64_t>(v)
                                   : static_cast<int32_t>(static_cast<uint32_t>(v));
            if (amount >= width) return s < 0 ? ~0ull : 0;
            return static_cast<uint64_t>(s >> amount);
        }
        default: return ror64(v, amount, width);                                 // ROR
    }
}

// The register-extend forms of ADD/SUB: take a sub-field of the source, sign- or
// zero-extend it, then shift left. This is how `add x0, x1, w2, uxtw #2` works.
uint64_t extend_reg(uint64_t v, unsigned option, unsigned shift) {
    switch (option & 7) {
        case 0: v = static_cast<uint8_t>(v); break;                              // UXTB
        case 1: v = static_cast<uint16_t>(v); break;                             // UXTH
        case 2: v = static_cast<uint32_t>(v); break;                             // UXTW
        case 3: break;                                                           // UXTX
        case 4: v = static_cast<uint64_t>(static_cast<int8_t>(v)); break;        // SXTB
        case 5: v = static_cast<uint64_t>(static_cast<int16_t>(v)); break;       // SXTH
        case 6: v = static_cast<uint64_t>(static_cast<int32_t>(v)); break;       // SXTW
        default: break;                                                          // SXTX
    }
    return v << shift;
}

uint64_t sign_extend(uint64_t v, unsigned bits) {
    if (bits >= 64) return v;
    const uint64_t m = 1ull << (bits - 1);
    return (v ^ m) - m;
}

}  // namespace

// DecodeBitMasks, straight from the ARM pseudocode, returning *both* masks.
//
// The logical-immediate instructions only need wmask: a run of ones, rotated,
// replicated. The bitfield instructions need tmask as well, and that is not a
// detail — the first hand-rolled version of this approximated the pair with one
// mask, which is right whenever imms >= immr and quietly turns `lsl x0, x0, #7`
// into a rotate when it is not. The differential test caught it on the first run;
// nothing about the wrong answer looked wrong.
//
// `immediate` distinguishes the two callers: the all-ones encoding is reserved for
// a logical immediate but perfectly legal for a bitfield op.
bool decode_bit_masks(bool n, unsigned imms, unsigned immr, bool immediate, bool is64,
                      uint64_t* wmask, uint64_t* tmask) {
    if (n && !is64) return false;
    // len = HighestSetBit(immN:NOT(imms)) over a *seven*-bit value: N is bit 6.
    const unsigned field = (n ? 0x40u : 0u) | (~imms & 0x3Fu);
    if (field == 0) return false;
    unsigned len = 0;
    for (unsigned b = 7; b-- > 0;) if (field & (1u << b)) { len = b; break; }
    if (len < 1) return false;
    const unsigned esize = 1u << len;
    if (esize > (is64 ? 64u : 32u)) return false;

    const unsigned levels = esize - 1;
    if (immediate && (imms & levels) == levels) return false;
    const unsigned S = imms & levels, R = immr & levels;
    const unsigned diff = (S - R) & levels;          // 6-bit subtraction, then truncated

    auto ones = [](unsigned k) { return k >= 64 ? ~0ull : ((1ull << k) - 1); };
    const uint64_t welem = ones(S + 1), telem = ones(diff + 1);
    const uint64_t wrot = ror64(welem, R, esize);

    uint64_t w = 0, t = 0;
    for (unsigned i = 0; i < 64; i += esize) { w |= wrot << i; t |= telem << i; }
    if (!is64) { w &= 0xFFFFFFFFull; t &= 0xFFFFFFFFull; }
    if (wmask) *wmask = w;
    if (tmask) *tmask = t;
    return true;
}

bool Cpu::cond_holds(unsigned cond) const {
    bool r;
    switch (cond >> 1) {
        case 0: r = z; break;                       // EQ / NE
        case 1: r = c; break;                       // CS / CC
        case 2: r = n; break;                       // MI / PL
        case 3: r = v; break;                       // VS / VC
        case 4: r = c && !z; break;                 // HI / LS
        case 5: r = n == v; break;                  // GE / LT
        case 6: r = (n == v) && !z; break;          // GT / LE
        default: r = true; break;                   // AL
    }
    return (cond & 1) && cond != 0xF ? !r : r;
}

// ---- top level -------------------------------------------------------------

void Cpu::step() {
    ++insns;
    if (max_insns && insns > max_insns) {
        char buf[96];
        std::snprintf(buf, sizeof buf, "instruction limit exceeded at PC %016llX",
                      static_cast<unsigned long long>(pc));
        throw CpuError{buf, pc, 0};
    }
    if (sample_every && !sample_left--) {
        sample_left = sample_every;
        std::printf("[pc] %016llX after %llu\n", static_cast<unsigned long long>(pc),
                    static_cast<unsigned long long>(insns));
    }

    if (pc_watch && pc == pc_watch && on_pc_watch) on_pc_watch();

    // A64EMU_TRACE_RANGE=lo:hi:bias appends (pc - bias) as 8 raw bytes to
    // A64EMU_TRACE_OUT for every instruction executed inside [lo, hi) - the
    // producer half of a qemu-diff (see the x86 sibling's tools/qemu-diff).
    {
        struct RangeTrace {
            uint64_t lo = 0, hi = 0, bias = 0;
            std::FILE* out = nullptr;
            RangeTrace() {
                const char* spec = std::getenv("A64EMU_TRACE_RANGE");
                const char* path = std::getenv("A64EMU_TRACE_OUT");
                if (!spec || !path) return;
                char* end = nullptr;
                lo = std::strtoull(spec, &end, 16);
                if (end && *end == ':') hi = std::strtoull(end + 1, &end, 16);
                if (end && *end == ':') bias = std::strtoull(end + 1, nullptr, 16);
                if (hi > lo) out = std::fopen(path, "wb");
            }
            ~RangeTrace() {
                if (out) std::fclose(out);
            }
        };
        static RangeTrace rt;
        if (rt.out && pc >= rt.lo && pc < rt.hi) {
            const uint64_t rebased = pc - rt.bias;
            std::fwrite(&rebased, 8, 1, rt.out);
            if ((insns & 0xFFFF) == 0) std::fflush(rt.out);
        }
    }

    cur_pc_ = pc;
    const uint32_t insn = mem_.read<uint32_t>(pc);
    pc += 4;

    switch ((insn >> 25) & 0xF) {
        case 0x8: case 0x9:                                   // 100x data processing, immediate
            switch ((insn >> 23) & 0x7) {
                case 0: case 1: exec_pc_rel(insn); break;
                case 2: exec_addsub_imm(insn); break;
                case 4: exec_logical_imm(insn); break;
                case 5: exec_move_wide(insn); break;
                case 6: exec_bitfield(insn); break;
                case 7: exec_extract(insn); break;
                default: fail("unimplemented immediate group", insn);
            }
            break;
        case 0xA: case 0xB: exec_branch(insn); break;         // 101x branch/exception/system
        case 0x4: case 0x6: case 0xC: case 0xE: exec_loadstore(insn); break;   // x1x0
        case 0x5: case 0xD: exec_dp_register(insn); break;    // x101
        case 0x7: case 0xF: exec_fp_simd(insn); break;        // x111
        default:
            if (on_undefined && on_undefined(insn, cur_pc_)) return;
            fail("unallocated encoding", insn);
    }
}

// ---- data processing: immediate --------------------------------------------

void Cpu::exec_pc_rel(uint32_t insn) {
    const unsigned rd = insn & 0x1F;
    const uint64_t immhi = (insn >> 5) & 0x7FFFF, immlo = (insn >> 29) & 3;
    int64_t imm = static_cast<int64_t>(sign_extend((immhi << 2) | immlo, 21));
    if ((insn >> 31) & 1) {                       // ADRP: page-relative
        setx(rd, (cur_pc_ & ~0xFFFull) + (imm << 12));
    } else {
        setx(rd, cur_pc_ + imm);
    }
}

void Cpu::exec_addsub_imm(uint32_t insn) {
    const bool is64 = (insn >> 31) & 1, sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
    const unsigned shift = (insn >> 22) & 3, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
    uint64_t imm = (insn >> 10) & 0xFFF;
    if (shift == 1) imm <<= 12;
    else if (shift > 1) fail("reserved shift in add/sub immediate", insn);

    // Rn is SP here, not XZR — `add sp, sp, #16` is the standard prologue.
    const uint64_t a = xsp(rn);
    const AddOut r = sub ? addc(a, ~imm, true, is64) : addc(a, imm, false, is64);
    if (setflags) { set_nzcv_from(r.v, is64, r.carry, r.ovf); setreg(rd, is64, r.v); }
    else if (is64) setxsp(rd, r.v);
    else setxsp(rd, static_cast<uint32_t>(r.v));
}

void Cpu::exec_logical_imm(uint32_t insn) {
    const bool is64 = (insn >> 31) & 1;
    const unsigned opc = (insn >> 29) & 3, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
    uint64_t mask;
    if (!decode_bit_masks((insn >> 22) & 1, (insn >> 10) & 0x3F, (insn >> 16) & 0x3F,
                          true, is64, &mask, nullptr))
        fail("reserved logical immediate", insn);
    const uint64_t a = reg(rn, is64);
    uint64_t res;
    switch (opc) {
        case 0: res = a & mask; break;                      // AND
        case 1: res = a | mask; break;                      // ORR
        case 2: res = a ^ mask; break;                      // EOR
        default: res = a & mask; break;                     // ANDS
    }
    if (opc == 3) { set_nzcv_from(res, is64, false, false); setreg(rd, is64, res); }
    else if (is64) setxsp(rd, res);                         // Rd is SP for the non-flag forms
    else setxsp(rd, static_cast<uint32_t>(res));
}

void Cpu::exec_move_wide(uint32_t insn) {
    const bool is64 = (insn >> 31) & 1;
    const unsigned opc = (insn >> 29) & 3, hw = (insn >> 21) & 3, rd = insn & 0x1F;
    const uint64_t imm = (insn >> 5) & 0xFFFF;
    if (!is64 && hw > 1) fail("hw out of range for 32-bit move wide", insn);
    const unsigned pos = hw * 16;
    switch (opc) {
        case 0: setreg(rd, is64, ~(imm << pos)); break;                       // MOVN
        case 2: setreg(rd, is64, imm << pos); break;                          // MOVZ
        case 3: {                                                             // MOVK
            const uint64_t keep = reg(rd, is64) & ~(0xFFFFull << pos);
            setreg(rd, is64, keep | (imm << pos));
            break;
        }
        default: fail("unallocated move wide", insn);
    }
}

void Cpu::exec_bitfield(uint32_t insn) {
    const bool is64 = (insn >> 31) & 1;
    const unsigned opc = (insn >> 29) & 3;
    const unsigned immr = (insn >> 16) & 0x3F, imms = (insn >> 10) & 0x3F;
    const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
    const unsigned width = is64 ? 64 : 32;
    if (((insn >> 22) & 1) != (is64 ? 1u : 0u)) fail("N must match sf in bitfield", insn);

    const uint64_t src = reg(rn, is64);
    uint64_t wmask = 0, tmask = 0;
    if (!decode_bit_masks(is64, imms, immr, false, is64, &wmask, &tmask))
        fail("reserved bitfield encoding", insn);
    const uint64_t rotated = ror64(src, immr, width);

    if (opc == 1) {                                                   // BFM: insert
        const uint64_t dst = reg(rd, is64);
        const uint64_t bot = (dst & ~wmask) | (rotated & wmask);
        setreg(rd, is64, (dst & ~tmask) | (bot & tmask));
        return;
    }
    if (opc == 2) { setreg(rd, is64, rotated & wmask & tmask); return; }   // UBFM
    // SBFM: everything outside the field takes the sign of the field's top bit.
    const uint64_t top = ((src >> imms) & 1) ? ~0ull : 0ull;
    setreg(rd, is64, (top & ~tmask) | (rotated & wmask & tmask));
}

void Cpu::exec_extract(uint32_t insn) {                               // EXTR / ROR immediate
    const bool is64 = (insn >> 31) & 1;
    const unsigned rm = (insn >> 16) & 0x1F, imms = (insn >> 10) & 0x3F;
    const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
    const unsigned width = is64 ? 64 : 32;
    if (imms >= width) fail("lsb out of range in EXTR", insn);
    const uint64_t hi = reg(rn, is64), lo = reg(rm, is64);
    uint64_t res;
    if (!imms) res = lo;
    else res = (lo >> imms) | (hi << (width - imms));
    setreg(rd, is64, res);
}

// ---- branches, exceptions, system ------------------------------------------

void Cpu::exec_branch(uint32_t insn) {
    const unsigned top = (insn >> 26) & 0x3F;

    if ((top & 0x1F) == 0x05) {                                       // B / BL
        const int64_t off = static_cast<int64_t>(sign_extend(insn & 0x3FFFFFF, 26)) * 4;
        if (insn >> 31) setx(30, cur_pc_ + 4);                        // BL sets the link register
        pc = cur_pc_ + off;
        return;
    }
    if ((insn >> 24) == 0x54) {                                       // B.cond
        const int64_t off = static_cast<int64_t>(sign_extend((insn >> 5) & 0x7FFFF, 19)) * 4;
        if (cond_holds(insn & 0xF)) pc = cur_pc_ + off;
        return;
    }
    if (((insn >> 25) & 0x3F) == 0x1A) {                              // CBZ / CBNZ
        const bool is64 = (insn >> 31) & 1, nz = (insn >> 24) & 1;
        const int64_t off = static_cast<int64_t>(sign_extend((insn >> 5) & 0x7FFFF, 19)) * 4;
        const uint64_t val = reg(insn & 0x1F, is64);
        if ((val != 0) == nz) pc = cur_pc_ + off;
        return;
    }
    if (((insn >> 25) & 0x3F) == 0x1B) {                              // TBZ / TBNZ
        const bool nz = (insn >> 24) & 1;
        const unsigned bit = ((insn >> 26) & 0x20) | ((insn >> 19) & 0x1F);
        const int64_t off = static_cast<int64_t>(sign_extend((insn >> 5) & 0x3FFF, 14)) * 4;
        const bool set = (xr(insn & 0x1F) >> bit) & 1;
        if (set == nz) pc = cur_pc_ + off;
        return;
    }
    if ((insn >> 24) == 0xD4) {                                       // exception generation
        const unsigned imm16 = (insn >> 5) & 0xFFFF, ll = insn & 3;
        if (ll == 1 && ((insn >> 21) & 7) == 0) {                     // SVC
            if (on_svc && !on_svc(imm16)) halted = true;
            return;
        }
        if (ll == 0 && ((insn >> 21) & 7) == 1) {                     // BRK
            fail("guest executed BRK", insn);
        }
        fail("unimplemented exception instruction", insn);
    }
    if ((insn >> 22) == 0x354) {                                      // system: MSR/MRS/hints/barriers
        const unsigned l = (insn >> 21) & 1;
        const unsigned op0 = (insn >> 19) & 3, op1 = (insn >> 16) & 7;
        const unsigned crn = (insn >> 12) & 0xF, crm = (insn >> 8) & 0xF, op2 = (insn >> 5) & 7;
        const unsigned rt = insn & 0x1F;
        if (!l && crn == 2 && rt == 31) return;                       // hints: NOP/YIELD/WFE/...
        if (!l && crn == 3) return;                                   // barriers: DMB/DSB/ISB
        // The system registers a user-mode guest actually touches. TPIDR_EL0 is the
        // thread pointer: every TLS access in a libc goes through it, so a guest that
        // cannot read it does not get as far as main().
        // op0 == 1 is a system *instruction* (DC/IC/AT/TLBI), not a register access.
        // There are no caches or TLBs to maintain here, so almost all of them are
        // genuinely nothing — except DC ZVA, which is not a hint: it zeroes a block
        // and musl's memset relies on it doing so. Reporting a block size through
        // DCZID_EL0 and then not zeroing would corrupt memory silently.
        if (op0 == 1) {
            if (crn == 7 && crm == 4 && op2 == 1) {           // DC ZVA
                const uint64_t base = xr(rt) & ~63ull;        // 64 bytes, per our DCZID
                for (unsigned k = 0; k < 64; k += 8) mem_.write<uint64_t>(base + k, 0);
            }
            return;
        }
        const unsigned sysreg = (op0 << 16) | (op1 << 12) | (crn << 8) | (crm << 4) | op2;
        constexpr unsigned kTPIDR_EL0 = (3 << 16) | (3 << 12) | (13 << 8) | (0 << 4) | 2;
        constexpr unsigned kTPIDRRO   = (3 << 16) | (3 << 12) | (13 << 8) | (0 << 4) | 3;
        constexpr unsigned kFPCR      = (3 << 16) | (3 << 12) | (4 << 8) | (4 << 4) | 0;
        constexpr unsigned kFPSR      = (3 << 16) | (3 << 12) | (4 << 8) | (4 << 4) | 1;
        constexpr unsigned kNZCV      = (3 << 16) | (3 << 12) | (4 << 8) | (2 << 4) | 0;
        constexpr unsigned kCTR_EL0   = (3 << 16) | (3 << 12) | (0 << 8) | (0 << 4) | 1;
        constexpr unsigned kDCZID     = (3 << 16) | (3 << 12) | (0 << 8) | (0 << 4) | 7;
        constexpr unsigned kMIDR      = (3 << 16) | (0 << 12) | (0 << 8) | (0 << 4) | 0;
        if (l) {                                                      // MRS: read
            switch (sysreg) {
                case kTPIDR_EL0: case kTPIDRRO: setx(rt, tpidr_el0); return;
                case kFPCR: setx(rt, fpcr); return;
                case kFPSR: setx(rt, fpsr); return;
                case kNZCV: setx(rt, nzcv()); return;
                // Cache type: 4-word I and D lines, which is what a libc uses to decide
                // how to flush. Any sane value works; zero does not.
                case kCTR_EL0: setx(rt, 0x8444C004); return;
                case kDCZID: setx(rt, 4); return;                     // DC ZVA of 64 bytes
                case kMIDR: setx(rt, 0x410FD083); return;             // a plausible Cortex-A
                default: break;
            }
        } else {                                                      // MSR: write
            switch (sysreg) {
                case kTPIDR_EL0: tpidr_el0 = xr(rt); return;
                case kFPCR: fpcr = static_cast<uint32_t>(xr(rt)); return;
                case kFPSR: fpsr = static_cast<uint32_t>(xr(rt)); return;
                case kNZCV: set_nzcv(static_cast<uint32_t>(xr(rt))); return;
                default: break;
            }
        }
        // An unknown system register is the same situation as an unknown
        // instruction: on a CPU without the feature it is undefined, and a library
        // probing for one (OpenSSL asks for RNDR this way) wants the fault, not an
        // invented value. Answering with a plausible zero would claim the feature.
        if (on_undefined && on_undefined(insn, cur_pc_)) return;
        char buf[96];
        std::snprintf(buf, sizeof buf, "unimplemented system register s%u_%u_c%u_c%u_%u (%s)",
                      op0, op1, crn, crm, op2, l ? "read" : "write");
        fail(buf, insn);
    }
    if (((insn >> 25) & 0x7F) == 0x6B) {                              // BR / BLR / RET (+ auth)
        const unsigned opc = (insn >> 21) & 0xF, rn = (insn >> 5) & 0x1F;
        const unsigned op3 = (insn >> 10) & 0x3F;
        // op3 is 000000 for the plain forms and 000010/000011 for the
        // pointer-authenticating ones — BRAA/BRAAZ, BLRAA/BLRAAZ, RETAA/RETAB.
        // Authentication is the identity here (see the PAC family above), so each
        // behaves as its plain counterpart; only the target register differs.
        const bool authed = op3 == 2 || op3 == 3;
        if (!authed && op3 != 0) fail("unimplemented indirect branch", insn);
        switch (opc) {
            case 0: pc = xr(rn); return;                              // BR / BRAAZ / BRABZ
            case 1: setx(30, cur_pc_ + 4); pc = xr(rn); return;       // BLR / BLRAAZ / BLRABZ
            // RET takes its target from Rn; RETAA/RETAB encode Rn as 11111 and use
            // X30 unconditionally. Reading Rn there would read XZR and branch to 0.
            case 2: pc = authed ? xr(30) : xr(rn); return;
            case 8: if (!authed) break; pc = xr(rn); return;          // BRAA / BRAB
            case 9: if (!authed) break; setx(30, cur_pc_ + 4); pc = xr(rn); return;   // BLRAA/AB
            default: break;
        }
        fail("unimplemented indirect branch", insn);
    }
    fail("unimplemented branch/system instruction", insn);
}

// ---- loads and stores ------------------------------------------------------

void Cpu::exec_loadstore(uint32_t insn) {
    const unsigned grp = (insn >> 27) & 0x7;

    if (grp == 1 && !((insn >> 26) & 1)) {                            // exclusive / ordered
        const unsigned size = (insn >> 30) & 3, l = (insn >> 22) & 1;
        // Two flags split this group four ways, and both are easy to miss:
        //   o2 (bit 23) = 1  ->  LDAR/STLR: *ordered*, not exclusive. No monitor, no
        //                        status register, and a store must never fail.
        //   o1 (bit 21) = 1  ->  the pair forms, LDXP/STXP, which are a different
        //                        instruction and not decoded here.
        const unsigned o2 = (insn >> 23) & 1, o1 = (insn >> 21) & 1;
        const unsigned rs = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        const uint64_t addr = xsp(rn);

        // o1 == 1 is the four-way pair/compare-and-swap corner of this group, and the
        // encodings overlap in a way that is easy to get wrong:
        //
        //   o2=0, size=1x  ->  LDXP / STXP     (exclusive pair, 32- or 64-bit halves)
        //   o2=0, size=0x  ->  CASP            (compare-and-swap pair)
        //   o2=1           ->  CAS / CASB / CASH (single, size selects the width)
        //
        // CASP and STXP share o2=0 and o1=1 and are told apart only by bit 31. Reading
        // a `casp` as a `stxp` stores the wrong register and reports success.
        if (o1) {
            const unsigned rt2 = (insn >> 10) & 0x1F;
            if (!o2 && ((insn >> 31) & 1)) {                           // LDXP / STXP
                const bool pair64 = size == 3;
                if (l) {
                    excl_valid_ = true;
                    excl_addr_ = addr;
                    if (pair64) {
                        setx(rt, mem_.read<uint64_t>(addr));
                        setx(rt2, mem_.read<uint64_t>(addr + 8));
                    } else {
                        setw(rt, mem_.read<uint32_t>(addr));
                        setw(rt2, mem_.read<uint32_t>(addr + 4));
                    }
                } else {
                    if (!excl_valid_ || excl_addr_ != addr) { setx(rs, 1); return; }
                    excl_valid_ = false;
                    if (pair64) {
                        mem_.write<uint64_t>(addr, xr(rt));
                        mem_.write<uint64_t>(addr + 8, xr(rt2));
                    } else {
                        mem_.write<uint32_t>(addr, wr(rt));
                        mem_.write<uint32_t>(addr + 4, wr(rt2));
                    }
                    setx(rs, 0);
                }
                return;
            }
            if (!o2) {                                                 // CASP
                const bool pair64 = size == 1;
                const unsigned rs2 = rs + 1, rtp = rt + 1;
                if (pair64) {
                    const uint64_t lo = mem_.read<uint64_t>(addr), hi = mem_.read<uint64_t>(addr + 8);
                    if (lo == xr(rs) && hi == xr(rs2)) {
                        mem_.write<uint64_t>(addr, xr(rt));
                        mem_.write<uint64_t>(addr + 8, xr(rtp));
                    }
                    setx(rs, lo);
                    setx(rs2, hi);
                } else {
                    const uint32_t lo = mem_.read<uint32_t>(addr), hi = mem_.read<uint32_t>(addr + 4);
                    if (lo == wr(rs) && hi == wr(rs2)) {
                        mem_.write<uint32_t>(addr, wr(rt));
                        mem_.write<uint32_t>(addr + 4, wr(rtp));
                    }
                    setw(rs, lo);
                    setw(rs2, hi);
                }
                return;
            }
            // CAS / CASB / CASH. Rs is both the comparand and the destination for the
            // old value, which is what makes the instruction useful and also what makes
            // the order of these three lines matter.
            const bool is64 = size == 3;
            uint64_t old;
            switch (size) {
                case 0: old = mem_.read<uint8_t>(addr); break;
                case 1: old = mem_.read<uint16_t>(addr); break;
                case 2: old = mem_.read<uint32_t>(addr); break;
                default: old = mem_.read<uint64_t>(addr); break;
            }
            const uint64_t want = size < 3 ? (xr(rs) & ((1ull << (8u << size)) - 1))
                                           : xr(rs);
            if (old == want) {
                switch (size) {
                    case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(xr(rt))); break;
                    case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(xr(rt))); break;
                    case 2: mem_.write<uint32_t>(addr, static_cast<uint32_t>(xr(rt))); break;
                    default: mem_.write<uint64_t>(addr, xr(rt)); break;
                }
            }
            setreg(rs, is64, old);
            return;
        }

        // A real exclusive monitor, because a threaded guest depends on it. The
        // interpreter runs one thread at a time, so the only thing that can break an
        // LL/SC pair is the scheduler switching between them — and clearing the
        // monitor on a context switch is what makes the store fail, which is what
        // sends the guest back round its retry loop. Always succeeding instead would
        // let two threads both win the same compare-and-swap.
        if (l) {
            if (!o2) { excl_valid_ = true; excl_addr_ = addr; }
            switch (size) {
                case 0: setx(rt, mem_.read<uint8_t>(addr)); break;
                case 1: setx(rt, mem_.read<uint16_t>(addr)); break;
                case 2: setx(rt, mem_.read<uint32_t>(addr)); break;
                default: setx(rt, mem_.read<uint64_t>(addr)); break;
            }
        } else {
            if (!o2) {
                if (!excl_valid_ || excl_addr_ != addr) {
                    setx(rs, 1);                                      // failed; guest retries
                    return;
                }
                excl_valid_ = false;
            }
            switch (size) {
                case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(xr(rt))); break;
                case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(xr(rt))); break;
                case 2: mem_.write<uint32_t>(addr, static_cast<uint32_t>(xr(rt))); break;
                default: mem_.write<uint64_t>(addr, xr(rt)); break;
            }
            if (!o2) setx(rs, 0);
        }
        return;
    }

    // ---- LDAPUR / STLUR: ordered load and store with an unscaled offset ------
    //
    // ARMv8.4's FEAT_LRCPC2. They share bits 29..27 with LDR (literal) and differ
    // only in **bit 24**, which the literal case below did not test -- so
    //
    //     stlur wzr, [x19, #0x10]
    //
    // decoded as `ldr xzr, [pc + …]`, a load into the zero register: an instruction
    // that read some unrelated address and threw the result away. Silently. The
    // store it was supposed to make never happened.
    //
    // What that cost is worth writing down, because it is the exact failure this
    // file's design is meant to prevent. CPython's `create_gil` ends with
    //
    //     gil->last_holder = NULL;      // str  -- decoded, and it happened
    //     gil->locked = 0;              // stlur -- decoded as a load, and it did not
    //
    // and `locked` is initialised to -1 meaning "no GIL yet". So the GIL was created
    // and then still looked uncreated; `take_gil` waited for a holder that could not
    // exist, timed out forever, and eventually dereferenced a null `last_holder`.
    // Five million instructions of ObjC, XPC and CoreFoundation start-up were
    // debugged before this, all of them working correctly.
    //
    // The ordering these instructions carry is free here: one interpreter, one thread
    // at a time, so acquire and release are already satisfied.
    if (grp == 3 && ((insn >> 24) & 1)) {
        if ((insn >> 26) & 1) fail("unimplemented SIMD LDAPUR/STLUR", insn);
        const unsigned size = (insn >> 30) & 3, opc = (insn >> 22) & 3;
        const unsigned rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        const int64_t imm = static_cast<int64_t>(sign_extend((insn >> 12) & 0x1FF, 9));
        const uint64_t addr = xsp(rn) + static_cast<uint64_t>(imm);
        if (opc == 0) {                                               // STLUR
            switch (size) {
                case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(wr(rt))); return;
                case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(wr(rt))); return;
                case 2: mem_.write<uint32_t>(addr, wr(rt)); return;
                default: mem_.write<uint64_t>(addr, xr(rt)); return;
            }
        }
        uint64_t v;
        switch (size) {
            case 0: v = mem_.read<uint8_t>(addr); break;
            case 1: v = mem_.read<uint16_t>(addr); break;
            case 2: v = mem_.read<uint32_t>(addr); break;
            default: v = mem_.read<uint64_t>(addr); break;
        }
        if (opc == 1) {                                               // LDAPUR
            setreg(rt, size == 3, v);
            return;
        }
        // opc 10 sign-extends to 64 bits, opc 11 to 32. Both are only defined for a
        // size smaller than the destination, which is why `size == 3` is refused
        // rather than treated as a wider load that happens to need no extension.
        if (size == 3 || (opc == 3 && size == 2)) fail("reserved LDAPURS size", insn);
        const uint64_t s = sign_extend(v, 8u << size);
        if (opc == 2) setx(rt, s); else setw(rt, static_cast<uint32_t>(s));
        return;
    }

    if (grp == 3) {                                                   // load register (literal)
        const unsigned opc = (insn >> 30) & 3, rt = insn & 0x1F;
        const bool simd = (insn >> 26) & 1;
        const int64_t off = static_cast<int64_t>(sign_extend((insn >> 5) & 0x7FFFF, 19)) * 4;
        const uint64_t addr = cur_pc_ + off;
        if (simd) {
            switch (opc) {
                case 0: vreg[rt] = {mem_.read<uint32_t>(addr), 0}; return;
                case 1: vreg[rt] = {mem_.read<uint64_t>(addr), 0}; return;
                default: vreg[rt] = {mem_.read<uint64_t>(addr), mem_.read<uint64_t>(addr + 8)}; return;
            }
        }
        switch (opc) {
            case 0: setw(rt, mem_.read<uint32_t>(addr)); return;
            case 1: setx(rt, mem_.read<uint64_t>(addr)); return;
            case 2: setx(rt, sign_extend(mem_.read<uint32_t>(addr), 32)); return;
            default: return;                              // PRFM literal: a hint, nothing to do
        }
    }

    if (grp == 5) {                                                   // load/store pair
        const unsigned opc = (insn >> 30) & 3, simd = (insn >> 26) & 1;
        const unsigned mode = (insn >> 23) & 3;   // 1=post, 2=offset, 3=pre
        const unsigned l = (insn >> 22) & 1;
        const unsigned rt2 = (insn >> 10) & 0x1F, rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        // The immediate is scaled by the size of *one* transfer, and LDPSW is the
        // trap: opc=01 moves two 4-byte values (sign-extended to 64 bits), so it
        // scales by 4 even though the destinations are X registers. Scaling it by 8
        // made `ldpsw x2, x8, [x19, #8]` read from +16, and musl's syscall wrapper
        // got its syscall number out of the wrong slot — an invalid number, from a
        // load that looked perfectly ordinary.
        const unsigned sz = simd ? (4u << opc) : (opc == 2 ? 8u : 4u);
        const int64_t imm = static_cast<int64_t>(sign_extend((insn >> 15) & 0x7F, 7)) * sz;
        uint64_t base = xsp(rn);
        const uint64_t addr = (mode == 1) ? base : base + imm;        // post-index uses the old base
        if (simd) {
            if (l) {
                if (sz == 4) { vreg[rt] = {mem_.read<uint32_t>(addr), 0};
                               vreg[rt2] = {mem_.read<uint32_t>(addr + 4), 0}; }
                else if (sz == 8) { vreg[rt] = {mem_.read<uint64_t>(addr), 0};
                                    vreg[rt2] = {mem_.read<uint64_t>(addr + 8), 0}; }
                else { vreg[rt] = {mem_.read<uint64_t>(addr), mem_.read<uint64_t>(addr + 8)};
                       vreg[rt2] = {mem_.read<uint64_t>(addr + 16), mem_.read<uint64_t>(addr + 24)}; }
            } else {
                if (sz == 4) { mem_.write<uint32_t>(addr, static_cast<uint32_t>(vreg[rt].lo));
                               mem_.write<uint32_t>(addr + 4, static_cast<uint32_t>(vreg[rt2].lo)); }
                else if (sz == 8) { mem_.write<uint64_t>(addr, vreg[rt].lo);
                                    mem_.write<uint64_t>(addr + 8, vreg[rt2].lo); }
                else { mem_.write<uint64_t>(addr, vreg[rt].lo); mem_.write<uint64_t>(addr + 8, vreg[rt].hi);
                       mem_.write<uint64_t>(addr + 16, vreg[rt2].lo); mem_.write<uint64_t>(addr + 24, vreg[rt2].hi); }
            }
        } else if (l) {
            if (opc == 0) { setw(rt, mem_.read<uint32_t>(addr)); setw(rt2, mem_.read<uint32_t>(addr + 4)); }
            else if (opc == 1) { setx(rt, sign_extend(mem_.read<uint32_t>(addr), 32));
                                 setx(rt2, sign_extend(mem_.read<uint32_t>(addr + 4), 32)); }
            else { setx(rt, mem_.read<uint64_t>(addr)); setx(rt2, mem_.read<uint64_t>(addr + 8)); }
        } else {
            if (opc == 0) { mem_.write<uint32_t>(addr, wr(rt)); mem_.write<uint32_t>(addr + 4, wr(rt2)); }
            else { mem_.write<uint64_t>(addr, xr(rt)); mem_.write<uint64_t>(addr + 8, xr(rt2)); }
        }
        if (mode == 1 || mode == 3) setxsp(rn, base + imm);           // write back
        return;
    }

    // ---- atomic memory operations (ARMv8.1 "LSE") ---------------------------
    //
    // LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN, SWP and LDAPR. Apple's
    // libraries use these throughout rather than an LDXR/STXR loop, so an emulator
    // that means to run libSystem needs them all, not a subset.
    //
    // They share their group with the register-offset load/store, and the only thing
    // that separates them is bits 11..10: 00 here, 10 there. Each is read-modify-write
    // in one step, which is exactly right for an interpreter that runs one thread at a
    // time -- no monitor, nothing to interrupt.
    //
    // The ST<op> forms are not a separate encoding: they are the LD<op> forms with Rt
    // as XZR, so discarding the old value falls out of the register file.
    if (grp == 7 && !((insn >> 26) & 1) && ((insn >> 24) & 1) == 0 &&
        ((insn >> 21) & 1) && ((insn >> 10) & 3) == 0) {
        const unsigned size = (insn >> 30) & 3;
        const unsigned rs = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        const unsigned o3 = (insn >> 15) & 1, opc = (insn >> 12) & 7;
        const uint64_t addr = xsp(rn);
        const bool is64 = size == 3;

        auto load_sized = [&]() -> uint64_t {
            switch (size) {
                case 0: return mem_.read<uint8_t>(addr);
                case 1: return mem_.read<uint16_t>(addr);
                case 2: return mem_.read<uint32_t>(addr);
                default: return mem_.read<uint64_t>(addr);
            }
        };
        auto store_sized = [&](uint64_t v) {
            switch (size) {
                case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(v)); break;
                case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(v)); break;
                case 2: mem_.write<uint32_t>(addr, static_cast<uint32_t>(v)); break;
                default: mem_.write<uint64_t>(addr, v); break;
            }
        };

        if (o3 && opc == 4 && rs == 31) {                             // LDAPR
            setreg(rt, is64, load_sized());
            return;
        }
        const uint64_t old = load_sized();
        const uint64_t operand = reg(rs, is64);
        uint64_t val;
        if (o3) {                                                     // SWP
            if (opc != 0) fail("unimplemented atomic memory operation", insn);
            val = operand;
        } else {
            // The signed comparisons must be done at the operand's own width: an
            // 8-bit LDSMAX compares bytes, and comparing them as 64-bit values makes
            // every negative byte look large.
            const unsigned bits = 8u << size;
            auto sext = [bits](uint64_t v) {
                return bits >= 64 ? static_cast<int64_t>(v)
                                  : static_cast<int64_t>(sign_extend(v, bits));
            };
            switch (opc) {
                case 0: val = old + operand; break;                   // LDADD
                case 1: val = old & ~operand; break;                  // LDCLR
                case 2: val = old ^ operand; break;                   // LDEOR
                case 3: val = old | operand; break;                   // LDSET
                case 4: val = sext(old) > sext(operand) ? old : operand; break;   // LDSMAX
                case 5: val = sext(old) < sext(operand) ? old : operand; break;   // LDSMIN
                case 6: val = old > operand ? old : operand; break;   // LDUMAX
                default: val = old < operand ? old : operand; break;  // LDUMIN
            }
        }
        store_sized(val);
        // The old value goes to Rt *after* the store, and only if Rt is not XZR --
        // which is how the ST<op> aliases discard it.
        setreg(rt, is64, size < 3 ? (old & ((1ull << (8u << size)) - 1)) : old);
        return;
    }

    if (grp == 7) {                                                   // load/store register
        const unsigned size = (insn >> 30) & 3, simd = (insn >> 26) & 1, opc = (insn >> 22) & 3;
        const unsigned rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        uint64_t addr;
        bool writeback = false, postindex = false;
        int64_t wbimm = 0;
        unsigned scale = size;
        if (simd) scale = size | (((opc >> 1) & 1) << 2);             // 128-bit forms

        if ((insn >> 24) & 1) {                                       // unsigned immediate
            addr = xsp(rn) + (static_cast<uint64_t>((insn >> 10) & 0xFFF) << scale);
        } else if (((insn >> 21) & 1) && ((insn >> 10) & 3) == 2) {   // register offset
            const unsigned rm = (insn >> 16) & 0x1F, option = (insn >> 13) & 7;
            const unsigned s = (insn >> 12) & 1;
            const uint64_t idx = extend_reg(xr(rm), option, s ? scale : 0);
            addr = xsp(rn) + idx;
        } else {                                                      // unscaled / pre / post
            wbimm = static_cast<int64_t>(sign_extend((insn >> 12) & 0x1FF, 9));
            const unsigned mode = (insn >> 10) & 3;
            if (mode == 1) { addr = xsp(rn); writeback = true; postindex = true; }        // post
            else if (mode == 3) { addr = xsp(rn) + wbimm; writeback = true; }             // pre
            else addr = xsp(rn) + wbimm;                                                  // LDUR/STUR
        }

        if (simd) {
            const bool load = (opc & 1) != 0;
            if (load) {
                switch (scale) {
                    case 0: vreg[rt] = {mem_.read<uint8_t>(addr), 0}; break;
                    case 1: vreg[rt] = {mem_.read<uint16_t>(addr), 0}; break;
                    case 2: vreg[rt] = {mem_.read<uint32_t>(addr), 0}; break;
                    case 3: vreg[rt] = {mem_.read<uint64_t>(addr), 0}; break;
                    default: vreg[rt] = {mem_.read<uint64_t>(addr), mem_.read<uint64_t>(addr + 8)}; break;
                }
            } else {
                switch (scale) {
                    case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(vreg[rt].lo)); break;
                    case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(vreg[rt].lo)); break;
                    case 2: mem_.write<uint32_t>(addr, static_cast<uint32_t>(vreg[rt].lo)); break;
                    case 3: mem_.write<uint64_t>(addr, vreg[rt].lo); break;
                    default: mem_.write<uint64_t>(addr, vreg[rt].lo);
                             mem_.write<uint64_t>(addr + 8, vreg[rt].hi); break;
                }
            }
        } else if (opc == 0) {                                        // store
            switch (size) {
                case 0: mem_.write<uint8_t>(addr, static_cast<uint8_t>(xr(rt))); break;
                case 1: mem_.write<uint16_t>(addr, static_cast<uint16_t>(xr(rt))); break;
                case 2: mem_.write<uint32_t>(addr, wr(rt)); break;
                default: mem_.write<uint64_t>(addr, xr(rt)); break;
            }
        } else if (opc == 1) {                                        // zero-extending load
            switch (size) {
                case 0: setx(rt, mem_.read<uint8_t>(addr)); break;
                case 1: setx(rt, mem_.read<uint16_t>(addr)); break;
                case 2: setw(rt, mem_.read<uint32_t>(addr)); break;
                default: setx(rt, mem_.read<uint64_t>(addr)); break;
            }
        } else {                                                      // sign-extending load
            const bool to32 = (opc == 3);
            uint64_t val;
            switch (size) {
                case 0: val = sign_extend(mem_.read<uint8_t>(addr), 8); break;
                case 1: val = sign_extend(mem_.read<uint16_t>(addr), 16); break;
                case 2: val = sign_extend(mem_.read<uint32_t>(addr), 32); break;
                // size==3 with opc==2 is PRFM, not a load: it names a cache level and
                // a policy and has no architectural effect. There is nothing to model.
                default: return;
            }
            if (to32) setw(rt, static_cast<uint32_t>(val)); else setx(rt, val);
        }
        if (writeback) setxsp(rn, postindex ? xsp(rn) + wbimm : addr);
        return;
    }

    // ---- Advanced SIMD load/store, multiple structures -------------------------
    // LD1/ST1 over one to four consecutive V registers. musl's string functions and
    // anything the compiler vectorises reach these immediately.
    if ((insn & 0xBFBF0000u) == 0x0C000000u ||                        // no offset
        (insn & 0xBFA00000u) == 0x0C800000u) {                        // post-index
        const bool q = (insn >> 30) & 1, load = (insn >> 22) & 1;
        const bool post = (insn >> 23) & 1;
        const unsigned opcode = (insn >> 12) & 0xF, rm = (insn >> 16) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        // Two families share this encoding. LD1/ST1 move whole registers; LD2/LD3/LD4
        // de-interleave — LD2 over 2s lanes puts elements 0,2,4… in the first register
        // and 1,3,5… in the second. Treating an LD2 as two plain register loads reads
        // the right bytes into the wrong places, which is invisible until the values
        // are used.
        unsigned count, stride;
        switch (opcode) {
            case 0x7: count = 1; stride = 1; break;               // LD1/ST1 x1
            case 0xA: count = 2; stride = 1; break;               // LD1/ST1 x2
            case 0x6: count = 3; stride = 1; break;               // LD1/ST1 x3
            case 0x2: count = 4; stride = 1; break;               // LD1/ST1 x4
            case 0x8: count = 2; stride = 2; break;               // LD2/ST2
            case 0x4: count = 3; stride = 3; break;               // LD3/ST3
            case 0x0: count = 4; stride = 4; break;               // LD4/ST4
            default: fail("unimplemented SIMD structure load/store", insn);
        }
        const unsigned size = (insn >> 10) & 3;
        const unsigned esize = 1u << size;
        const unsigned bytes = q ? 16u : 8u;
        const unsigned lanes = bytes / esize;
        uint64_t addr = xsp(rn);

        if (stride == 1) {
            for (unsigned k = 0; k < count; ++k) {
                const unsigned r = (rt + k) & 31;
                if (load) {
                    vreg[r].lo = mem_.read<uint64_t>(addr);
                    vreg[r].hi = q ? mem_.read<uint64_t>(addr + 8) : 0;
                } else {
                    mem_.write<uint64_t>(addr, vreg[r].lo);
                    if (q) mem_.write<uint64_t>(addr + 8, vreg[r].hi);
                }
                addr += bytes;
            }
        } else {
            V128 tmp[4] = {};
            if (load) {
                for (unsigned e = 0; e < lanes; ++e)
                    for (unsigned k = 0; k < count; ++k) {
                        uint64_t val = 0;
                        const uint64_t a = addr + (e * count + k) * esize;
                        switch (esize) {
                            case 1: val = mem_.read<uint8_t>(a); break;
                            case 2: val = mem_.read<uint16_t>(a); break;
                            case 4: val = mem_.read<uint32_t>(a); break;
                            default: val = mem_.read<uint64_t>(a); break;
                        }
                        set_vlane(tmp[k], esize, e, val);
                    }
                for (unsigned k = 0; k < count; ++k) vreg[(rt + k) & 31] = tmp[k];
            } else {
                for (unsigned e = 0; e < lanes; ++e)
                    for (unsigned k = 0; k < count; ++k) {
                        const uint64_t val = get_vlane(vreg[(rt + k) & 31], esize, e);
                        const uint64_t a = addr + (e * count + k) * esize;
                        switch (esize) {
                            case 1: mem_.write<uint8_t>(a, static_cast<uint8_t>(val)); break;
                            case 2: mem_.write<uint16_t>(a, static_cast<uint16_t>(val)); break;
                            case 4: mem_.write<uint32_t>(a, static_cast<uint32_t>(val)); break;
                            default: mem_.write<uint64_t>(a, val); break;
                        }
                    }
            }
            addr += static_cast<uint64_t>(bytes) * count;
        }
        // Post-index: Rm == 31 means "advance by the transfer size", otherwise the
        // register holds the increment.
        if (post) setxsp(rn, xsp(rn) + (rm == 31 ? count * bytes : xr(rm)));
        return;
    }

    // ---- Advanced SIMD load/store, single structure ----------------------------
    // Two shapes: LD1R and friends, which load one element and replicate it across
    // every lane; and the single-lane forms, which touch one lane and leave the rest
    // of the register alone. The index is scattered across Q, S and size, which is
    // the only fiddly part.
    if ((insn & 0xBF000000u) == 0x0D000000u) {
        const bool q = (insn >> 30) & 1, post = (insn >> 23) & 1;
        const bool load = (insn >> 22) & 1, rbit = (insn >> 21) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, opcode = (insn >> 13) & 7;
        const unsigned s = (insn >> 12) & 1, size = (insn >> 10) & 3;
        const unsigned rn = (insn >> 5) & 0x1F, rt = insn & 0x1F;
        const unsigned selem = (((opcode & 1) << 1) | (rbit ? 1u : 0u)) + 1;
        const uint64_t addr0 = xsp(rn);
        uint64_t addr = addr0;

        auto rdmem = [&](uint64_t a, unsigned esz) -> uint64_t {
            switch (esz) {
                case 1: return mem_.read<uint8_t>(a);
                case 2: return mem_.read<uint16_t>(a);
                case 4: return mem_.read<uint32_t>(a);
                default: return mem_.read<uint64_t>(a);
            }
        };
        auto wrmem = [&](uint64_t a, unsigned esz, uint64_t v) {
            switch (esz) {
                case 1: mem_.write<uint8_t>(a, static_cast<uint8_t>(v)); break;
                case 2: mem_.write<uint16_t>(a, static_cast<uint16_t>(v)); break;
                case 4: mem_.write<uint32_t>(a, static_cast<uint32_t>(v)); break;
                default: mem_.write<uint64_t>(a, v); break;
            }
        };

        unsigned esize, index = 0;
        bool replicate = false;
        if ((opcode >> 1) == 3) { esize = 1u << size; replicate = true; }   // LD1R..LD4R
        else if ((opcode >> 1) == 0) { esize = 1; index = (q << 3) | (s << 2) | size; }
        else if ((opcode >> 1) == 1) { esize = 2; index = (q << 2) | (s << 1) | (size >> 1); }
        else if ((size & 1) == 0)    { esize = 4; index = (q << 1) | s; }
        else                         { esize = 8; index = q; }

        for (unsigned k = 0; k < selem; ++k) {
            const unsigned r = (rt + k) & 31;
            if (replicate) {
                const uint64_t val = rdmem(addr, esize);
                V128 out{};
                for (unsigned i = 0, lanes = (q ? 16u : 8u) / esize; i < lanes; ++i)
                    set_vlane(out, esize, i, val);
                vreg[r] = out;
            } else if (load) {
                set_vlane(vreg[r], esize, index, rdmem(addr, esize));
            } else {
                wrmem(addr, esize, get_vlane(vreg[r], esize, index));
            }
            addr += esize;
        }
        if (post) setxsp(rn, addr0 + (rm == 31 ? static_cast<uint64_t>(selem) * esize : xr(rm)));
        return;
    }

    fail("unimplemented load/store", insn);
}

// ---- data processing: register ---------------------------------------------

void Cpu::exec_dp_register(uint32_t insn) {
    const bool is64 = (insn >> 31) & 1;
    const unsigned op = (insn >> 21) & 0xFF;

    if (((insn >> 24) & 0x1F) == 0x0A) {                              // logical, shifted register
        const unsigned opc = (insn >> 29) & 3, shift = (insn >> 22) & 3, negate = (insn >> 21) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, amount = (insn >> 10) & 0x3F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (!is64 && amount >= 32) fail("shift amount too large for 32-bit", insn);
        uint64_t b = shift_reg(reg(rm, is64), shift, amount, is64);
        if (negate) b = ~b;
        const uint64_t a = reg(rn, is64);
        uint64_t res;
        switch (opc) {
            case 0: case 3: res = a & b; break;
            case 1: res = a | b; break;
            default: res = a ^ b; break;
        }
        if (opc == 3) set_nzcv_from(res, is64, false, false);
        setreg(rd, is64, res);
        return;
    }

    if (((insn >> 24) & 0x1F) == 0x0B && !((insn >> 21) & 1)) {       // add/sub, shifted register
        const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
        const unsigned shift = (insn >> 22) & 3, rm = (insn >> 16) & 0x1F;
        const unsigned amount = (insn >> 10) & 0x3F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (shift == 3) fail("ROR is not allowed in add/sub shifted register", insn);
        const uint64_t b = shift_reg(reg(rm, is64), shift, amount, is64);
        const uint64_t a = reg(rn, is64);
        const AddOut r = sub ? addc(a, ~b, true, is64) : addc(a, b, false, is64);
        if (setflags) set_nzcv_from(r.v, is64, r.carry, r.ovf);
        setreg(rd, is64, r.v);
        return;
    }

    if (((insn >> 24) & 0x1F) == 0x0B && ((insn >> 21) & 1)) {        // add/sub, extended register
        const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, option = (insn >> 13) & 7;
        const unsigned imm3 = (insn >> 10) & 7, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const uint64_t b = extend_reg(xr(rm), option, imm3);
        const uint64_t a = xsp(rn);
        const AddOut r = sub ? addc(a, ~b, true, is64) : addc(a, b, false, is64);
        if (setflags) { set_nzcv_from(r.v, is64, r.carry, r.ovf); setreg(rd, is64, r.v); }
        else setxsp(rd, is64 ? r.v : static_cast<uint32_t>(r.v));
        return;
    }

    if ((op & 0x1FF) == 0xD0 || ((insn >> 21) & 0xFF) == 0xD0) {      // add/sub with carry
        const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const uint64_t b = reg(rm, is64), a = reg(rn, is64);
        const AddOut r = sub ? addc(a, ~b, c, is64) : addc(a, b, c, is64);
        if (setflags) set_nzcv_from(r.v, is64, r.carry, r.ovf);
        setreg(rd, is64, r.v);
        return;
    }

    if (((insn >> 21) & 0xFF) == 0xD2 && ((insn >> 10) & 3) == 0) {   // conditional compare, register
        const bool sub = (insn >> 30) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, cond = (insn >> 12) & 0xF;
        const unsigned rn = (insn >> 5) & 0x1F, nzcv_imm = insn & 0xF;
        if (cond_holds(cond)) {
            const uint64_t a = reg(rn, is64), b = reg(rm, is64);
            const AddOut r = sub ? addc(a, ~b, true, is64) : addc(a, b, false, is64);
            set_nzcv_from(r.v, is64, r.carry, r.ovf);
        } else {
            n = (nzcv_imm >> 3) & 1; z = (nzcv_imm >> 2) & 1;
            c = (nzcv_imm >> 1) & 1; v = nzcv_imm & 1;
        }
        return;
    }
    if (((insn >> 21) & 0xFF) == 0xD2 && ((insn >> 10) & 3) == 2) {   // conditional compare, immediate
        const bool sub = (insn >> 30) & 1;
        const unsigned imm = (insn >> 16) & 0x1F, cond = (insn >> 12) & 0xF;
        const unsigned rn = (insn >> 5) & 0x1F, nzcv_imm = insn & 0xF;
        if (cond_holds(cond)) {
            const uint64_t a = reg(rn, is64);
            const AddOut r = sub ? addc(a, ~static_cast<uint64_t>(imm), true, is64)
                                 : addc(a, imm, false, is64);
            set_nzcv_from(r.v, is64, r.carry, r.ovf);
        } else {
            n = (nzcv_imm >> 3) & 1; z = (nzcv_imm >> 2) & 1;
            c = (nzcv_imm >> 1) & 1; v = nzcv_imm & 1;
        }
        return;
    }

    if (((insn >> 21) & 0xFF) == 0xD4) {                              // conditional select
        const unsigned rm = (insn >> 16) & 0x1F, cond = (insn >> 12) & 0xF;
        const unsigned o2 = (insn >> 10) & 3, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        const bool o1 = (insn >> 30) & 1;
        uint64_t res;
        if (cond_holds(cond)) res = reg(rn, is64);
        else {
            res = reg(rm, is64);
            if (o2 & 1) res += 1;                                     // CSINC
            if (o1) res = ~res;                                       // CSINV / CSNEG
            if (o1 && (o2 & 1)) res = static_cast<uint64_t>(0) - reg(rm, is64);   // CSNEG
        }
        setreg(rd, is64, res);
        return;
    }

    if (((insn >> 21) & 0xFF) == 0xD6) {                              // data processing, 1 or 2 source
        const bool is_two_source = !((insn >> 30) & 1);
        const unsigned opcode = (insn >> 10) & 0x3F;
        const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (is_two_source) {
            const uint64_t a = reg(rn, is64), b = reg(rm, is64);
            switch (opcode) {
                case 0x02: {                                          // UDIV
                    const uint64_t d = is64 ? b : static_cast<uint32_t>(b);
                    setreg(rd, is64, d == 0 ? 0 : (is64 ? a / d : static_cast<uint32_t>(a) / static_cast<uint32_t>(d)));
                    return;
                }
                case 0x03: {                                          // SDIV
                    if (is64) {
                        const int64_t sa = static_cast<int64_t>(a), sb = static_cast<int64_t>(b);
                        setx(rd, sb == 0 ? 0 : (sb == -1 && sa == INT64_MIN ? static_cast<uint64_t>(sa)
                                                                            : static_cast<uint64_t>(sa / sb)));
                    } else {
                        const int32_t sa = static_cast<int32_t>(a), sb = static_cast<int32_t>(b);
                        setw(rd, sb == 0 ? 0 : (sb == -1 && sa == INT32_MIN ? static_cast<uint32_t>(sa)
                                                                            : static_cast<uint32_t>(sa / sb)));
                    }
                    return;
                }
                case 0x08: setreg(rd, is64, shift_reg(a, 0, b & (is64 ? 63 : 31), is64)); return;   // LSLV
                case 0x09: setreg(rd, is64, shift_reg(a, 1, b & (is64 ? 63 : 31), is64)); return;   // LSRV
                case 0x0A: setreg(rd, is64, shift_reg(a, 2, b & (is64 ? 63 : 31), is64)); return;   // ASRV
                case 0x0B: setreg(rd, is64, shift_reg(a, 3, b & (is64 ? 63 : 31), is64)); return;   // RORV
                // PACGA — a *generic* pointer-authentication code: a 32-bit MAC of Rn
                // keyed by Rm, placed in bits 63:32 with the low half zero. It is the one
                // PAC instruction the identity treatment does not fit, because there is no
                // pointer to leave alone: the code is a value the guest computes now and
                // compares to one it computed earlier (libobjc uses it on its method
                // caches). What it needs is therefore not the *right* MAC but a
                // *deterministic* one -- the same inputs giving the same answer twice --
                // and it must be non-zero, since a MAC that is always zero is
                // indistinguishable from an uninitialised field.
                //
                // So: a fixed 64-bit mix, kept to the top half. Not Apple's function, and
                // nothing that crosses a process boundary could accept it; nothing does,
                // because a generic MAC is only ever checked by the code that made it.
                case 0x0C: {
                    if (!is64) break;
                    const uint64_t mix = (a ^ b) * 0x9E3779B97F4A7C15ull;
                    setx(rd, ((mix ^ (mix >> 32)) | 1) << 32);
                    return;
                }
                default: break;
            }
        } else if (rm == 1) {
            // ---- pointer authentication (arm64e) ----------------------------
            //
            // In this group the Rm field is really `opcode2`, and 00001 selects the
            // PAC family: PACIA/PACIB/PACDA/PACDB, their Z forms, the matching
            // AUTxx, and XPACI/XPACD. Nothing here looked at opcode2 before, so
            // `pacia x0, x1` decoded as RBIT and silently reversed the bits of a
            // return address.
            //
            // PAC is implemented as the *identity*: signing leaves the pointer
            // alone and authenticating accepts it. That is not a stub — it is
            // exactly what an ARMv8.3 CPU does when pointer authentication is
            // disabled, which is a real configuration and the one this emulator
            // presents. The consequence is honest and worth knowing: a guest that
            // corrupts a signed pointer will not fault here, because there is no
            // signature to fail. Everything Apple's own code does — sign on entry,
            // authenticate on return, strip before printing — round-trips
            // correctly, which is what running arm64e libSystem needs.
            // Every one of these reads *and writes* Rd — the pointer — and takes the
            // modifier in Rn: `X[d] = AddPAC(X[d], X[n])`. So the identity is a
            // genuine no-op, and writing anything (the first version copied Rn into
            // Rd) replaces the pointer with the salt.
            //
            // A no-op is normally the wrong answer in this emulator, and it is worth
            // being clear about why this one is not: PAC-disabled hardware really
            // does nothing here, and the round-trip in tests/pac.c holds on both,
            // so the behaviour is checkable rather than merely convenient.
            if (!is64) fail("pointer authentication needs a 64-bit form", insn);
            //
            // The whole family, so the halves are not guessed at:
            //
            //   0x00..0x03  PACIA  PACIB  PACDA  PACDB     sign
            //   0x04..0x07  AUTIA  AUTIB  AUTDA  AUTDB     authenticate
            //   0x08..0x0B  PACIZA PACIZB PACDZA PACDZB    sign, zero modifier
            //   0x0C..0x0F  AUTIZA AUTIZB AUTDZA AUTDZB    authenticate, zero modifier
            //   0x10..0x11  XPACI  XPACD                   strip
            //
            // **Making AUT*/XPAC* strip the top bits was tried, and measured worse.** The
            // argument for it was good: `--strict` reported libobjc's `addMethod` writing to
            // 0x80006000002000E0 when the object it meant was at 0x6000002000C0, which is a
            // signature surviving an authenticate. But the class `bits` field is not a plain
            // pointer — libobjc tests bit 63 of it directly (`tbnz x8, #63` inside
            // `class_data_bits_t::setData`), so the bit carries meaning of its own, and the
            // shared cache's pointers arrive canonical anyway because `dsc_extract`'s slide
            // walk has already rewritten them. Stripping took the macOS guest from 134,534
            // instructions to 122,663 and moved the failure earlier. Reverted; recorded here
            // so the next attempt starts from the measurement rather than the argument.
            if (opcode <= 0x11) return;
            fail("unimplemented pointer-authentication instruction", insn);
        } else if (rm != 0) {
            fail("unimplemented 1-source data processing (opcode2 != 0)", insn);
        } else {
            const uint64_t a = reg(rn, is64);
            const unsigned width = is64 ? 64 : 32;
            switch (opcode) {
                case 0x00: {                                          // RBIT
                    uint64_t r = 0;
                    for (unsigned i = 0; i < width; ++i) if ((a >> i) & 1) r |= 1ull << (width - 1 - i);
                    setreg(rd, is64, r); return;
                }
                case 0x01: {                                          // REV16
                    uint64_t r = 0;
                    for (unsigned i = 0; i < width; i += 16)
                        r |= ((a >> i) & 0xFF) << (i + 8) | (((a >> (i + 8)) & 0xFF) << i);
                    setreg(rd, is64, r); return;
                }
                case 0x02: {                                          // REV32 / REV (32-bit)
                    uint64_t r = 0;
                    for (unsigned i = 0; i < width; i += 32) {
                        const uint32_t w = static_cast<uint32_t>(a >> i);
                        r |= static_cast<uint64_t>(bswap32(w)) << i;
                    }
                    setreg(rd, is64, r); return;
                }
                case 0x03: setx(rd, bswap64(a)); return;          // REV (64-bit)
                case 0x04: {                                          // CLZ
                    unsigned k = 0;
                    while (k < width && !((a >> (width - 1 - k)) & 1)) ++k;
                    setreg(rd, is64, k); return;
                }
                case 0x05: {                                          // CLS
                    const uint64_t top = (a >> (width - 1)) & 1;
                    unsigned k = 0;
                    while (k + 1 < width && (((a >> (width - 2 - k)) & 1) == top)) ++k;
                    setreg(rd, is64, k); return;
                }
                default: break;
            }
        }
        fail("unimplemented 1/2-source data processing", insn);
    }

    if (((insn >> 24) & 0x1F) == 0x1B) {                              // 3-source: MADD/MSUB/MULH
        const unsigned op31 = (insn >> 21) & 7, o0 = (insn >> 15) & 1;
        const unsigned rm = (insn >> 16) & 0x1F, ra = (insn >> 10) & 0x1F;
        const unsigned rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;
        if (op31 == 0) {                                              // MADD / MSUB
            const uint64_t prod = reg(rn, is64) * reg(rm, is64);
            const uint64_t acc = reg(ra, is64);
            setreg(rd, is64, o0 ? acc - prod : acc + prod);
            return;
        }
        if (op31 == 1 || op31 == 5) {                                 // SMADDL / UMADDL (+ SUBL)
            const uint64_t na = op31 == 1 ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(wr(rn))))
                                          : wr(rn);
            const uint64_t nb = op31 == 1 ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(wr(rm))))
                                          : wr(rm);
            const uint64_t prod = na * nb;
            setx(rd, o0 ? xr(ra) - prod : xr(ra) + prod);
            return;
        }
        if (op31 == 2) {                                              // SMULH
            setx(rd, smulh(static_cast<int64_t>(xr(rn)), static_cast<int64_t>(xr(rm))));
            return;
        }
        if (op31 == 6) {                                              // UMULH
            setx(rd, umulh(xr(rn), xr(rm)));
            return;
        }
        fail("unimplemented 3-source data processing", insn);
    }

    fail("unimplemented register data processing", insn);
}

}  // namespace a64
