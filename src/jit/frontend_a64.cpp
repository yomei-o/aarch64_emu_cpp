// AArch64 frontend: guest words -> IR.
//
// Every A64 instruction is four bytes, so the walk is trivial; what takes the code is
// the decoding, which follows cpu.cpp group for group (it is the specification this
// has to agree with - the verifier compares the two).  Whatever is not translated is
// emitted as an `Interp` op, which runs that one instruction through the interpreter;
// that is every FP / SIMD instruction, atomics, exclusives, system calls and the rarer
// integer forms, so coverage can grow one encoding at a time.
//
// Registers are slots 0..30 (x0..x30) and `sp` follows them; register 31 is the zero
// register almost everywhere (reads the zero cell, writes go to a scratch temporary)
// and the stack pointer where the architecture says so (a load/store base, ADD/SUB
// immediate and extended, logical immediate destinations).
#include <cstring>
#include <vector>

#include "engine.h"

namespace jit {

namespace {

using a64::Cpu;

inline uint64_t sext(uint64_t v, unsigned bits) {
    if (bits >= 64) return v;
    const uint64_t m = 1ull << (bits - 1);
    return (v ^ m) - m;
}

// What the translator learns about one instruction.
struct Info {
    bool native = false;
    bool term = false;         // ends the block
    bool reads = true;         // may read NZCV
    bool writes_all = false;   // overwrites NZCV
    bool effects = false;      // has effects beyond CPU state and memory (a system call...)
};

struct Tr {
    const GuestSlots& s;
    IrBlock& ir;
    int tmp_next = 1;
    uint32_t cur_off = 0;
    bool last = false;
    bool stored = false;

    Tr(const GuestSlots& sl, IrBlock& b) : s(sl), ir(b) {}

    // x0..x30 are slots 0, 8, ...; XZR reads the zero cell
    int src(unsigned r) const { return r == 31 ? s.zero : static_cast<int>(r) * 8; }
    int base(unsigned r) const { return r == 31 ? s.sp : static_cast<int>(r) * 8; }
    int newtmp() { return s.tmp0 + 8 * (tmp_next++); }
    int dst(unsigned r) { return r == 31 ? newtmp() : static_cast<int>(r) * 8; }
    int dst_sp(unsigned r) const { return r == 31 ? s.sp : static_cast<int>(r) * 8; }

    Op& emit(OpKind k) {
        ir.ops.emplace_back();
        Op& o = ir.ops.back();
        o.kind = k;
        o.pc = cur_off;
        o.ni = static_cast<uint16_t>(ir.insns);
        return o;
    }
    void mov(int d, int a) { Op& o = emit(OpKind::Mov); o.d = d; o.a = a; }
    void movi(int d, int64_t v) { Op& o = emit(OpKind::MovI); o.d = d; o.imm = v; }
    void bin(BinOp op, int sz, int d, int a, int b) {
        Op& o = emit(OpKind::Bin);
        o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(sz); o.d = d; o.a = a; o.b = b;
    }
    void bini(BinOp op, int sz, int d, int a, int64_t imm) {
        Op& o = emit(OpKind::BinI);
        o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(sz); o.d = d; o.a = a; o.imm = imm;
    }
    void ext(int d, int a, int src_sz, bool sgn, int dst_sz) {
        Op& o = emit(OpKind::Ext);
        o.d = d; o.a = a; o.sz = static_cast<uint8_t>(src_sz); o.cc = static_cast<uint8_t>(dst_sz);
        o.flags = sgn ? kFlagSigned : 0;
    }
    void ld(int d, int a, int c, int cc, int64_t imm, int sz) {
        Op& o = emit(OpKind::Ld);
        o.d = d; o.a = a; o.c = c; o.cc = static_cast<uint8_t>(cc); o.imm = imm; o.sz = static_cast<uint8_t>(sz);
    }
    void lds(int d, int a, int c, int cc, int64_t imm, int sz, int dstsz) {
        Op& o = emit(OpKind::LdS);
        o.d = d; o.a = a; o.c = c; o.cc = static_cast<uint8_t>(cc); o.imm = imm; o.sz = static_cast<uint8_t>(sz);
        o.imm2 = dstsz;
    }
    void st(int a, int c, int cc, int64_t imm, int val, int sz) {
        Op& o = emit(OpKind::St);
        o.a = a; o.c = c; o.cc = static_cast<uint8_t>(cc); o.imm = imm; o.b = val; o.sz = static_cast<uint8_t>(sz);
        stored = true;
    }
    // Stores check for invalidated code themselves; only the instruction's last store may.
    void flush_check(uint64_t next_pc) {
        if (!stored || last || ir.ops.empty()) return;
        Op& s = ir.ops.back();
        if (s.kind == OpKind::St) {
            s.flags |= kFlagChk;
            s.imm2 = static_cast<int64_t>(next_pc);
            return;
        }
        Op& o = emit(OpKind::ChkFlush);
        o.imm = static_cast<int64_t>(next_pc);
    }
    void exit_to(uint64_t target) { Op& o = emit(OpKind::Exit); o.imm = static_cast<int64_t>(target); }
};

// The shifted operand of the register forms: Rm shifted by `amount`.  Returns the
// slot holding it (Rm itself when there is nothing to do).
int shifted(Tr& t, unsigned rm, unsigned type, unsigned amount, int sz) {
    if (amount == 0 && type != 3) return t.src(rm);
    if (amount == 0) return t.src(rm);
    const int d = t.newtmp();
    static const BinOp ops[4] = {BinOp::Shl, BinOp::Shr, BinOp::Sar, BinOp::Ror};
    t.bini(ops[type & 3], sz, d, t.src(rm), amount);
    return d;
}

// ---- the translator proper ------------------------------------------------------

// Translates one instruction.  Emits IR and returns with info.native set, or emits
// nothing and leaves info.native clear (the caller then emits an Interp op).
void emit_insn(Tr& t, uint32_t insn, uint64_t pc, bool flags_live, Info& info) {
    const uint64_t next_pc = pc + 4;
    const bool is64 = (insn >> 31) & 1;
    const int sz = is64 ? 8 : 4;
    const unsigned rd = insn & 0x1F, rn = (insn >> 5) & 0x1F;

    auto native = [&](bool reads, bool writes_all) {
        info.native = true;
        info.reads = reads;
        info.writes_all = writes_all;
    };
    // Instructions that never touch NZCV: the interpreted ones among them (loads and
    // stores) should not keep earlier flag writes alive.
    if (((insn >> 25) & 5) == 4) info.reads = false;   // the load/store group, whatever it is

    switch ((insn >> 25) & 0xF) {
    case 0x8: case 0x9:
        switch ((insn >> 23) & 7) {
        case 0: case 1: {   // ADR / ADRP
            const uint64_t immhi = (insn >> 5) & 0x7FFFF, immlo = (insn >> 29) & 3;
            const int64_t imm = static_cast<int64_t>(sext((immhi << 2) | immlo, 21));
            const uint64_t v = (insn >> 31) ? (pc & ~0xFFFull) + (static_cast<uint64_t>(imm) << 12)
                                            : pc + static_cast<uint64_t>(imm);
            native(false, false);
            if (rd != 31) t.movi(t.dst(rd), static_cast<int64_t>(v));
            return;
        }
        case 2: {   // ADD / SUB immediate
            const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
            const unsigned shift = (insn >> 22) & 3;
            if (shift > 1) return;
            uint64_t imm = (insn >> 10) & 0xFFF;
            if (shift == 1) imm <<= 12;
            const BinOp op = sub ? BinOp::Sub : BinOp::Add;
            if (!setflags) {
                native(false, false);
                t.bini(op, sz, t.dst_sp(rd), t.base(rn), static_cast<int64_t>(imm));
                return;
            }
            native(false, true);
            if (flags_live) {
                Op& o = t.emit(OpKind::A64BinSI);
                o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(sz);
                o.d = t.dst(rd); o.a = t.base(rn); o.imm = static_cast<int64_t>(imm); o.flags = kFlagEager;
            } else if (rd != 31) {
                t.bini(op, sz, t.dst(rd), t.base(rn), static_cast<int64_t>(imm));
            }
            return;
        }
        case 4: {   // logical immediate
            const unsigned opc = (insn >> 29) & 3;
            uint64_t mask;
            if (!a64::decode_bit_masks((insn >> 22) & 1, (insn >> 10) & 0x3F, (insn >> 16) & 0x3F, true, is64,
                                       &mask, nullptr))
                return;
            if (opc == 3) {
                native(false, true);
                if (flags_live) {
                    Op& o = t.emit(OpKind::A64BinSI);
                    o.cc = static_cast<uint8_t>(BinOp::And); o.sz = static_cast<uint8_t>(sz);
                    o.d = t.dst(rd); o.a = t.src(rn); o.imm = static_cast<int64_t>(mask); o.flags = kFlagEager;
                } else if (rd != 31) {
                    t.bini(BinOp::And, sz, t.dst(rd), t.src(rn), static_cast<int64_t>(mask));
                }
                return;
            }
            native(false, false);
            const BinOp op = opc == 0 ? BinOp::And : opc == 1 ? BinOp::Or : BinOp::Xor;
            t.bini(op, sz, t.dst_sp(rd), t.src(rn), static_cast<int64_t>(mask));
            return;
        }
        case 5: {   // move wide
            const unsigned opc = (insn >> 29) & 3, hw = (insn >> 21) & 3;
            const uint64_t imm = (insn >> 5) & 0xFFFF;
            if (opc == 1 || (!is64 && hw > 1)) return;
            const unsigned pos = hw * 16;
            const uint64_t wmask = is64 ? ~0ull : 0xFFFFFFFFull;
            native(false, false);
            if (rd == 31) return;
            if (opc == 0) {
                t.movi(rd * 8, static_cast<int64_t>(~(imm << pos) & wmask));
            } else if (opc == 2) {
                t.movi(rd * 8, static_cast<int64_t>((imm << pos) & wmask));
            } else {   // MOVK
                t.bini(BinOp::And, sz, rd * 8, rd * 8, static_cast<int64_t>(~(0xFFFFull << pos)));
                t.bini(BinOp::Or, sz, rd * 8, rd * 8, static_cast<int64_t>(imm << pos));
            }
            return;
        }
        case 6: {   // bitfield
            const unsigned opc = (insn >> 29) & 3;
            const unsigned immr = (insn >> 16) & 0x3F, imms = (insn >> 10) & 0x3F;
            const unsigned width = is64 ? 64 : 32;
            if (((insn >> 22) & 1) != (is64 ? 1u : 0u)) return;
            uint64_t wmask = 0, tmask = 0;
            if (!a64::decode_bit_masks(is64, imms, immr, false, is64, &wmask, &tmask)) return;
            native(false, false);
            if (rd == 31) return;
            const int d = rd * 8, a = t.src(rn);
            if (opc == 1) {   // BFM
                Op& o = t.emit(OpKind::A64Bfm);
                o.sz = static_cast<uint8_t>(sz); o.d = d; o.a = a; o.b = t.src(rd);
                o.imm = static_cast<int64_t>(wmask); o.imm2 = static_cast<int64_t>(tmask);
                o.c = static_cast<int32_t>(immr); o.cc = static_cast<uint8_t>(imms);
                return;
            }
            if (opc == 2) {   // UBFM and its aliases
                if (imms == width - 1) { t.bini(BinOp::Shr, sz, d, a, immr); return; }                   // LSR
                if (imms + 1 == immr) { t.bini(BinOp::Shl, sz, d, a, width - immr); return; }            // LSL
                if (immr == 0 && imms == 7) { t.ext(d, a, 1, false, sz); return; }                       // UXTB
                if (immr == 0 && imms == 15) { t.ext(d, a, 2, false, sz); return; }                      // UXTH
                Op& o = t.emit(OpKind::A64Ubfm);
                o.sz = static_cast<uint8_t>(sz); o.d = d; o.a = a;
                o.imm = static_cast<int64_t>(wmask & tmask); o.imm2 = static_cast<int64_t>(tmask);
                o.c = static_cast<int32_t>(immr); o.cc = static_cast<uint8_t>(imms);
                return;
            }
            // SBFM (opc 0, and the unallocated 3, which cpu.cpp also treats as SBFM)
            if (imms == width - 1) { t.bini(BinOp::Sar, sz, d, a, immr); return; }                       // ASR
            if (immr == 0 && imms == 7) { t.ext(d, a, 1, true, sz); return; }                            // SXTB
            if (immr == 0 && imms == 15) { t.ext(d, a, 2, true, sz); return; }                           // SXTH
            if (immr == 0 && imms == 31 && is64) { t.ext(d, a, 4, true, 8); return; }                    // SXTW
            Op& o = t.emit(OpKind::A64Sbfm);
            o.sz = static_cast<uint8_t>(sz); o.d = d; o.a = a;
            o.imm = static_cast<int64_t>(wmask); o.imm2 = static_cast<int64_t>(tmask);
            o.c = static_cast<int32_t>(immr); o.cc = static_cast<uint8_t>(imms);
            return;
        }
        case 7: {   // EXTR / ROR immediate
            const unsigned rm = (insn >> 16) & 0x1F, imms = (insn >> 10) & 0x3F;
            const unsigned width = is64 ? 64 : 32;
            if (imms >= width) return;
            native(false, false);
            if (rd == 31) return;
            if (imms == 0) {
                if (is64) t.mov(rd * 8, t.src(rm)); else t.ext(rd * 8, t.src(rm), 4, false, 4);
            } else if (rn == rm) {
                t.bini(BinOp::Ror, sz, rd * 8, t.src(rn), imms);
            } else {
                const int lo = t.newtmp(), hi = t.newtmp();
                t.bini(BinOp::Shr, sz, lo, t.src(rm), imms);
                t.bini(BinOp::Shl, sz, hi, t.src(rn), width - imms);
                t.bin(BinOp::Or, sz, rd * 8, lo, hi);
            }
            return;
        }
        default: return;
        }

    case 0xA: case 0xB: {
        const unsigned top = (insn >> 26) & 0x3F;
        if ((top & 0x1F) == 0x05) {   // B / BL
            const int64_t off = static_cast<int64_t>(sext(insn & 0x3FFFFFF, 26)) * 4;
            native(false, false);
            info.term = true;
            if (insn >> 31) t.movi(30 * 8, static_cast<int64_t>(next_pc));
            t.exit_to(pc + static_cast<uint64_t>(off));
            return;
        }
        if ((insn >> 24) == 0x54) {   // B.cond
            const int64_t off = static_cast<int64_t>(sext((insn >> 5) & 0x7FFFF, 19)) * 4;
            native(true, false);
            info.term = true;
            Op& o = t.emit(OpKind::A64Jcc);
            o.cc = insn & 0xF; o.imm = static_cast<int64_t>(pc + static_cast<uint64_t>(off)); o.imm2 = static_cast<int64_t>(next_pc);
            return;
        }
        if (((insn >> 25) & 0x3F) == 0x1A) {   // CBZ / CBNZ
            const bool nz = (insn >> 24) & 1;
            const int64_t off = static_cast<int64_t>(sext((insn >> 5) & 0x7FFFF, 19)) * 4;
            native(false, false);
            info.term = true;
            Op& o = t.emit(OpKind::JccGenI);
            o.cc = static_cast<uint8_t>(nz ? Cond::Ne : Cond::Eq); o.sz = static_cast<uint8_t>(sz);
            o.a = t.src(rd); o.d = 0;
            o.imm = static_cast<int64_t>(pc + static_cast<uint64_t>(off)); o.imm2 = static_cast<int64_t>(next_pc);
            return;
        }
        if (((insn >> 25) & 0x3F) == 0x1B) {   // TBZ / TBNZ
            const bool nz = (insn >> 24) & 1;
            const unsigned bit = ((insn >> 26) & 0x20) | ((insn >> 19) & 0x1F);
            const int64_t off = static_cast<int64_t>(sext((insn >> 5) & 0x3FFF, 14)) * 4;
            native(false, false);
            info.term = true;
            const uint64_t mask = 1ull << bit;
            const Cond cond = nz ? Cond::Tst : Cond::Ntst;
            if (bit < 31) {
                Op& o = t.emit(OpKind::JccGenI);
                o.cc = static_cast<uint8_t>(cond); o.sz = 8; o.a = t.src(rd); o.d = static_cast<int32_t>(mask);
                o.imm = static_cast<int64_t>(pc + static_cast<uint64_t>(off)); o.imm2 = static_cast<int64_t>(next_pc);
            } else {
                const int m = t.newtmp();
                t.movi(m, static_cast<int64_t>(mask));
                Op& o = t.emit(OpKind::JccGen);
                o.cc = static_cast<uint8_t>(cond); o.sz = 8; o.a = t.src(rd); o.b = m;
                o.imm = static_cast<int64_t>(pc + static_cast<uint64_t>(off)); o.imm2 = static_cast<int64_t>(next_pc);
            }
            return;
        }
        if ((insn >> 24) == 0xD4) {   // exception generation: SVC and friends
            info.effects = true;
            return;
        }
        if ((insn >> 22) == 0x354) {   // system
            const unsigned l = (insn >> 21) & 1;
            const unsigned op0 = (insn >> 19) & 3, op1 = (insn >> 16) & 7;
            const unsigned crn = (insn >> 12) & 0xF, crm = (insn >> 8) & 0xF, op2 = (insn >> 5) & 7;
            if (!l && crn == 2 && rd == 31) { native(false, false); return; }   // hints
            if (!l && crn == 3) { native(false, false); return; }               // barriers
            if (op0 == 1) return;
            const unsigned sysreg = (op0 << 16) | (op1 << 12) | (crn << 8) | (crm << 4) | op2;
            constexpr unsigned kTPIDR_EL0 = (3 << 16) | (3 << 12) | (13 << 8) | (0 << 4) | 2;
            constexpr unsigned kTPIDRRO = (3 << 16) | (3 << 12) | (13 << 8) | (0 << 4) | 3;
            if (l && (sysreg == kTPIDR_EL0 || sysreg == kTPIDRRO)) {
                native(false, false);
                if (rd != 31) t.mov(rd * 8, t.s.tpidr);
                return;
            }
            if (!l && sysreg == kTPIDR_EL0) {
                native(false, false);
                t.mov(t.s.tpidr, t.src(rd));
                return;
            }
            return;
        }
        if (((insn >> 25) & 0x7F) == 0x6B) {   // BR / BLR / RET
            const unsigned opc = (insn >> 21) & 0xF, op3 = (insn >> 10) & 0x3F;
            if (op3 != 0 || opc > 2) return;
            native(false, false);
            info.term = true;
            if (opc == 1) t.movi(30 * 8, static_cast<int64_t>(next_pc));   // BLR sets the link first
            Op& o = t.emit(OpKind::ExitInd);
            o.a = t.src(rn);
            return;
        }
        return;
    }

    case 0x4: case 0x6: case 0xC: case 0xE: {   // loads and stores
        const unsigned grp = (insn >> 27) & 7;
        const bool simd = (insn >> 26) & 1;
        if (grp == 1 && !simd) { info.effects = true; return; }          // exclusive / ordered
        if (grp == 3 && ((insn >> 24) & 1)) return;                       // LDAPUR / STLUR
        if (grp == 3) {                                                   // LDR (literal)
            if (simd) return;
            const unsigned opc = (insn >> 30) & 3;
            const int64_t off = static_cast<int64_t>(sext((insn >> 5) & 0x7FFFF, 19)) * 4;
            const int64_t addr = static_cast<int64_t>(pc + static_cast<uint64_t>(off));
            native(false, false);
            if (opc == 0) t.ld(t.dst(rd), t.s.zero, t.s.zero, 0, addr, 4);
            else if (opc == 1) t.ld(t.dst(rd), t.s.zero, t.s.zero, 0, addr, 8);
            else if (opc == 2) t.lds(t.dst(rd), t.s.zero, t.s.zero, 0, addr, 4, 8);
            return;
        }
        if (grp == 5) {                                                   // load/store pair
            if (simd) return;
            const unsigned opc = (insn >> 30) & 3, mode = (insn >> 23) & 3, l = (insn >> 22) & 1;
            const unsigned rt2 = (insn >> 10) & 0x1F;
            if (l ? opc > 2 : (opc != 0 && opc != 2)) return;
            const int psz = opc == 2 ? 8 : 4;
            const int64_t imm = static_cast<int64_t>(sext((insn >> 15) & 0x7F, 7)) * psz;
            const int64_t off = mode == 1 ? 0 : imm;
            const int b = t.base(rn);
            native(false, false);
            if (l) {
                const bool clobber = mode != 2 && mode != 0 && (rd == rn || rt2 == rn) && rn != 31;
                int nb = 0;
                if (clobber) {   // the write-back value is the base as it was before the loads
                    nb = t.newtmp();
                    t.bini(BinOp::Add, 8, nb, b, imm);
                }
                // Both loads address from the base as it was: when the first one's
                // destination is the base register itself, keep a copy.
                int ab = b;
                if (rd == rn && rn != 31) {
                    ab = t.newtmp();
                    t.mov(ab, b);
                }
                auto load = [&](unsigned r, int64_t o) {
                    if (opc == 1) t.lds(t.dst(r), ab, t.s.zero, 0, o, 4, 8);
                    else t.ld(t.dst(r), ab, t.s.zero, 0, o, psz);
                };
                load(rd, off);
                load(rt2, off + psz);
                if (mode == 1 || mode == 3) {
                    if (clobber) t.mov(b, nb); else t.bini(BinOp::Add, 8, b, b, imm);
                }
            } else {
                t.st(b, t.s.zero, 0, off, t.src(rd), psz);
                const bool wb = mode == 1 || mode == 3;
                if (wb) {
                    // the second store is the last effect, then the base moves
                    t.st(b, t.s.zero, 0, off + psz, t.src(rt2), psz);
                    t.flush_check(next_pc);
                    t.bini(BinOp::Add, 8, b, b, imm);
                    // the check belongs on the store, which is no longer the last op; make it explicit
                    if (t.stored && !t.last) {
                        // find that store (second to last op) and give it the check
                        Op& s2 = t.ir.ops[t.ir.ops.size() - 2];
                        if (s2.kind == OpKind::St && !(s2.flags & kFlagChk)) {
                            s2.flags |= kFlagChk;
                            s2.imm2 = static_cast<int64_t>(next_pc);
                        }
                    }
                } else {
                    t.st(b, t.s.zero, 0, off + psz, t.src(rt2), psz);
                }
            }
            if (!l) t.flush_check(next_pc);
            return;
        }
        if (grp == 7 && !simd && ((insn >> 24) & 1) == 0 && ((insn >> 21) & 1) && ((insn >> 10) & 3) == 0)
            return;                                                       // LSE atomics
        if (grp != 7 || simd) return;
        // load/store register
        const unsigned size = (insn >> 30) & 3, opc = (insn >> 22) & 3;
        if (size == 3 && ((insn >> 24) & 1) == 0 && ((insn >> 21) & 1) && ((insn >> 10) & 1)) return;   // LDRAA
        const unsigned scale = size;
        int idx = t.s.zero, idx_shift = 0;
        int64_t off = 0, wbimm = 0;
        unsigned mode = 0;   // 0 plain, 1 post, 3 pre
        if ((insn >> 24) & 1) {
            off = static_cast<int64_t>(((insn >> 10) & 0xFFF) << scale);
        } else if (((insn >> 21) & 1) && ((insn >> 10) & 3) == 2) {
            const unsigned rm = (insn >> 16) & 0x1F, option = (insn >> 13) & 7, sbit = (insn >> 12) & 1;
            if (option != 2 && option != 3 && option != 6 && option != 7) return;
            idx_shift = sbit ? static_cast<int>(scale) : 0;
            if (option == 3 || option == 7) {
                idx = t.src(rm);
            } else {
                // extension happens before the shift; do it into a temporary
                idx = t.newtmp();
                t.ext(idx, t.src(rm), 4, option == 6, 8);
            }
        } else {
            wbimm = static_cast<int64_t>(sext((insn >> 12) & 0x1FF, 9));
            mode = (insn >> 10) & 3;
            if (mode == 2) mode = 0;
            off = (mode == 1) ? 0 : wbimm;
        }
        // PRFM and friends: size 3 with a sign-extending opcode do nothing at all
        if (opc >= 2 && size == 3) { native(false, false); return; }
        native(false, false);
        const int b = t.base(rn);
        const bool wb = mode == 1 || mode == 3;
        if (opc == 0) {   // store
            t.st(b, idx, idx_shift, off, t.src(rd), 1 << size);
            if (wb) {
                t.bini(BinOp::Add, 8, b, b, wbimm);
                if (!t.last && t.ir.ops.size() >= 2) {   // the check belongs on the store
                    Op& s2 = t.ir.ops[t.ir.ops.size() - 2];
                    if (s2.kind == OpKind::St) { s2.flags |= kFlagChk; s2.imm2 = static_cast<int64_t>(next_pc); }
                }
            } else {
                t.flush_check(next_pc);
            }
            return;
        }
        // loads
        const bool clobber = mode == 3 && rd == rn && rn != 31;
        int nb = 0;
        if (clobber) {
            nb = t.newtmp();
            t.bini(BinOp::Add, 8, nb, b, wbimm);
        }
        const int abase = clobber ? nb : b;
        const int64_t aoff = clobber ? 0 : off;
        const int d = t.dst(rd);
        if (opc == 1) {   // zero extending
            t.ld(d, abase, idx, idx_shift, aoff, 1 << size);
        } else {          // sign extending: opc 2 -> 64-bit destination, opc 3 -> 32-bit
            t.lds(d, abase, idx, idx_shift, aoff, 1 << size, opc == 3 ? 4 : 8);
        }
        if (wb) {
            if (clobber) t.mov(b, nb); else t.bini(BinOp::Add, 8, b, b, wbimm);
        }
        return;
    }

    case 0x5: case 0xD: {   // data processing, register
        if (((insn >> 24) & 0x1F) == 0x0A) {   // logical, shifted register
            const unsigned opc = (insn >> 29) & 3, shift = (insn >> 22) & 3, negate = (insn >> 21) & 1;
            const unsigned rm = (insn >> 16) & 0x1F, amount = (insn >> 10) & 0x3F;
            if (!is64 && amount >= 32) return;
            const int b = shifted(t, rm, shift, amount, sz);
            const int a = t.src(rn);
            if (opc == 3) {   // ANDS / BICS
                native(false, true);
                if (flags_live) {
                    Op& o = t.emit(OpKind::A64BinS);
                    o.cc = static_cast<uint8_t>(negate ? BinOp::Andn : BinOp::And); o.sz = static_cast<uint8_t>(sz);
                    o.d = t.dst(rd); o.a = a; o.b = b; o.flags = kFlagEager;
                } else if (rd != 31) {
                    t.bin(negate ? BinOp::Andn : BinOp::And, sz, t.dst(rd), a, b);
                }
                return;
            }
            native(false, false);
            if (rd == 31) return;
            const BinOp op = opc == 0 ? (negate ? BinOp::Andn : BinOp::And)
                           : opc == 1 ? (negate ? BinOp::Orn : BinOp::Or)
                                      : (negate ? BinOp::Eon : BinOp::Xor);
            t.bin(op, sz, rd * 8, a, b);
            return;
        }
        if (((insn >> 24) & 0x1F) == 0x0B && !((insn >> 21) & 1)) {   // add/sub, shifted register
            const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
            const unsigned shift = (insn >> 22) & 3, rm = (insn >> 16) & 0x1F, amount = (insn >> 10) & 0x3F;
            if (shift == 3) return;
            if (!is64 && amount >= 32) { /* the interpreter masks it; so do the shift ops */ }
            const int b = shifted(t, rm, shift, amount, sz);
            const int a = t.src(rn);
            const BinOp op = sub ? BinOp::Sub : BinOp::Add;
            if (!setflags) {
                native(false, false);
                if (rd != 31) t.bin(op, sz, rd * 8, a, b);
                return;
            }
            native(false, true);
            if (flags_live) {
                Op& o = t.emit(OpKind::A64BinS);
                o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(sz);
                o.d = t.dst(rd); o.a = a; o.b = b; o.flags = kFlagEager;
            } else if (rd != 31) {
                t.bin(op, sz, t.dst(rd), a, b);
            }
            return;
        }
        if (((insn >> 24) & 0x1F) == 0x0B && ((insn >> 21) & 1)) {   // add/sub, extended register
            const bool sub = (insn >> 30) & 1, setflags = (insn >> 29) & 1;
            const unsigned rm = (insn >> 16) & 0x1F, option = (insn >> 13) & 7, imm3 = (insn >> 10) & 7;
            int b = t.src(rm);
            if (option != 3 && option != 7) {
                const int e = t.newtmp();
                static const int szs[8] = {1, 2, 4, 8, 1, 2, 4, 8};
                t.ext(e, b, szs[option], option >= 4, 8);
                b = e;
            }
            if (imm3) {
                const int e = t.newtmp();
                t.bini(BinOp::Shl, 8, e, b, imm3);
                b = e;
            }
            const int a = t.base(rn);
            const BinOp op = sub ? BinOp::Sub : BinOp::Add;
            if (!setflags) {
                native(false, false);
                t.bin(op, sz, t.dst_sp(rd), a, b);
                return;
            }
            native(false, true);
            if (flags_live) {
                Op& o = t.emit(OpKind::A64BinS);
                o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(sz);
                o.d = t.dst(rd); o.a = a; o.b = b; o.flags = kFlagEager;
            } else if (rd != 31) {
                t.bin(op, sz, t.dst(rd), a, b);
            }
            return;
        }
        if (((insn >> 21) & 0xFF) == 0xD0) {   // add/sub with carry: reads C, maybe writes NZCV
            info.writes_all = (insn >> 29) & 1;
            return;
        }
        if (((insn >> 21) & 0xFF) == 0xD2 && (((insn >> 10) & 3) == 0 || ((insn >> 10) & 3) == 2)) {   // CCMP / CCMN
            const bool reg_form = ((insn >> 10) & 3) == 0;
            const bool sub = (insn >> 30) & 1;
            const unsigned f = (insn >> 16) & 0x1F, cond = (insn >> 12) & 0xF, nzcv_imm = insn & 0xF;
            native(true, true);
            Op& o = t.emit(reg_form ? OpKind::A64Ccmp : OpKind::A64CcmpI);
            o.cc = static_cast<uint8_t>(cond); o.sz = static_cast<uint8_t>(sz);
            o.a = t.src(rn);
            if (reg_form) o.b = t.src(f); else o.d = static_cast<int32_t>(f);
            o.imm = sub ? 0 : 1; o.imm2 = nzcv_imm;
            return;
        }
        if (((insn >> 21) & 0xFF) == 0xD4) {   // conditional select
            const unsigned rm = (insn >> 16) & 0x1F, cond = (insn >> 12) & 0xF, o2 = (insn >> 10) & 3;
            const bool o1 = (insn >> 30) & 1;
            native(true, false);
            if (rd == 31) return;
            Op& o = t.emit(OpKind::A64Csel);
            o.cc = static_cast<uint8_t>(cond); o.sz = static_cast<uint8_t>(sz);
            o.d = rd * 8; o.a = t.src(rn); o.b = t.src(rm);
            o.imm = (o1 ? 2 : 0) + (o2 & 1);
            return;
        }
        if (((insn >> 21) & 0xFF) == 0xD6) {   // 1 or 2 source
            const bool two = !((insn >> 30) & 1);
            const unsigned opcode = (insn >> 10) & 0x3F, rm = (insn >> 16) & 0x1F;
            if (two) {
                BinOp op;
                switch (opcode) {
                    case 0x02: op = BinOp::UDiv0; break;
                    case 0x03: op = BinOp::SDiv0; break;
                    case 0x08: op = BinOp::Shl; break;
                    case 0x09: op = BinOp::Shr; break;
                    case 0x0A: op = BinOp::Sar; break;
                    case 0x0B: op = BinOp::Ror; break;
                    default: return;
                }
                native(false, false);
                if (rd != 31) t.bin(op, sz, rd * 8, t.src(rn), t.src(rm));
                return;
            }
            if (rm != 0) return;
            UnOp op;
            int usz = sz;
            switch (opcode) {
                case 0x00: op = UnOp::Rbit; break;
                case 0x01: op = UnOp::Rev16; break;
                case 0x02: op = is64 ? UnOp::Rev32 : UnOp::Rev; break;
                case 0x03: if (!is64) return; op = UnOp::Rev; break;
                case 0x04: op = UnOp::Clz; break;
                default: return;
            }
            native(false, false);
            if (rd == 31) return;
            Op& o = t.emit(OpKind::Un);
            o.cc = static_cast<uint8_t>(op); o.sz = static_cast<uint8_t>(usz); o.d = rd * 8; o.a = t.src(rn);
            return;
        }
        if (((insn >> 24) & 0x1F) == 0x1B) {   // 3 source
            const unsigned op31 = (insn >> 21) & 7, o0 = (insn >> 15) & 1;
            const unsigned rm = (insn >> 16) & 0x1F, ra = (insn >> 10) & 0x1F;
            if (op31 == 0) {   // MADD / MSUB
                native(false, false);
                if (rd == 31) return;
                const int p = t.newtmp();
                t.bin(BinOp::Mul, sz, p, t.src(rn), t.src(rm));
                t.bin(o0 ? BinOp::Sub : BinOp::Add, sz, rd * 8, t.src(ra), p);
                return;
            }
            if (op31 == 1 || op31 == 5) {   // SMADDL / UMADDL and the SUBL forms
                native(false, false);
                if (rd == 31) return;
                const int na = t.newtmp(), nb = t.newtmp(), p = t.newtmp();
                t.ext(na, t.src(rn), 4, op31 == 1, 8);
                t.ext(nb, t.src(rm), 4, op31 == 1, 8);
                t.bin(BinOp::Mul, 8, p, na, nb);
                t.bin(o0 ? BinOp::Sub : BinOp::Add, 8, rd * 8, t.src(ra), p);
                return;
            }
            return;
        }
        return;
    }

    default:
        return;
    }
}

}  // namespace

bool translate_block(GCpu& cpu, const GuestSlots& slots, uint64_t pc, IrBlock& out) {
    const uint8_t* end = nullptr;
    const uint8_t* p0 = nullptr;
    try {
        p0 = cpu.mem().code_window(pc, &end);
    } catch (...) {
        return false;
    }
    // A block stays inside one 4 KiB granule, which is what invalidation tracks.
    const uint64_t to_granule_end = ((pc >> kCodeBits) + 1) << kCodeBits;
    uint64_t room = to_granule_end - pc;
    if (static_cast<uint64_t>(end - p0) < room) room = static_cast<uint64_t>(end - p0);
    const size_t max_insns = static_cast<size_t>(room / 4) < 64 ? static_cast<size_t>(room / 4) : 64;
    if (max_insns == 0) return false;

    struct Plan {
        uint32_t w;
        Info info;
    };
    std::vector<Plan> plans;
    // Pass 1: what each instruction is.
    for (size_t i = 0; i < max_insns; ++i) {
        Plan pl;
        std::memcpy(&pl.w, p0 + i * 4, 4);
        IrBlock scratch;
        Tr dry(slots, scratch);
        emit_insn(dry, pl.w, pc + i * 4, true, pl.info);
        // A branch the frontend does not translate still ends the block.
        if (!pl.info.native && ((pl.w >> 25) & 0xE) == 0xA) pl.info.term = true;
        plans.push_back(pl);
        if (pl.info.term) break;
    }
    const size_t n = plans.size();

    // Which flag writes can anyone see?  At the end of the block, everyone can.
    std::vector<char> live_after(n);
    {
        bool live = true;
        for (size_t i = n; i-- > 0;) {
            live_after[i] = live;
            if (plans[i].info.writes_all) live = false;
            if (plans[i].info.reads) live = true;
        }
    }

    out.start = pc;
    Tr t(slots, out);
    uint64_t cur = pc;
    for (size_t i = 0; i < n; ++i) {
        const uint32_t w = plans[i].w;
        t.cur_off = static_cast<uint32_t>(cur - pc);
        t.tmp_next = 1;
        t.stored = false;
        t.last = i + 1 == n;
        const uint64_t next = cur + 4;
        Info info;
        const size_t before = out.ops.size();
        ++out.insns;
        emit_insn(t, w, cur, live_after[i] != 0, info);
        if (!info.native) {
            --out.insns;
            out.ops.resize(before);   // nothing should have been emitted; be sure
            Op& o = t.emit(OpKind::Interp);
            o.imm = static_cast<int64_t>(cur);
            o.imm2 = static_cast<int64_t>(next);
            o.c = static_cast<int32_t>((w >> 21) & 0x1FF);   // for the statistics
            if (info.effects) out.effects = true;
        }
        cur = next;
    }
    out.guest_bytes = static_cast<uint32_t>(cur - pc);
    if (!(plans.back().info.native && plans.back().info.term)) {
        t.cur_off = static_cast<uint32_t>(cur - pc);
        Op& o = t.emit(OpKind::Exit);
        o.imm = static_cast<int64_t>(cur);
    }
    return out.insns > 0;
}

}  // namespace jit
