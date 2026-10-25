// A small AArch64 assembler: just the instructions the native backend emits.
//
// Code is assembled into a buffer that will be copied to `base` afterwards, so a branch to
// a fixed address (the shared exit stub) can be a plain PC-relative one.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace jit {
namespace a64 {

// X0..X30; 31 is SP or XZR depending on the instruction.
constexpr int XZR = 31, SP = 31, LR = 30, FP = 29;
// condition codes
enum CC : int { EQ, NE, HS, LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL };
enum Shift : int { LSL = 0, LSR = 1, ASR = 2, ROR = 3 };

struct Label {
    int pos = -1;                                  // instruction index
    std::vector<std::pair<size_t, int>> fixups;    // (instruction index, kind: 0 = b/bl imm26, 1 = imm19 at bit 5)
};

// opcodes of the shifted-register ALU forms (64-bit)
constexpr uint32_t ADD = 0x8B000000u, SUB = 0xCB000000u, AND = 0x8A000000u, ORR = 0xAA000000u,
                   EOR = 0xCA000000u, BIC = 0x8A200000u, ORN = 0xAA200000u, EON = 0xCA200000u,
                   ANDS = 0xEA000000u, SUBS = 0xEB000000u, ADDS = 0xAB000000u;

struct Asm {
    std::vector<uint32_t> w;
    const uint8_t* base = nullptr;

    explicit Asm(const uint8_t* where) : base(where) {}

    size_t pos() const { return w.size(); }       // in instructions
    size_t bytes() const { return w.size() * 4; }
    void emit(uint32_t v) { w.push_back(v); }

    // ---- moves ----------------------------------------------------------------------
    void movz(int rd, uint32_t imm16, int shift) { emit(0xD2800000u | (static_cast<uint32_t>(shift / 16) << 21) | (imm16 << 5) | rd); }
    void movk(int rd, uint32_t imm16, int shift) { emit(0xF2800000u | (static_cast<uint32_t>(shift / 16) << 21) | (imm16 << 5) | rd); }
    void movn(int rd, uint32_t imm16, int shift) { emit(0x92800000u | (static_cast<uint32_t>(shift / 16) << 21) | (imm16 << 5) | rd); }
    void mov_imm(int rd, uint64_t v) {
        int zeros = 0, ones = 0;
        for (int i = 0; i < 4; ++i) {
            const uint32_t c = static_cast<uint32_t>(v >> (16 * i)) & 0xFFFF;
            if (c == 0) ++zeros;
            if (c == 0xFFFF) ++ones;
        }
        if (ones > zeros) {   // start from all ones: MOVN, then MOVK for the chunks that are not 0xFFFF
            bool first = true;
            for (int i = 0; i < 4; ++i) {
                const uint32_t c = static_cast<uint32_t>(v >> (16 * i)) & 0xFFFF;
                if (c == 0xFFFF) continue;
                if (first) { movn(rd, c ^ 0xFFFF, 16 * i); first = false; }
                else movk(rd, c, 16 * i);
            }
            if (first) movn(rd, 0, 0);   // all ones
            return;
        }
        bool first = true;
        for (int i = 0; i < 4; ++i) {
            const uint32_t c = static_cast<uint32_t>(v >> (16 * i)) & 0xFFFF;
            if (c == 0) continue;
            if (first) { movz(rd, c, 16 * i); first = false; }
            else movk(rd, c, 16 * i);
        }
        if (first) movz(rd, 0, 0);   // zero
    }
    void mov_rr(int rd, int rm) { emit(0xAA0003E0u | (static_cast<uint32_t>(rm) << 16) | rd); }     // orr rd, xzr, rm
    void mov_rr32(int rd, int rm) { emit(0x2A0003E0u | (static_cast<uint32_t>(rm) << 16) | rd); }   // zero extends

    // ---- loads and stores, [rn + imm] ---------------------------------------------------------
    // size: 1, 2, 4, 8.  `off` is a byte offset; scaled when it divides evenly, else unscaled.
    void ldst(uint32_t scaled_op, uint32_t unscaled_op, int size, int rt, int rn, int32_t off) {
        if (off >= 0 && off % size == 0 && off / size < 4096) {
            emit(scaled_op | (static_cast<uint32_t>(off / size) << 10) | (static_cast<uint32_t>(rn) << 5) | rt);
        } else if (off >= -256 && off < 256) {
            emit(unscaled_op | ((static_cast<uint32_t>(off) & 0x1FF) << 12) | (static_cast<uint32_t>(rn) << 5) | rt);
        } else {
            // far: x16 = off; use the register form
            mov_imm(16, static_cast<uint64_t>(static_cast<int64_t>(off)));
            emit(0x8B100000u | (static_cast<uint32_t>(rn) << 5) | 16);   // add x16, rn, x16
            emit(unscaled_op | (16u << 5) | rt);
        }
    }
    void ldr64(int rt, int rn, int32_t off) { ldst(0xF9400000u, 0xF8400000u, 8, rt, rn, off); }
    void ldr32(int rt, int rn, int32_t off) { ldst(0xB9400000u, 0xB8400000u, 4, rt, rn, off); }
    void ldrh(int rt, int rn, int32_t off) { ldst(0x79400000u, 0x78400000u, 2, rt, rn, off); }
    void ldrb(int rt, int rn, int32_t off) { ldst(0x39400000u, 0x38400000u, 1, rt, rn, off); }
    void ldrsb(int rt, int rn, int32_t off) { ldst(0x39800000u, 0x38800000u, 1, rt, rn, off); }   // to 64 bits
    void ldrsh(int rt, int rn, int32_t off) { ldst(0x79800000u, 0x78800000u, 2, rt, rn, off); }
    void ldrsw(int rt, int rn, int32_t off) { ldst(0xB9800000u, 0xB8800000u, 4, rt, rn, off); }
    void str64(int rt, int rn, int32_t off) { ldst(0xF9000000u, 0xF8000000u, 8, rt, rn, off); }
    void str32(int rt, int rn, int32_t off) { ldst(0xB9000000u, 0xB8000000u, 4, rt, rn, off); }
    void strh(int rt, int rn, int32_t off) { ldst(0x79000000u, 0x78000000u, 2, rt, rn, off); }
    void strb(int rt, int rn, int32_t off) { ldst(0x39000000u, 0x38000000u, 1, rt, rn, off); }
    // [rn + rm]
    void ldr64_rr(int rt, int rn, int rm) { emit(0xF8606800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void ldr32_rr(int rt, int rn, int rm) { emit(0xB8606800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void ldrh_rr(int rt, int rn, int rm) { emit(0x78606800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void ldrb_rr(int rt, int rn, int rm) { emit(0x38606800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void str64_rr(int rt, int rn, int rm) { emit(0xF8206800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void str32_rr(int rt, int rn, int rm) { emit(0xB8206800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void strh_rr(int rt, int rn, int rm) { emit(0x78206800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    void strb_rr(int rt, int rn, int rm) { emit(0x38206800u | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rt); }
    // pairs, pre-index store / post-index load, for the frame in the entry code
    void stp_pre(int rt, int rt2, int rn, int32_t off) {
        emit(0xA9800000u | ((static_cast<uint32_t>(off / 8) & 0x7F) << 15) | (static_cast<uint32_t>(rt2) << 10) | (static_cast<uint32_t>(rn) << 5) | rt);
    }
    void ldp_post(int rt, int rt2, int rn, int32_t off) {
        emit(0xA8C00000u | ((static_cast<uint32_t>(off / 8) & 0x7F) << 15) | (static_cast<uint32_t>(rt2) << 10) | (static_cast<uint32_t>(rn) << 5) | rt);
    }
    void stp(int rt, int rt2, int rn, int32_t off) {
        emit(0xA9000000u | ((static_cast<uint32_t>(off / 8) & 0x7F) << 15) | (static_cast<uint32_t>(rt2) << 10) | (static_cast<uint32_t>(rn) << 5) | rt);
    }
    void ldp(int rt, int rt2, int rn, int32_t off) {
        emit(0xA9400000u | ((static_cast<uint32_t>(off / 8) & 0x7F) << 15) | (static_cast<uint32_t>(rt2) << 10) | (static_cast<uint32_t>(rn) << 5) | rt);
    }

    // ---- data processing --------------------------------------------------------------------
    // rd = rn OP rm (w: 32-bit operation).  op: the 64-bit opcode of the shifted-register form.
    void alu(uint32_t op, bool x, int rd, int rn, int rm, int shift = LSL, int amount = 0) {
        emit((x ? op : (op & 0x7FFFFFFFu)) | (static_cast<uint32_t>(shift) << 22) | (static_cast<uint32_t>(rm) << 16) |
             (static_cast<uint32_t>(amount) << 10) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    // add/sub with a 12-bit immediate
    void add_imm(bool x, int rd, int rn, uint32_t imm12) { emit((x ? 0x91000000u : 0x11000000u) | (imm12 << 10) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void sub_imm(bool x, int rd, int rn, uint32_t imm12) { emit((x ? 0xD1000000u : 0x51000000u) | (imm12 << 10) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void cmp_imm(bool x, int rn, uint32_t imm12) { emit((x ? 0xF100001Fu : 0x7100001Fu) | (imm12 << 10) | (static_cast<uint32_t>(rn) << 5)); }
    void cmp(bool x, int rn, int rm) { alu(SUBS, x, XZR, rn, rm); }
    void tst(bool x, int rn, int rm) { alu(ANDS, x, XZR, rn, rm); }
    void mul(bool x, int rd, int rn, int rm) { emit((x ? 0x9B007C00u : 0x1B007C00u) | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void udiv(bool x, int rd, int rn, int rm) { emit((x ? 0x9AC00800u : 0x1AC00800u) | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void sdiv(bool x, int rd, int rn, int rm) { emit((x ? 0x9AC00C00u : 0x1AC00C00u) | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rd); }
    // variable shifts (the amount is taken modulo the register size)
    void shiftv(int type, bool x, int rd, int rn, int rm) {
        emit((x ? 0x9AC02000u : 0x1AC02000u) | (static_cast<uint32_t>(type) << 10) | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    // bitfield moves
    void ubfm(bool x, int rd, int rn, int immr, int imms) {
        emit((x ? 0xD3400000u : 0x53000000u) | (static_cast<uint32_t>(immr) << 16) | (static_cast<uint32_t>(imms) << 10) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    void sbfm(bool x, int rd, int rn, int immr, int imms) {
        emit((x ? 0x93400000u : 0x13000000u) | (static_cast<uint32_t>(immr) << 16) | (static_cast<uint32_t>(imms) << 10) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    void bfm(bool x, int rd, int rn, int immr, int imms) {
        emit((x ? 0xB3400000u : 0x33000000u) | (static_cast<uint32_t>(immr) << 16) | (static_cast<uint32_t>(imms) << 10) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    void lsl_imm(bool x, int rd, int rn, int n) { const int bits = x ? 64 : 32; ubfm(x, rd, rn, (bits - n) % bits, bits - 1 - n); }
    void lsr_imm(bool x, int rd, int rn, int n) { ubfm(x, rd, rn, n, (x ? 63 : 31)); }
    void asr_imm(bool x, int rd, int rn, int n) { sbfm(x, rd, rn, n, (x ? 63 : 31)); }
    void ror_imm(bool x, int rd, int rn, int n) { emit((x ? 0x93C00000u : 0x13800000u) | (static_cast<uint32_t>(rn) << 16) | (static_cast<uint32_t>(n) << 10) | (static_cast<uint32_t>(rn) << 5) | rd); }   // extr rd, rn, rn, #n
    void uxtb(int rd, int rn) { ubfm(false, rd, rn, 0, 7); }
    void uxth(int rd, int rn) { ubfm(false, rd, rn, 0, 15); }
    void sxtb(bool x, int rd, int rn) { sbfm(x, rd, rn, 0, 7); }
    void sxth(bool x, int rd, int rn) { sbfm(x, rd, rn, 0, 15); }
    void sxtw(int rd, int rn) { sbfm(true, rd, rn, 0, 31); }
    // unary
    void rev(bool x, int rd, int rn) { emit((x ? 0xDAC00C00u : 0x5AC00800u) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void rev16(bool x, int rd, int rn) { emit((x ? 0xDAC00400u : 0x5AC00400u) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void rev32(int rd, int rn) { emit(0xDAC00800u | (static_cast<uint32_t>(rn) << 5) | rd); }
    void rbit(bool x, int rd, int rn) { emit((x ? 0xDAC00000u : 0x5AC00000u) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void clz(bool x, int rd, int rn) { emit((x ? 0xDAC01000u : 0x5AC01000u) | (static_cast<uint32_t>(rn) << 5) | rd); }
    void csel(bool x, int rd, int rn, int rm, int cc) {
        emit((x ? 0x9A800000u : 0x1A800000u) | (static_cast<uint32_t>(rm) << 16) | (static_cast<uint32_t>(cc) << 12) | (static_cast<uint32_t>(rn) << 5) | rd);
    }
    void cset(bool x, int rd, int cc) {   // csinc rd, zr, zr, !cc
        emit((x ? 0x9A9F07E0u : 0x1A9F07E0u) | (static_cast<uint32_t>(cc ^ 1) << 12) | rd);
    }

    // ---- control flow -------------------------------------------------------------------------
    void ret() { emit(0xD65F03C0u); }
    void br(int rn) { emit(0xD61F0000u | (static_cast<uint32_t>(rn) << 5)); }
    void blr(int rn) { emit(0xD63F0000u | (static_cast<uint32_t>(rn) << 5)); }
    void brk() { emit(0xD4200000u); }
    void bind(Label& l) {
        l.pos = static_cast<int>(pos());
        for (auto& f : l.fixups) patch(f.first, f.second, l.pos);
        l.fixups.clear();
    }
    void b(Label& l) { branch(0x14000000u, 0, l); }
    void b_cond(int cc, Label& l) { branch(0x54000000u | cc, 1, l); }
    void cbz(bool x, int rt, Label& l) { branch((x ? 0xB4000000u : 0x34000000u) | rt, 1, l); }
    void cbnz(bool x, int rt, Label& l) { branch((x ? 0xB5000000u : 0x35000000u) | rt, 1, l); }
    // To a fixed address outside the buffer.
    void b_abs(const uint8_t* target) { emit(0x14000000u | (rel_words(target) & 0x3FFFFFF)); }
    void b_cond_abs(int cc, const uint8_t* target) { emit(0x54000000u | ((rel_words(target) & 0x7FFFF) << 5) | cc); }

private:
    uint32_t rel_words(const uint8_t* target) const {
        const intptr_t here = reinterpret_cast<intptr_t>(base) + static_cast<intptr_t>(w.size() * 4);
        return static_cast<uint32_t>((reinterpret_cast<intptr_t>(target) - here) / 4);
    }
    void branch(uint32_t opc, int kind, Label& l) {
        const size_t at = pos();
        emit(opc);
        if (l.pos >= 0) patch(at, kind, l.pos);
        else l.fixups.push_back({at, kind});
    }
    void patch(size_t at, int kind, int target) {
        const int32_t rel = target - static_cast<int32_t>(at);
        if (kind == 0) w[at] |= static_cast<uint32_t>(rel) & 0x3FFFFFF;
        else w[at] |= (static_cast<uint32_t>(rel) & 0x7FFFF) << 5;
    }
};

}  // namespace a64
}  // namespace jit
