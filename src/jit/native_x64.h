// A small x86-64 assembler: just the instructions the native backend emits.
//
// Code is assembled into a buffer that will be copied to `base` afterwards, so a
// jump to a fixed address (the shared exit stub, a helper) can be a plain rel32.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace jit {
namespace x64 {

enum Reg : int { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };
// condition codes, as the low nibble of Jcc / SETcc / CMOVcc
enum CC : int { O, NO, B, AE, E, NE, BE, A, S, NS, P, NP, L, GE, LE, G };
// the eight classic ALU operations, as the /digit of the 0x81 group
enum Alu : int { ADD = 0, OR = 1, ADC = 2, SBB = 3, AND = 4, SUB = 5, XOR = 6, CMP = 7 };
enum Shift : int { ROL = 0, ROR = 1, SHL = 4, SHR = 5, SAR = 7 };

struct Label {
    int pos = -1;
    std::vector<size_t> fixups;   // positions of rel32 fields waiting for the target
};

struct Asm {
    std::vector<uint8_t> b;
    const uint8_t* base = nullptr;   // where the code will live

    explicit Asm(const uint8_t* where) : base(where) {}

    size_t pos() const { return b.size(); }
    void u8(uint32_t v) { b.push_back(static_cast<uint8_t>(v)); }
    void u16(uint32_t v) { u8(v); u8(v >> 8); }
    void u32(uint32_t v) { u16(v); u16(v >> 16); }
    void u64(uint64_t v) { u32(static_cast<uint32_t>(v)); u32(static_cast<uint32_t>(v >> 32)); }

    // ---- encoding helpers ---------------------------------------------------------
    // REX: w = 64-bit operand, reg = ModRM.reg, rm = ModRM.rm or SIB base.  `force`
    // emits one even when empty (byte access to SIL, DIL, SPL, BPL).
    void rex(bool w, int reg, int rm, bool force = false) {
        const uint8_t v = 0x40 | (w ? 8 : 0) | ((reg & 8) ? 4 : 0) | ((rm & 8) ? 1 : 0);
        if (v != 0x40 || force) u8(v);
    }
    void modrm_reg(int reg, int rm) { u8(0xC0 | ((reg & 7) << 3) | (rm & 7)); }
    void modrm_mem(int reg, int base_reg, int32_t disp) {
        const int bs = base_reg & 7;
        const int mod = (disp == 0 && bs != 5) ? 0 : (disp >= -128 && disp <= 127) ? 1 : 2;
        u8((mod << 6) | ((reg & 7) << 3) | (bs == 4 ? 4 : bs));
        if (bs == 4) u8(0x24);   // SIB: base only
        if (mod == 1) u8(static_cast<uint32_t>(disp));
        else if (mod == 2) u32(static_cast<uint32_t>(disp));
    }
    // [prefix] REX opcode(s) ModRM(reg, [base + disp])
    void op_m(int prefix, bool w, int opc1, int opc2, int reg, int base_reg, int32_t disp, bool force = false) {
        if (prefix) u8(prefix);
        rex(w, reg, base_reg, force);
        if (opc1) u8(opc1);
        u8(opc2);
        modrm_mem(reg, base_reg, disp);
    }
    void op_r(int prefix, bool w, int opc1, int opc2, int reg, int rm, bool force = false) {
        if (prefix) u8(prefix);
        rex(w, reg, rm, force);
        if (opc1) u8(opc1);
        u8(opc2);
        modrm_reg(reg, rm);
    }

    // ---- moves --------------------------------------------------------------------
    void load64(int r, int base_reg, int32_t d) { op_m(0, true, 0, 0x8B, r, base_reg, d); }
    void load32(int r, int base_reg, int32_t d) { op_m(0, false, 0, 0x8B, r, base_reg, d); }          // zero extends
    void load16u(int r, int base_reg, int32_t d) { op_m(0, false, 0x0F, 0xB7, r, base_reg, d); }
    void load8u(int r, int base_reg, int32_t d) { op_m(0, false, 0x0F, 0xB6, r, base_reg, d); }
    void load8s(int r, int base_reg, int32_t d) { op_m(0, true, 0x0F, 0xBE, r, base_reg, d); }       // to 64 bits
    void load16s(int r, int base_reg, int32_t d) { op_m(0, true, 0x0F, 0xBF, r, base_reg, d); }
    void load32s(int r, int base_reg, int32_t d) { op_m(0, true, 0, 0x63, r, base_reg, d); }
    void store64(int base_reg, int32_t d, int r) { op_m(0, true, 0, 0x89, r, base_reg, d); }
    void store32(int base_reg, int32_t d, int r) { op_m(0, false, 0, 0x89, r, base_reg, d); }
    void store16(int base_reg, int32_t d, int r) { op_m(0x66, false, 0, 0x89, r, base_reg, d); }
    void store8(int base_reg, int32_t d, int r) { op_m(0, false, 0, 0x88, r, base_reg, d, r >= 4 && r < 8); }
    // mov [base + d], imm32 (sign extended to 64 bits)
    void store64_imm(int base_reg, int32_t d, int32_t imm) {
        op_m(0, true, 0, 0xC7, 0, base_reg, d);
        u32(static_cast<uint32_t>(imm));
    }
    void store32_imm(int base_reg, int32_t d, uint32_t imm) {
        op_m(0, false, 0, 0xC7, 0, base_reg, d);
        u32(imm);
    }
    void mov_rr(int dst, int src) { op_r(0, true, 0, 0x89, src, dst); }
    void mov_rr32(int dst, int src) { op_r(0, false, 0, 0x89, src, dst); }
    void movi(int r, int64_t imm) {
        if (imm >= 0 && imm <= 0xFFFFFFFFll) {          // mov r32, imm32 zero extends
            rex(false, 0, r);
            u8(0xB8 + (r & 7));
            u32(static_cast<uint32_t>(imm));
        } else if (imm >= INT32_MIN && imm <= INT32_MAX) {   // mov r64, simm32
            rex(true, 0, r);
            u8(0xC7);
            modrm_reg(0, r);
            u32(static_cast<uint32_t>(imm));
        } else {                                         // movabs
            rex(true, 0, r);
            u8(0xB8 + (r & 7));
            u64(static_cast<uint64_t>(imm));
        }
    }
    void movzx32(int dst, int src, int bits) {           // dst = zero extend low `bits` of src
        if (bits == 8) op_r(0, false, 0x0F, 0xB6, dst, src, src >= 4 && src < 8);
        else if (bits == 16) op_r(0, false, 0x0F, 0xB7, dst, src);
        else mov_rr32(dst, src);
    }
    void movsx64(int dst, int src, int bits) {           // dst = sign extend low `bits` of src to 64
        if (bits == 8) op_r(0, true, 0x0F, 0xBE, dst, src, true);
        else if (bits == 16) op_r(0, true, 0x0F, 0xBF, dst, src);
        else op_r(0, true, 0, 0x63, dst, src);
    }
    void lea(int dst, int base_reg, int32_t d) { op_m(0, true, 0, 0x8D, dst, base_reg, d); }

    // ---- arithmetic -----------------------------------------------------------------
    // dst op= [base + d]
    void alu_rm(int op, bool w, int r, int base_reg, int32_t d) { op_m(0, w, 0, (op << 3) | 3, r, base_reg, d); }
    // [base + d] op= r
    void alu_mr(int op, bool w, int base_reg, int32_t d, int r) { op_m(0, w, 0, (op << 3) | 1, r, base_reg, d); }
    // dst op= src
    void alu_rr(int op, bool w, int dst, int src) { op_r(0, w, 0, (op << 3) | 1, src, dst); }
    void alu_ri(int op, bool w, int r, int32_t imm) {
        rex(w, 0, r);
        if (imm >= -128 && imm <= 127) { u8(0x83); modrm_reg(op, r); u8(static_cast<uint32_t>(imm)); }
        else { u8(0x81); modrm_reg(op, r); u32(static_cast<uint32_t>(imm)); }
    }
    void alu_mi(int op, bool w, int base_reg, int32_t d, int32_t imm) {
        rex(w, 0, base_reg);
        if (imm >= -128 && imm <= 127) { u8(0x83); modrm_mem(op, base_reg, d); u8(static_cast<uint32_t>(imm)); }
        else { u8(0x81); modrm_mem(op, base_reg, d); u32(static_cast<uint32_t>(imm)); }
    }
    void cmp_m32_imm(int base_reg, int32_t d, int8_t imm) { alu_mi(CMP, false, base_reg, d, imm); }
    void test_rr(bool w, int a, int c) { op_r(0, w, 0, 0x85, c, a); }
    void test_rm(bool w, int r, int base_reg, int32_t d) { op_m(0, w, 0, 0x85, r, base_reg, d); }
    void test_ri(bool w, int r, int32_t imm) {
        rex(w, 0, r);
        u8(0xF7); modrm_reg(0, r); u32(static_cast<uint32_t>(imm));
    }
    void imul_rm(bool w, int r, int base_reg, int32_t d) { op_m(0, w, 0x0F, 0xAF, r, base_reg, d); }
    void imul_rr(bool w, int dst, int src) { op_r(0, w, 0x0F, 0xAF, dst, src); }
    void not_r(bool w, int r) { op_r(0, w, 0, 0xF7, 2, r); }
    void neg_r(bool w, int r) { op_r(0, w, 0, 0xF7, 3, r); }
    void shift_cl(int sh, bool w, int r) { op_r(0, w, 0, 0xD3, sh, r); }
    void shift_i(int sh, bool w, int r, int imm) {
        rex(w, 0, r);
        u8(0xC1); modrm_reg(sh, r); u8(imm);
    }
    void bswap(bool w, int r) { rex(w, 0, r); u8(0x0F); u8(0xC8 + (r & 7)); }
    void setcc(int cc, int r) { op_r(0, false, 0x0F, 0x90 + cc, 0, r, r >= 4 && r < 8); }
    void cmov(int cc, bool w, int dst, int src) { op_r(0, w, 0x0F, 0x40 + cc, dst, src); }

    // ---- control flow -----------------------------------------------------------------
    void push(int r) { rex(false, 0, r); u8(0x50 + (r & 7)); }
    void pop(int r) { rex(false, 0, r); u8(0x58 + (r & 7)); }
    void ret() { u8(0xC3); }
    void pushfq() { u8(0x9C); }
    void call_r(int r) { rex(false, 0, r); u8(0xFF); modrm_reg(2, r); }
    void jmp_r(int r) { rex(false, 0, r); u8(0xFF); modrm_reg(4, r); }
    // Jumps to a label in this buffer.
    void bind(Label& l) {
        l.pos = static_cast<int>(pos());
        for (size_t f : l.fixups) patch32(f, static_cast<int32_t>(l.pos - static_cast<int>(f + 4)));
        l.fixups.clear();
    }
    void jcc(int cc, Label& l) {
        u8(0x0F); u8(0x80 + cc);
        rel32(l);
    }
    void jmp(Label& l) {
        u8(0xE9);
        rel32(l);
    }
    // Jumps to a fixed address outside the buffer.
    void jcc_abs(int cc, const uint8_t* target) {
        u8(0x0F); u8(0x80 + cc);
        abs32(target);
    }
    void jmp_abs(const uint8_t* target) {
        u8(0xE9);
        abs32(target);
    }

private:
    void rel32(Label& l) {
        const size_t at = pos();
        u32(0);
        if (l.pos >= 0) patch32(at, static_cast<int32_t>(l.pos - static_cast<int>(at + 4)));
        else l.fixups.push_back(at);
    }
    void abs32(const uint8_t* target) {
        const size_t at = pos();
        u32(0);
        const intptr_t rel = reinterpret_cast<intptr_t>(target) - (reinterpret_cast<intptr_t>(base) + static_cast<intptr_t>(at + 4));
        patch32(at, static_cast<int32_t>(rel));
    }
    void patch32(size_t at, int32_t v) { std::memcpy(&b[at], &v, 4); }
};

}  // namespace x64
}  // namespace jit
