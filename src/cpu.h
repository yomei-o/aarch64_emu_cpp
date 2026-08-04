// An AArch64 (A64) user-mode interpreter.
//
// A64 is a much kinder target than x86: every instruction is exactly four bytes,
// little-endian, and the encoding is a clean field layout rather than a prefix
// soup. There is no segmentation, no operand-size prefix, no ModRM. The whole
// decoder is a switch on bits 28..25 followed by sub-decoding, which is how the
// architecture reference manual itself organises it — so cpu.cpp is laid out in
// the same order, and an instruction can be found by the group name the ARM ARM
// gives it.
//
// The two things that do bite:
//
//  - **Register 31 is not one register.** In most encodings it reads as zero
//    (XZR/WZR) and discards writes; in a handful — the base of a load/store, the
//    operand of ADD/SUB immediate, the destination of ADDS with certain forms — it
//    means SP. Getting this wrong is silent, so the two cases go through different
//    accessors (`xr`/`setx` vs `xsp`/`setxsp`) and never through a raw index.
//  - **W-register writes zero the top half.** A 32-bit result always clears bits
//    63..32 of the destination, unlike x86 where a 16-bit write preserves them.
//    That is handled in one place, `setw`.
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include "memory.h"

namespace a64 {

struct CpuError {
    std::string what;
    uint64_t pc;
    uint32_t insn;
};

// A 128-bit SIMD register. Kept as two halves rather than a compiler extension so
// the code builds the same under MSVC, gcc and emscripten.
struct V128 {
    uint64_t lo = 0, hi = 0;
};

class Cpu {
public:
    explicit Cpu(Memory& mem) : mem_(mem) {}

    uint64_t x[31] = {0};       // X0..X30; there is no x[31] on purpose (see below)
    uint64_t sp = 0;
    uint64_t pc = 0;
    bool n = false, z = false, c = false, v = false;   // NZCV
    V128 vreg[32] = {};
    uint32_t fpcr = 0, fpsr = 0;
    uint64_t tpidr_el0 = 0;     // thread pointer; the TLS base for a Linux guest

    bool halted = false;
    int exit_code = 0;
    uint64_t insns = 0;
    uint64_t max_insns = 0;     // 0 = unlimited; a runaway guard for tests
    // Print PC every N instructions. A guest that stops making progress looks
    // exactly like one doing a lot of work; sampling tells them apart in seconds.
    uint64_t sample_every = 0, sample_left = 0;

    // Register 31 as zero (XZR): the common case.
    uint64_t xr(unsigned i) const { return i == 31 ? 0 : x[i]; }
    void setx(unsigned i, uint64_t val) { if (i != 31) x[i] = val; }
    uint32_t wr(unsigned i) const { return static_cast<uint32_t>(xr(i)); }
    // A 32-bit destination write clears the upper half. One place, so it cannot be
    // forgotten in an individual instruction.
    void setw(unsigned i, uint32_t val) { if (i != 31) x[i] = val; }
    // Register 31 as the stack pointer: load/store base, ADD/SUB immediate, MOV to SP.
    uint64_t xsp(unsigned i) const { return i == 31 ? sp : x[i]; }
    void setxsp(unsigned i, uint64_t val) { if (i == 31) sp = val; else x[i] = val; }

    // Width-generic helpers so an instruction can be written once for W and X.
    uint64_t reg(unsigned i, bool is64) const { return is64 ? xr(i) : wr(i); }
    void setreg(unsigned i, bool is64, uint64_t val) {
        if (is64) setx(i, val); else setw(i, static_cast<uint32_t>(val));
    }

    // SVC handler: the OS personality. Returns false to stop the machine.
    std::function<bool(uint32_t imm)> on_svc;
    // Called for an instruction the decoder does not implement, before failing, so
    // a host can log or count it.
    std::function<void(uint32_t insn, uint64_t pc)> on_undefined;

    void run() { while (!halted) step(); }
    void step();

    Memory& mem() { return mem_; }

    bool cond_holds(unsigned cond) const;
    void set_nzcv_from(uint64_t result, bool is64, bool carry, bool overflow) {
        n = is64 ? ((result >> 63) & 1) : ((result >> 31) & 1);
        z = (is64 ? result : (result & 0xFFFFFFFFull)) == 0;
        c = carry; v = overflow;
    }
    uint32_t nzcv() const {
        return (uint32_t(n) << 31) | (uint32_t(z) << 30) | (uint32_t(c) << 29) | (uint32_t(v) << 28);
    }
    void set_nzcv(uint32_t val) {
        n = (val >> 31) & 1; z = (val >> 30) & 1; c = (val >> 29) & 1; v = (val >> 28) & 1;
    }

    [[noreturn]] void fail(const std::string& why, uint32_t insn) const;

private:
    Memory& mem_;
    // The address of the instruction being executed. pc has already advanced by the
    // time a handler runs, and PC-relative forms (ADR, B, literal loads) need the
    // original — keeping it here beats threading it through every handler.
    uint64_t cur_pc_ = 0;

    // Instruction groups, in the order the ARM ARM lists them (bits 28..25).
    void exec_pc_rel(uint32_t insn);
    void exec_addsub_imm(uint32_t insn);
    void exec_logical_imm(uint32_t insn);
    void exec_move_wide(uint32_t insn);
    void exec_bitfield(uint32_t insn);
    void exec_extract(uint32_t insn);
    void exec_branch(uint32_t insn);
    void exec_loadstore(uint32_t insn);
    void exec_dp_register(uint32_t insn);
    void exec_fp_simd(uint32_t insn);
};

// DecodeBitMasks: the "N:immr:imms" form behind both the logical immediates and
// the bitfield instructions. Returns false for a reserved encoding. Either mask
// pointer may be null.  selects the logical-immediate rules, where the
// all-ones case is reserved.
bool decode_bit_masks(bool n, unsigned imms, unsigned immr, bool immediate, bool is64,
                      uint64_t* wmask, uint64_t* tmask);

}  // namespace a64
