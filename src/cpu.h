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
    // Stop at a *function* and show its arguments. `--sample` finds where the time goes
    // and `--watch` finds who touched an address; this answers "what was it asked for",
    // which is the question when a guest library is about to make a decision from a
    // string. Zero disables it, so the cost is one compare against a register.
    uint64_t pc_watch = 0;
    std::function<void()> on_pc_watch;

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
    // Called for an instruction the decoder does not implement. Returning true
    // means the host dealt with it -- in practice by delivering SIGILL, which is
    // not a workaround but the architecturally correct answer for a CPU that does
    // not have the instruction. Returning false lets the emulator stop and print it.
    std::function<bool(uint32_t insn, uint64_t pc)> on_undefined;

    // Lane accessors on a V128, shared by the interpreter and the SIMD file.
    static uint64_t get_vlane(const V128& v, unsigned esize, unsigned idx) {
        const uint64_t half = (idx * esize >= 8) ? v.hi : v.lo;
        const unsigned sh = ((idx * esize) % 8) * 8;
        const uint64_t m = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
        return (half >> sh) & m;
    }
    static void set_vlane(V128& v, unsigned esize, unsigned idx, uint64_t val) {
        uint64_t& half = (idx * esize >= 8) ? v.hi : v.lo;
        const unsigned sh = ((idx * esize) % 8) * 8;
        const uint64_t m = esize == 8 ? ~0ull : ((1ull << (esize * 8)) - 1);
        half = (half & ~(m << sh)) | ((val & m) << sh);
    }

    // A plain register snapshot, for a signal frame.
    struct Regs { uint64_t x[31], sp, pc; uint32_t nzcv; };
    Regs save_regs() const {
        Regs r{};
        for (int i = 0; i < 31; ++i) r.x[i] = x[i];
        r.sp = sp; r.pc = pc; r.nzcv = nzcv();
        return r;
    }

    // Everything a thread owns. Wider than `Regs`, which only carries what a signal
    // frame needs: a context switch has to preserve the vector registers and the
    // thread pointer too, and a switch that drops them corrupts whichever thread
    // happens to be holding a value there.
    struct Context {
        uint64_t x[31] = {0};
        uint64_t sp = 0, pc = 0, tpidr_el0 = 0;
        V128 vreg[32] = {};
        uint32_t fpcr = 0, fpsr = 0, nzcv = 0;
    };
    Context save_context() const {
        Context c;
        for (int i = 0; i < 31; ++i) c.x[i] = x[i];
        for (int i = 0; i < 32; ++i) c.vreg[i] = vreg[i];
        c.sp = sp; c.pc = pc; c.tpidr_el0 = tpidr_el0;
        c.fpcr = fpcr; c.fpsr = fpsr; c.nzcv = nzcv();
        return c;
    }
    void load_context(const Context& c) {
        for (int i = 0; i < 31; ++i) x[i] = c.x[i];
        for (int i = 0; i < 32; ++i) vreg[i] = c.vreg[i];
        sp = c.sp; pc = c.pc; tpidr_el0 = c.tpidr_el0;
        fpcr = c.fpcr; fpsr = c.fpsr; set_nzcv(c.nzcv);
        // The monitor is not part of the context — it belongs to the CPU, and a
        // switch is precisely the event a real one loses it to. Keeping it across a
        // switch would let a thread's STXR succeed against a LDXR another thread
        // made, which is the one thing the instruction exists to prevent.
        clear_exclusive();
    }
    void clear_exclusive() { excl_valid_ = false; }

    // Preemption, for a multi-threaded guest. Zero — the default — costs one
    // predictable branch per instruction and never fires; the scheduler turns it on
    // only once a second thread exists. Without it a guest that spins on a lock
    // instead of blocking on a futex would never give the CPU back.
    uint64_t preempt_every = 0, preempt_left = 0;
    std::function<void()> on_preempt;

    void run() { run_until(0, false); }

    // Step until `halted`, or -- when `bounded` -- until the PC reaches `stop_pc`.
    //
    // The bounded form is how the Darwin path runs an initializer and `main`, both of
    // which return to a sentinel address rather than exiting. It exists as a method
    // rather than a loop at each call site because the preemption check has to be in
    // *every* run loop: the Darwin loops were written as bare `while (…) step();` and
    // so never preempted, which meant `bsdthread_create` could put four threads on the
    // list and none of them would ever be given the CPU. The guest reported that as a
    // sum of zero, which is exactly what a thread that never ran contributes.
    // Set by a vfork child reaching execve or _exit: the run loop stops so the host
    // can restore the parent. A flag rather than an exception because the parent
    // resumes in the same loop, one instruction later.
    bool stop_requested = false;

    void run_until(uint64_t stop_pc, bool bounded = true) {
        for (;;) {
            while (!halted && !stop_requested && !(bounded && pc == stop_pc)) {
                step();
                if (preempt_left && --preempt_left == 0) {
                    preempt_left = preempt_every;
                    if (on_preempt) on_preempt();
                }
            }
            // A vfork child finished: the host puts the parent back and the loop
            // carries on with it. Handled here rather than at the call sites because
            // there are four of them and a missed one is a run that ends when a
            // *child* exits.
            if (stop_requested && on_stop_requested) {
                stop_requested = false;
                on_stop_requested();
                continue;
            }
            return;
        }
    }
    std::function<void()> on_stop_requested;
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

    // The local exclusive monitor, set by LDXR and consumed by STXR.
    bool excl_valid_ = false;
    uint64_t excl_addr_ = 0;

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
    // SHA1/SHA256, in crypto.cpp. Returns false if the encoding is not one of them.
    bool exec_crypto(uint32_t insn);
};

// DecodeBitMasks: the "N:immr:imms" form behind both the logical immediates and
// the bitfield instructions. Returns false for a reserved encoding. Either mask
// pointer may be null.  selects the logical-immediate rules, where the
// all-ones case is reserved.
bool decode_bit_masks(bool n, unsigned imms, unsigned immr, bool immediate, bool is64,
                      uint64_t* wmask, uint64_t* tmask);

}  // namespace a64
