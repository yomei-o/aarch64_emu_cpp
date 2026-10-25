// The one header that says which guest this copy of the translator serves.
//
// Everything else under jit/ is written against the names declared here, so the
// translation cache, the threaded and WebAssembly backends and the verifier can be
// shared between emulators for different CPUs: each repository carries the same
// shared files plus its own glue.h, one frontend, and the code for the ops that only
// its ISA has (flags, special addressing).
//
// This is the AArch64 (A64) one.
#pragma once

#include <cstdint>
#include <string>

#include "../cpu.h"

namespace jit {

using GCpu = a64::Cpu;
using GMemory = a64::Memory;
using GObserver = a64::CodeObserver;
using GFault = a64::CpuError;

// Names of the environment variables that control the translator.
#define JIT_ENV(n) "A64EMU_" n

// Translations are tracked, and invalidated, in units of 2^kCodeBits bytes.
constexpr int kCodeBits = 12;
// This guest has no direct-mapped page cache for the wasm tier to probe inline; the
// numbers are only here so the shared code compiles.
constexpr int kTlbPageBits = 16;
constexpr int kTlbBits = 10;

// Byte offsets, from the start of the guest register file (x0), of the cells
// translated code uses.  The first four are needed by every guest.
struct GuestSlots {
    int32_t zero = 0;      // a cell that always reads zero
    int32_t rip = 0;       // the program counter
    int32_t tmp0 = 0;      // the first temporary
    int32_t ntmp = 0;      // how many temporaries
    int32_t sp = 0;        // the stack pointer (register 31 as a base)
    int32_t tpidr = 0;     // TPIDR_EL0
};

// A guest's machine state as the verifier compares it.
struct GuestState {
    uint64_t x[31];
    uint64_t sp, pc, tpidr;
    bool n, z, c, v;
    a64::V128 vreg[32];
    uint32_t fpcr, fpsr;
    uint64_t icount;
    bool halted;
};

struct Glue {
    // The register file, which is also where the temporaries live.
    static uint8_t* env(GCpu& c) { return reinterpret_cast<uint8_t*>(c.x); }
    static void fill_slots(GuestSlots& s, GCpu& c);

    static uint64_t pc(const GCpu& c) { return c.pc; }
    static void set_pc(GCpu& c, uint64_t v) { c.pc = v; }
    static uint64_t icount(const GCpu& c) { return c.insns; }
    static void add_icount(GCpu& c, uint64_t n) { c.insns += n; }
    // A vfork child reaching execve ends the run loop just as a halt does.
    static bool halted(const GCpu& c) { return c.halted || c.stop_requested; }
    // There are no host hooks in this guest: system calls are SVC instructions.
    static bool in_hook(const GCpu&, uint64_t) { return false; }
    // One instruction through the interpreter.
    static void step(GCpu& c) { c.step(); }
    // Flags are always kept exact in this guest, so there is nothing to settle.
    static void settle(GCpu&) {}

    // Guest memory accesses, as the translated code makes them.
    static uint8_t rd8(GMemory& m, uint64_t a) { return m.read<uint8_t>(a); }
    static uint16_t rd16(GMemory& m, uint64_t a) { return m.read<uint16_t>(a); }
    static uint32_t rd32(GMemory& m, uint64_t a) { return m.read<uint32_t>(a); }
    static uint64_t rd64(GMemory& m, uint64_t a) { return m.read<uint64_t>(a); }
    static void wr8(GMemory& m, uint64_t a, uint8_t v) { m.write<uint8_t>(a, v); }
    static void wr16(GMemory& m, uint64_t a, uint16_t v) { m.write<uint16_t>(a, v); }
    static void wr32(GMemory& m, uint64_t a, uint32_t v) { m.write<uint32_t>(a, v); }
    static void wr64(GMemory& m, uint64_t a, uint64_t v) { m.write<uint64_t>(a, v); }

    // The page cache the wasm tier probes inline; null where the guest has none.
    static const void* tlb_read_base(const GMemory&) { return nullptr; }
    static const void* tlb_write_base(const GMemory&) { return nullptr; }

    // The verifier.
    static void take(const GCpu& c, GuestState& s);
    static void put(GCpu& c, const GuestState& s);
    static std::string diff(const GuestState& a, const GuestState& b);
};

}  // namespace jit
