// The A64 guest's side of the translator: how the engine finds the registers, and
// the Cpu entry points that hand control to it.
#include <cstdlib>
#include <cstring>
#include <string>

#include "engine.h"

namespace jit {

void Glue::fill_slots(GuestSlots& s, GCpu& cpu) {
    auto off = [&](const void* p) {
        return static_cast<int32_t>(reinterpret_cast<const uint8_t*>(p) -
                                    reinterpret_cast<const uint8_t*>(cpu.x));
    };
    s.zero = off(&cpu.jit_tmp[0]);
    s.tmp0 = off(&cpu.jit_tmp[1]);
    s.ntmp = static_cast<int32_t>(sizeof(cpu.jit_tmp) / sizeof(cpu.jit_tmp[0])) - 1;
    s.rip = off(&cpu.pc);
    s.sp = off(&cpu.sp);
    s.tpidr = off(&cpu.tpidr_el0);
}

void Glue::take(const GCpu& c, GuestState& s) {
    std::memcpy(s.x, c.x, sizeof s.x);
    s.sp = c.sp;
    s.pc = c.pc;
    s.tpidr = c.tpidr_el0;
    s.n = c.n; s.z = c.z; s.c = c.c; s.v = c.v;
    std::memcpy(s.vreg, c.vreg, sizeof s.vreg);
    s.fpcr = c.fpcr;
    s.fpsr = c.fpsr;
    s.icount = c.insns;
    s.halted = c.halted;
}

void Glue::put(GCpu& c, const GuestState& s) {
    std::memcpy(c.x, s.x, sizeof s.x);
    c.sp = s.sp;
    c.pc = s.pc;
    c.tpidr_el0 = s.tpidr;
    c.n = s.n; c.z = s.z; c.c = s.c; c.v = s.v;
    std::memcpy(c.vreg, s.vreg, sizeof c.vreg);
    c.fpcr = s.fpcr;
    c.fpsr = s.fpsr;
    c.insns = s.icount;
    c.halted = s.halted;
}

std::string Glue::diff(const GuestState& s1, const GuestState& s2) {
    std::string diff;
    char buf[256];
    auto note = [&](const char* what, uint64_t a, uint64_t c) {
        std::snprintf(buf, sizeof buf, "  %s: jit %016llX  interp %016llX\n", what,
                      (unsigned long long)a, (unsigned long long)c);
        diff += buf;
    };
    for (int i = 0; i < 31; ++i) {
        if (s1.x[i] != s2.x[i]) {
            char name[8];
            std::snprintf(name, sizeof name, "x%d", i);
            note(name, s1.x[i], s2.x[i]);
        }
    }
    if (s1.sp != s2.sp) note("sp", s1.sp, s2.sp);
    if (s1.pc != s2.pc) note("pc", s1.pc, s2.pc);
    if (s1.tpidr != s2.tpidr) note("tpidr", s1.tpidr, s2.tpidr);
    if (s1.n != s2.n || s1.z != s2.z || s1.c != s2.c || s1.v != s2.v)
        note("nzcv", (s1.n << 3) | (s1.z << 2) | (s1.c << 1) | s1.v, (s2.n << 3) | (s2.z << 2) | (s2.c << 1) | s2.v);
    if (s1.icount != s2.icount) note("insns", s1.icount, s2.icount);
    if (s1.halted != s2.halted) note("halted", s1.halted, s2.halted);
    if (std::memcmp(s1.vreg, s2.vreg, sizeof s1.vreg) != 0) diff += "  vector registers differ\n";
    if (s1.fpcr != s2.fpcr || s1.fpsr != s2.fpsr) diff += "  fpcr/fpsr differ\n";
    return diff;
}

}  // namespace jit

namespace a64 {

Cpu::~Cpu() { delete jit_; }

void Cpu::enable_jit(bool on) {
    if (on == (jit_ != nullptr)) return;
    if (on) {
        jit_ = new jit::Engine(*this, mem_);
    } else {
        delete jit_;
        jit_ = nullptr;
    }
}

// On unless A64EMU_JIT=0.  Decided on the first run, so tools that build a Cpu and
// never run it do not pay for an engine.
void Cpu::maybe_enable_jit() {
    jit_checked_ = true;
    const char* v = std::getenv("A64EMU_JIT");
    if (v && v[0] == '0') return;
    // These make every instruction observable; translated code would skip them.
    if (std::getenv("A64EMU_TRACE_RANGE") || std::getenv("A64EMU_SAMPLE")) return;
    enable_jit(true);
}

bool Cpu::jit_usable() const {
    return jit_ && !sample_every && !pc_watch && !mem_.strict && !mem_.watch_hi;
}

bool Cpu::jit_run(uint64_t deadline, uint64_t stop_pc, const bool* yield) {
    // The instruction limit is a runaway guard that step() enforces; stop the blocks
    // at it so that step() still gets to.
    if (max_insns && deadline > max_insns) deadline = max_insns;
    return jit_->run(deadline, stop_pc, yield);
}

}  // namespace a64
