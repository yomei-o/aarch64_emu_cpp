// Signal delivery.
//
// This exists because of a specific discovery: CPython's bundled OpenSSL detects
// CPU features by *executing* them. `_armv8_sm3_probe` is literally one SM3
// instruction and a `ret`, run under a SIGILL handler — and on musl OpenSSL takes
// that path rather than reading AT_HWCAP, because its getauxval branch is guarded
// on glibc.
//
// So "unimplemented instruction" is not always an emulator gap to be filled. Here
// it is *the answer the guest is asking for*, and the only way to give it is the
// way the kernel does: build a signal frame and call the handler. Implementing
// SM3, SM4, SHA512 and the rest instead would answer "yes" to every probe and
// commit us to implementing the whole crypto extension.
//
// The frame layout is the AArch64 one from the kernel's sigcontext.h. A handler
// that immediately siglongjmps — which is what a probe does — barely reads it, but
// Python installs real handlers too, so it is filled in properly.
#include "syscalls.h"
#include <cstring>
#include <cstdio>

namespace a64 {

namespace {
// struct sigcontext, at the end of the ucontext.
constexpr uint64_t kUcMcontextOff = 176;
constexpr uint64_t kScRegsOff = 8;      // regs[31] follows fault_address
constexpr uint64_t kScSpOff = 8 + 31 * 8;
constexpr uint64_t kScPcOff = kScSpOff + 8;
constexpr uint64_t kScPstateOff = kScPcOff + 8;
constexpr uint64_t kSiginfoSize = 128;
constexpr uint64_t kFrameSize = kSiginfoSize + kUcMcontextOff + 288 + 512;
}  // namespace

bool Syscalls::deliver_signal(int sig, uint64_t fault_addr) {
    if (sig < 0 || sig >= 64) return false;
    const Handler& h = handlers_[sig];
    // 0 = SIG_DFL, 1 = SIG_IGN. Neither is something we can act on usefully: the
    // default for SIGILL is to kill the process, which is what failing already does.
    if (h.func <= 1) return false;

    // The frame goes below the current stack, 16-byte aligned as the ABI requires.
    uint64_t frame = (cpu_.sp - kFrameSize) & ~15ull;
    mem_.set(frame, 0, kFrameSize);

    const uint64_t siginfo = frame;
    const uint64_t uc = frame + kSiginfoSize;
    const uint64_t sc = uc + kUcMcontextOff;

    mem_.write<uint32_t>(siginfo + 0, static_cast<uint32_t>(sig));   // si_signo
    mem_.write<uint32_t>(siginfo + 8, 1);                            // si_code: ILL_ILLOPC
    mem_.write<uint64_t>(siginfo + 16, fault_addr);                  // si_addr

    mem_.write<uint64_t>(sc + 0, fault_addr);                        // fault_address
    for (int i = 0; i < 31; ++i) mem_.write<uint64_t>(sc + kScRegsOff + i * 8, cpu_.x[i]);
    mem_.write<uint64_t>(sc + kScSpOff, cpu_.sp);
    mem_.write<uint64_t>(sc + kScPcOff, cpu_.pc);
    mem_.write<uint64_t>(sc + kScPstateOff, cpu_.nzcv());

    sig_frames_.push_back({frame, cpu_.save_regs()});
    if (trace)
        std::fprintf(stderr, "[sig] %d at %016llX -> handler %016llX (frame %016llX)\n", sig,
                     (unsigned long long)fault_addr, (unsigned long long)h.func,
                     (unsigned long long)frame);

    cpu_.sp = frame;
    cpu_.setx(0, static_cast<uint64_t>(sig));
    cpu_.setx(1, siginfo);
    cpu_.setx(2, uc);
    // Returning from the handler lands on the restorer, which issues rt_sigreturn.
    // musl always supplies one; if a guest does not, point at a magic address the
    // CPU will trap on rather than letting it run off into whatever is there.
    cpu_.setx(30, h.restorer ? h.restorer : kSigreturnMagic);
    cpu_.pc = h.func;
    return true;
}

// rt_sigreturn: put back everything the frame saved. A probe never gets here — it
// longjmps out — but a real handler that returns must resume exactly where it was.
int64_t Syscalls::sys_rt_sigreturn() {
    if (sig_frames_.empty()) return -22;
    const SigFrame f = sig_frames_.back();
    sig_frames_.pop_back();
    const uint64_t sc = f.frame + kSiginfoSize + kUcMcontextOff;
    for (int i = 0; i < 31; ++i) cpu_.x[i] = mem_.read<uint64_t>(sc + kScRegsOff + i * 8);
    cpu_.sp = mem_.read<uint64_t>(sc + kScSpOff);
    cpu_.pc = mem_.read<uint64_t>(sc + kScPcOff);
    cpu_.set_nzcv(static_cast<uint32_t>(mem_.read<uint64_t>(sc + kScPstateOff)));
    return static_cast<int64_t>(cpu_.xr(0));
}

// rt_sigaction: remember the handler. The struct is
//   { void *handler; unsigned long flags; void *restorer; sigset_t mask; }
int64_t Syscalls::sys_rt_sigaction(int sig, uint64_t act, uint64_t oact) {
    if (sig < 0 || sig >= 64) return -22;
    if (oact) {
        mem_.write<uint64_t>(oact + 0, handlers_[sig].func);
        mem_.write<uint64_t>(oact + 8, handlers_[sig].flags);
        mem_.write<uint64_t>(oact + 16, handlers_[sig].restorer);
    }
    if (act) {
        handlers_[sig].func = mem_.read<uint64_t>(act + 0);
        handlers_[sig].flags = mem_.read<uint64_t>(act + 8);
        handlers_[sig].restorer = mem_.read<uint64_t>(act + 16);
    }
    return 0;
}

}  // namespace a64
