// The Linux AArch64 kernel interface.
//
// A static guest talks to the outside world only through `svc #0`, with the call
// number in x8 and arguments in x0..x5. That makes this file the entire OS as far
// as the guest is concerned — and the reason a *static* binary is the right first
// target: there is no dynamic loader, no libc to hook, nothing but this.
//
// AArch64 uses the "generic" syscall numbering (asm-generic/unistd.h), which is
// not the x86-64 numbering: write is 64, not 1. Numbers here are that table.
//
// Errors are returned the way Linux returns them: a negative errno in x0, not a
// separate flag.
#include "syscalls.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace a64 {

namespace {
constexpr int64_t kEBADF = -9, kENOSYS = -38, kEINVAL = -22, kEFAULT = -14;
}

Syscalls::Syscalls(Cpu& cpu, Memory& mem) : cpu_(cpu), mem_(mem) {
    cpu_.on_svc = [this](uint32_t imm) { return svc(imm); };
}

bool Syscalls::svc(uint32_t imm) {
    // Linux traps with `svc #0`, Darwin with `svc #0x80`. The immediate is the
    // personality selector, so a Mach-O guest and an ELF guest need no mode flag.
    if (imm == 0x80) return svc_darwin();
    // A third personality on the same instruction: the stubs behind the synthesised
    // dyld vtable trap here with the slot index in w16.
    if (imm == 0x81) {
        cpu_.setx(0, static_cast<uint64_t>(dyld_api_stub(static_cast<uint32_t>(cpu_.wr(16)))));
        return true;
    }
    if (imm != 0) {
        cpu_.setx(0, static_cast<uint64_t>(kENOSYS));
        return true;
    }
    const uint64_t nr = cpu_.xr(8);
    const uint64_t a0 = cpu_.xr(0), a1 = cpu_.xr(1), a2 = cpu_.xr(2);
    const uint64_t a3 = cpu_.xr(3), a4 = cpu_.xr(4), a5 = cpu_.xr(5);
    int64_t r = kENOSYS;

    if (trace) {
        std::fprintf(stderr, "[sys] %llu(%llX, %llX, %llX)\n",
                     static_cast<unsigned long long>(nr), static_cast<unsigned long long>(a0),
                     static_cast<unsigned long long>(a1), static_cast<unsigned long long>(a2));
    }

    switch (nr) {
        case 64: r = sys_write(static_cast<int>(a0), a1, a2); break;
        case 63: r = sys_read(static_cast<int>(a0), a1, a2); break;
        case 66: r = sys_writev(static_cast<int>(a0), a1, a2); break;
        case 65: r = sys_readv(static_cast<int>(a0), a1, a2); break;
        // exit ends *this thread*; exit_group ends the process. They are the same
        // thing right up until a second thread exists, and then they are not.
        case 93: thread_exit(static_cast<int>(a0 & 0xFF)); return true;
        case 94:
            cpu_.exit_code = static_cast<int>(a0 & 0xFF);
            cpu_.halted = true;
            return true;
        case 214: r = sys_brk(a0); break;
        case 222: r = sys_mmap(a0, a1, a2, a3, static_cast<int>(a4), a5); break;
        case 215: r = 0; break;                                // munmap: the arena never shrinks
        // mremap: the arena only grows, so "move it" is a fresh mapping plus a copy.
        // Refusing instead makes musl fall back to a path that retries forever.
        case 216: {
            const uint64_t old_addr = a0, old_len = a1, new_len = a2;
            if (new_len <= old_len) { r = static_cast<int64_t>(old_addr); break; }
            const int64_t dst = sys_mmap(0, new_len, 0, 0x20, -1, 0);
            std::vector<uint8_t> tmp(old_len);
            mem_.read_bytes(old_addr, tmp.data(), old_len);
            mem_.write_bytes(static_cast<uint64_t>(dst), tmp.data(), old_len);
            r = dst;
            break;
        }
        case 226: r = 0; break;                                // mprotect: no protection modelled
        // ---- threads ----------------------------------------------------------
        // aarch64's clone argument order is flags, stack, parent_tid, **tls**,
        // child_tid -- tls and child_tid are the other way round from x86-64, and
        // swapping them hands the new thread a thread pointer that is really a
        // pointer to a tid. These three write x0 themselves and return early: after
        // a context switch the shared tail below would write it into the wrong
        // thread.
        case 220:
            cpu_.setx(0, static_cast<uint64_t>(sys_clone(a0, a1, a2, a3, a4)));
            return true;
        case 98: sys_futex(a0, static_cast<int>(a1), static_cast<uint32_t>(a2)); return true;
        case 124: sys_sched_yield(); return true;              // sched_yield
        case 96:                                               // set_tid_address
            tid_address_ = a0;
            if (!threads_.empty()) threads_[cur_thread_].clear_child_tid = a0;
            r = static_cast<int64_t>(current_tid());
            break;
        case 99: r = 0; break;                                 // set_robust_list
        // membarrier. Guest threads are interleaved on one interpreter, never
        // concurrent, so every barrier is already satisfied and 0 is the truth
        // rather than a stub. CMD_QUERY (cmd 0) reads the same 0 as "no expedited
        // commands available", which is also true, and CPython falls back cleanly.
        case 283: r = 0; break;
        case 261: r = kEINVAL; break;                          // prlimit64
        case 278: {                                            // getrandom
            for (uint64_t i = 0; i < a1; ++i)
                mem_.write<uint8_t>(a0 + i, static_cast<uint8_t>(0x9E * (i + 1) + 0x37));
            r = static_cast<int64_t>(a1);
            break;
        }
        case 113: {                                            // clock_gettime
            const uint64_t ns = host_nanos();
            mem_.write<uint64_t>(a1, ns / 1000000000ull);
            mem_.write<uint64_t>(a1 + 8, ns % 1000000000ull);
            r = 0;
            break;
        }
        // ---- files -----------------------------------------------------------
        // AArch64 has no plain open(2): everything is openat with AT_FDCWD, which
        // is why a guest that "never opens anything" is really just calling 56.
        case 56: r = files.open(guest_str(a1), static_cast<int>(a2), static_cast<int>(a3)); break;
        case 57: r = files.close(static_cast<int>(a0)); break;
        case 61: {                                             // getdents64
            std::vector<uint8_t> tmp(a2);
            r = files.getdents64(static_cast<int>(a0), tmp.data(), a2);
            if (r > 0) mem_.write_bytes(a1, tmp.data(), static_cast<uint64_t>(r));
            break;
        }
        case 62: r = files.lseek(static_cast<int>(a0), static_cast<int64_t>(a1),
                                 static_cast<int>(a2)); break;
        case 80: {                                             // fstat
            uint8_t st[128];
            r = files.fstat(static_cast<int>(a0), st);
            if (r == 0) mem_.write_bytes(a1, st, sizeof st);
            break;
        }
        case 79: {                                             // newfstatat
            uint8_t st[128];
            r = files.stat_path(guest_str(a1), st);
            if (r == 0) mem_.write_bytes(a2, st, sizeof st);
            break;
        }
        case 48: r = files.access(guest_str(a1)); break;        // faccessat
        case 17: {                                             // getcwd
            const std::string& d = files.cwd;
            if (a1 < d.size() + 1) { r = -34; break; }         // ERANGE
            mem_.write_bytes(a0, d.c_str(), d.size() + 1);
            r = static_cast<int64_t>(d.size() + 1);
            break;
        }
        case 78: {                                             // readlinkat
            const std::string path = guest_str(a1);
            if (path == "/proc/self/exe") {
                const std::string& e = exe_path;
                const uint64_t n = e.size() < a3 ? e.size() : a3;
                mem_.write_bytes(a2, e.c_str(), n);
                r = static_cast<int64_t>(n);
            } else r = -22;                                    // EINVAL: not a symlink
            break;
        }
        // ---- signals, threads, and other things a program sets up and forgets --
        // These must *succeed*. Refusing rt_sigprocmask is not neutral: musl's
        // startup treats the failure as fatal-ish and busybox's applet dispatch
        // came apart a few instructions later, ending up executing data.
        case 134: r = sys_rt_sigaction(static_cast<int>(a0), a1, a2); break;
        case 139: return (void)sys_rt_sigreturn(), true;        // rt_sigreturn: no x0 write
        case 135: case 132: case 133: r = 0; break;            // procmask / altstack / suspend
        case 129: case 130: case 131: r = 0; break;            // kill / tkill / tgkill
        case 178: r = static_cast<int64_t>(current_tid()); break;   // gettid
        // The set*id family. busybox drops privileges before dispatching an applet,
        // so refusing these stops it before it does anything at all.
        case 144: case 146: case 147: case 149: case 151: case 152: r = 0; break;
        case 154: case 155: case 156: case 157: case 158: r = 0; break;   // setpgid/getpgid/...
        case 179: r = 0; break;                                // sysinfo: zeroed is fine
        case 233: r = 0; break;                                // madvise
        case 29: r = -25; break;                               // ioctl: ENOTTY, we are not a tty
        case 23: case 24: r = static_cast<int64_t>(a0); break;  // dup / dup3: same fd back
        case 25: r = (a1 == 1 /*F_GETFD*/ || a1 == 3 /*F_GETFL*/) ? 0 : 0; break;   // fcntl
        case 101: r = 0; break;                                // nanosleep: return immediately
        case 169: {                                            // gettimeofday
            const uint64_t ns = host_nanos();
            mem_.write<uint64_t>(a0, ns / 1000000000ull);
            mem_.write<uint64_t>(a0 + 8, (ns % 1000000000ull) / 1000);
            r = 0;
            break;
        }
        case 172: r = 1000; break;                             // getpid
        case 174: case 175: case 176: case 177: r = 1000; break;  // getuid/geteuid/getgid/getegid
        case 160: {                                            // uname
            struct { char s[6][65]; } u{};
            std::snprintf(u.s[0], 65, "Linux");
            std::snprintf(u.s[1], 65, "aarch64emu");
            std::snprintf(u.s[2], 65, "6.1.0");
            std::snprintf(u.s[3], 65, "#1 SMP aarch64_emu_cpp");
            std::snprintf(u.s[4], 65, "aarch64");
            std::snprintf(u.s[5], 65, "(none)");
            mem_.write_bytes(a0, &u, sizeof u);
            r = 0;
            break;
        }
        default:
            if (unknown) unknown(nr);
            std::fprintf(stderr, "[sys] unimplemented syscall %llu at PC %016llX\n",
                         static_cast<unsigned long long>(nr),
                         static_cast<unsigned long long>(cpu_.pc - 4));
            r = kENOSYS;
            break;
    }
    cpu_.setx(0, static_cast<uint64_t>(r));
    return true;
}

int64_t Syscalls::sys_write(int fd, uint64_t buf, uint64_t len) {
    if (len == 0) return 0;
    std::vector<uint8_t> tmp(len);
    mem_.read_bytes(buf, tmp.data(), len);
    if (fd > 2) return files.write(fd, tmp.data(), len);
    if (output) { output(fd, reinterpret_cast<const char*>(tmp.data()), len); return static_cast<int64_t>(len); }
    if (fd == 1 || fd == 2) {
        std::FILE* f = fd == 2 ? stderr : stdout;
        std::fwrite(tmp.data(), 1, len, f);
        std::fflush(f);
        return static_cast<int64_t>(len);
    }
    return kEBADF;
}

int64_t Syscalls::sys_read(int fd, uint64_t buf, uint64_t len) {
    if (fd > 2) {
        std::vector<uint8_t> tmp(len);
        const int64_t got = files.read(fd, tmp.data(), len);
        if (got > 0) mem_.write_bytes(buf, tmp.data(), static_cast<uint64_t>(got));
        return got;
    }
    if (fd != 0) return kEBADF;
    if (!input) return 0;                                      // EOF
    std::vector<char> tmp(len);
    const int64_t got = input(tmp.data(), len);
    if (got > 0) mem_.write_bytes(buf, tmp.data(), static_cast<uint64_t>(got));
    return got;
}

// writev exists because a libc that buffers will flush through it rather than
// write(2); without it a program that "works" prints nothing.
int64_t Syscalls::sys_writev(int fd, uint64_t iov, uint64_t cnt) {
    int64_t total = 0;
    for (uint64_t i = 0; i < cnt; ++i) {
        const uint64_t base = mem_.read<uint64_t>(iov + i * 16);
        const uint64_t len = mem_.read<uint64_t>(iov + i * 16 + 8);
        if (!len) continue;
        const int64_t w = sys_write(fd, base, len);
        if (w < 0) return total ? total : w;
        total += w;
    }
    return total;
}

// brk(0) reports the break; brk(x) moves it. Memory is allocated on touch, so
// there is nothing to map — the only job is to answer consistently, because a
// libc computes its heap size from the difference between two calls.
// readv, the mirror of writev. A libc that reads through an iovec looks like a
// program that reads nothing at all without it.
int64_t Syscalls::sys_readv(int fd, uint64_t iov, uint64_t cnt) {
    int64_t total = 0;
    for (uint64_t i = 0; i < cnt; ++i) {
        const uint64_t base = mem_.read<uint64_t>(iov + i * 16);
        const uint64_t len = mem_.read<uint64_t>(iov + i * 16 + 8);
        if (!len) continue;
        const int64_t got = sys_read(fd, base, len);
        if (got < 0) return total ? total : got;
        total += got;
        if (static_cast<uint64_t>(got) < len) break;     // short read ends the vector
    }
    return total;
}

int64_t Syscalls::sys_brk(uint64_t addr) {
    if (addr && addr >= brk_start_) {
        // Map what the break now covers. With permissive memory nothing had to be done
        // here -- a write allocated its own page -- but that is exactly what `--strict`
        // withdraws, and growing the break is the guest *asking* for the memory. malloc
        // then writes into it 2.7 M instructions later, which under --strict was the first
        // thing to report itself.
        if (addr > brk_) mem_.map(brk_, addr - brk_);
        brk_ = addr;
    }
    return static_cast<int64_t>(brk_);
}

// A bump allocator over a fixed mmap region. Real mmap semantics (MAP_FIXED,
// unmapping, remap) are not modelled; what a libc needs at startup is a large
// zeroed region at a stable address, and it gets one.
// mmap, for real this time.
//
// A static guest only needs "give me a zeroed region somewhere". A *dynamic* one
// needs the actual contract, because the dynamic loader builds every shared
// library out of it: first one PROT_NONE anonymous reservation spanning the whole
// object, then a MAP_FIXED file mapping over each segment at its own offset. Get
// MAP_FIXED wrong, or ignore the file offset, and ld.so lays libc down in pieces
// that do not join up.
//
// What is *not* modelled: protection (nothing here faults), sharing (a file
// mapping is a private copy), and unmapping (the arena only grows). Those are
// honest gaps rather than approximations — a guest that writes to a read-only
// mapping gets away with it here, and one that expects MAP_SHARED to reach the
// file will not see it happen.
int64_t Syscalls::sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                           int fd, uint64_t off) {
    (void)prot;
    constexpr uint64_t kMAP_FIXED = 0x10, kMAP_ANONYMOUS = 0x20;
    const bool anon = (flags & kMAP_ANONYMOUS) || fd < 0;

    uint64_t base;
    if (addr && (flags & kMAP_FIXED)) {
        base = addr;
    } else {
        base = mmap_next_;
        mmap_next_ = (mmap_next_ + len + 0xFFFF) & ~0xFFFFull;
    }

    // Every mapping starts zeroed, including the tail of a file mapping that runs
    // past end-of-file — which is exactly how a .bss inside a PT_LOAD gets there.
    mem_.set(base, 0, len);
    if (!anon) {
        std::vector<uint8_t> tmp(len);
        const int64_t got = files.pread(fd, tmp.data(), len, off);
        if (got > 0) mem_.write_bytes(base, tmp.data(), static_cast<uint64_t>(got));
    }
    return static_cast<int64_t>(base);
}

uint64_t Syscalls::host_nanos() {
    // Monotonic enough for a guest that only measures elapsed time.
    const auto t = std::clock();
    return static_cast<uint64_t>(t) * (1000000000ull / CLOCKS_PER_SEC);
}

}  // namespace a64
