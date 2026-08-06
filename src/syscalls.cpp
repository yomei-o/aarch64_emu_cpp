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

// Every syscall returns through here, and a vfork child that has just execed or
// exited asks the run loop to stop so the parent can be restored.
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
    // And a fourth: the thunk every `tlv_descriptor` points at. x0 arrives holding
    // the descriptor and leaves holding this thread's copy of the variable.
    if (imm == 0x82) {
        cpu_.setx(0, tlv_addr(cpu_.xr(0)));
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
        case 93: case 94:
            // A vfork child that exits before it execs -- the `_exit(127)` after a
            // failed exec, and what `posix_spawn` does when it cannot find the
            // program. The parent has to come back rather than the whole run ending.
            if (in_vfork_child()) {
                vfork_child_status_ = static_cast<int>(a0 & 0xFF) << 8;
                vfork_returning_ = true;
                cpu_.stop_requested = true;
                return true;
            }
            if (nr == 93) { thread_exit(static_cast<int>(a0 & 0xFF)); return true; }
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
            // A thread is CLONE_VM *and* CLONE_THREAD. Everything else that comes
            // through here is a new process: musl's `fork()` passes SIGCHLD alone, and
            // its `posix_spawn()` passes CLONE_VM|CLONE_VFORK -- which shares the
            // address space but is emphatically not a thread, and taking the thread
            // path for it would leave two schedulable contexts in one program.
            if (!((a0 & 0x00000100) && (a0 & 0x00010000))) {
                cpu_.setx(0, static_cast<uint64_t>(sys_fork()));
                return true;
            }
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
        // prlimit64(pid, resource, new, old). Answering EINVAL was survivable until
        // something asked how many descriptors it might have: CPython's
        // `_posixsubprocess` closes every fd from 3 to the limit before it execs, and
        // with no answer it falls back to a limit of about twenty million and spends
        // the run calling close(2) on descriptors that were never open.
        case 261: {
            constexpr uint64_t kInfinity = ~0ull;
            uint64_t cur = kInfinity, max = kInfinity;
            switch (a1) {
                case 3: cur = 8u << 20; max = 64u << 20; break;    // RLIMIT_STACK
                case 7: cur = 256; max = 4096; break;              // RLIMIT_NOFILE
                default: break;
            }
            if (a3) {                                              // the `old` buffer
                mem_.write<uint64_t>(a3, cur);
                mem_.write<uint64_t>(a3 + 8, max);
            }
            r = 0;
            break;
        }
        // close_range(first, last, flags). One call instead of a loop, and CPython uses
        // it when it is there -- which is the difference between a child that execs
        // immediately and one that makes a quarter of a million syscalls first.
        // epoll_create1 (20) and ppoll (73). CPython's `subprocess` waits on the
        // child's pipes with one or the other, and refusing both leaves it with no way
        // to find out that there is data.
        //
        // Nothing here runs two processes at once, so by the time the parent polls, the
        // child has finished and everything it wrote is already in the buffer. "Every
        // descriptor asked about is ready" is therefore the truthful answer rather than
        // a convenient one -- a pipe with a dead writer is ready to report end of file
        // even when it is empty.
        // epoll_create1: refused on purpose. Python's selectors module tries epoll
        // first and falls back to poll when it is absent, and poll is the one that can
        // be answered honestly here -- an epoll set would have to remember
        // registrations and report edges, which is a lot of machinery for a design
        // where the child has always already finished.
        case 20: r = kENOSYS; break;
        case 73: {                                             // ppoll(fds, n, ...)
            const uint64_t n = a1;
            int64_t ready = 0;
            for (uint64_t i = 0; i < n && i < 64; ++i) {
                const uint64_t e = a0 + i * 8;                 // struct pollfd
                const int16_t events = static_cast<int16_t>(mem_.read<uint16_t>(e + 4));
                mem_.write<uint16_t>(e + 6, static_cast<uint16_t>(events));
                ++ready;
            }
            r = ready;
            break;
        }
        case 436: {
            const uint64_t last = a1 > 4096 ? 4096 : a1;
            for (uint64_t fd = a0; fd <= last; ++fd) files.close(static_cast<int>(fd));
            r = 0;
            break;
        }
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
        case 56: {                                             // openat
            const std::string path = guest_str(a1);
            r = files.open(path, static_cast<int>(a2), static_cast<int>(a3));
            // The path, when tracing. A syscall log of numbers answers "how many
            // opens" and never "which file", and "which file" is the question every
            // time a dynamic loader cannot find something.
            if (trace)
                std::fprintf(stderr, "[sys]   openat(\"%s\") -> %lld\n", path.c_str(),
                             static_cast<long long>(r));
            break;
        }
        // unlinkat. gcc removes its temporary files with it, and refusing left a
        // driver that compiled correctly and then complained it could not clean up.
        case 35: r = files.unlink(guest_str(a1)); break;
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
            const std::string path = guest_str(a1);
            // AT_EMPTY_PATH (0x1000) with an empty path means "stat the fd
            // itself" - it is how glibc's fstat() is spelled on aarch64.
            // Statting "" as a path instead answered with the sysroot root
            // directory, whose 4096-byte st_size made ld.so reject every
            // ld.so.cache as truncated.
            if (path.empty() && (a3 & 0x1000))
                r = files.fstat(static_cast<int>(a0), st);
            else
                r = files.stat_path(path, st);
            if (r == 0) mem_.write_bytes(a2, st, sizeof st);
            if (trace)
                std::fprintf(stderr, "[sys]   fstatat(%lld, \"%s\") -> %lld\n",
                             static_cast<long long>(static_cast<int64_t>(a0)), path.c_str(),
                             static_cast<long long>(r));
            break;
        }
        case 293:                                              // rseq: refused, glibc falls back
            r = kENOSYS;
            break;
        case 439:                                              // faccessat2: flags add nothing here
        case 48: {                                             // faccessat
            const std::string path = guest_str(a1);
            r = files.access(path);
            if (trace)
                std::fprintf(stderr, "[sys]   access(\"%s\") -> %lld\n", path.c_str(),
                             static_cast<long long>(r));
            break;
        }
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
        // dup / dup3. These used to hand the same descriptor back, which is right
        // only while nothing can have two: a child redirecting its own stdout with
        // `dup2(pipe_w, 1)` needs fd 1 to *become* the pipe, and getting fd 1 back
        // unchanged sends its output to the terminal instead of to its parent.
        case 23: r = files.dup(static_cast<int>(a0), -1); break;
        case 24: r = files.dup(static_cast<int>(a0), static_cast<int>(a1)); break;
        case 59: {                                             // pipe2
            int fds[2];
            r = files.pipe2(fds);
            if (r == 0) {
                mem_.write<uint32_t>(a0, static_cast<uint32_t>(fds[0]));
                mem_.write<uint32_t>(a0 + 4, static_cast<uint32_t>(fds[1]));
            }
            break;
        }
        case 221: r = sys_execve(a0, a1, a2); return true;      // execve
        case 260: r = sys_wait4(static_cast<int64_t>(a0), a1); break;   // wait4
        case 25: r = (a1 == 1 /*F_GETFD*/ || a1 == 3 /*F_GETFL*/) ? 0 : 0; break;   // fcntl
        case 101: r = 0; break;                                // nanosleep: return immediately
        case 169: {                                            // gettimeofday
            const uint64_t ns = host_nanos();
            mem_.write<uint64_t>(a0, ns / 1000000000ull);
            mem_.write<uint64_t>(a0 + 8, (ns % 1000000000ull) / 1000);
            r = 0;
            break;
        }
        // umask and fchmodat, from ld setting its output executable. There are no
        // guest permissions to keep: the host filesystem's are what they are.
        case 166: r = 022; break;
        case 53: r = 0; break;
        // getrusage: gcc asks at exit to report time spent. All zeros reads as
        // "no time at all", which is honest enough -- there is no host rusage
        // for a guest process. struct rusage is 144 bytes.
        case 165: mem_.set(a1, 0, 144); r = 0; break;
        case 172: r = 1000; break;                             // getpid
        case 174: case 175: case 176: case 177: r = 1000; break;  // getuid/geteuid/getgid/getegid
        case 160: {                                            // uname
            struct { char s[6][65]; } u{};
            std::snprintf(u.s[0], 65, "Linux");
            std::snprintf(u.s[1], 65, "aarch64emu");
            std::snprintf(u.s[2], 65, "6.18.33.2-microsoft-standard-WSL2");
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
    // A vfork child that has just execed or exited: ask the run loop to stop so the
    // host can put the parent back. Set after x0, because the value written here
    // belongs to the child and is about to be discarded with it.
    if (vfork_pending()) cpu_.stop_requested = true;
    return true;
}

int64_t Syscalls::sys_write(int fd, uint64_t buf, uint64_t len) {
    if (len == 0) return 0;
    std::vector<uint8_t> tmp(len);
    mem_.read_bytes(buf, tmp.data(), len);
    // Descriptors 0..2 are the console *unless* something redirected them. A child
    // about to exec does exactly that -- `dup2(pipe_w, 1)` -- and sending fd 1 to the
    // terminal regardless made the child's output appear on the screen while its
    // parent read an empty pipe and reported failure.
    if (fd >= 0 && fd <= 2 && files.is_open(fd)) return files.write(fd, tmp.data(), len);
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
    // The same rule as sys_write: fd 0 is the console until something redirects it.
    if (fd == 0 && files.is_open(0)) {
        std::vector<uint8_t> tmp(len);
        const int64_t n = files.read(0, tmp.data(), len);
        if (n > 0) mem_.write_bytes(buf, tmp.data(), static_cast<size_t>(n));
        return n;
    }
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
        // MAP_SHARED on a file is a *writable window onto the file*, and dropping
        // the window has to put the bytes back.  This is not an exotic case: it is
        // how ld writes its output - 186 million instructions and not one write(2)
        // - so without it the linker exits 0 having produced nothing.
        constexpr uint64_t kMAP_SHARED = 0x01;
        if (flags & kMAP_SHARED) shared_maps_.push_back({base, len, off, fd});
    }
    return static_cast<int64_t>(base);
}

void Syscalls::flush_shared_maps(uint64_t base, uint64_t len, bool all) {
    for (size_t i = 0; i < shared_maps_.size();) {
        SharedMap& m = shared_maps_[i];
        // A partial unmap of a mapping still means those bytes are now the file's;
        // overlap is enough to write the whole window back, which is wasteful and
        // never wrong.
        const bool hit = all || (base < m.base + m.len && m.base < base + (len ? len : 1));
        if (!hit) { ++i; continue; }
        std::vector<uint8_t> tmp(static_cast<size_t>(m.len));
        mem_.read_bytes(m.base, tmp.data(), m.len);
        files.pwrite(m.fd, tmp.data(), m.len, m.off);
        if (all) { ++i; continue; }              // exit: keep the list intact
        shared_maps_.erase(shared_maps_.begin() + static_cast<long>(i));
    }
}

uint64_t Syscalls::host_nanos() {
    // Monotonic enough for a guest that only measures elapsed time.
    const auto t = std::clock();
    return static_cast<uint64_t>(t) * (1000000000ull / CLOCKS_PER_SEC);
}

}  // namespace a64
