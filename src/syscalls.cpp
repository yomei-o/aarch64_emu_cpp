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
    if (imm != 0) {   // Linux uses svc #0; anything else is a different personality
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
        case 93: case 94:                                      // exit, exit_group
            cpu_.exit_code = static_cast<int>(a0 & 0xFF);
            cpu_.halted = true;
            return true;
        case 214: r = sys_brk(a0); break;
        case 222: r = sys_mmap(a0, a1, a2, a3, static_cast<int>(a4), a5); break;
        case 215: r = 0; break;                                // munmap: the arena never shrinks
        case 226: r = 0; break;                                // mprotect: no protection modelled
        case 96: tid_address_ = a0; r = 1; break;              // set_tid_address -> our tid
        case 99: case 98: r = 0; break;                        // set_robust_list, futex-ish no-ops
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
int64_t Syscalls::sys_brk(uint64_t addr) {
    if (addr && addr >= brk_start_) brk_ = addr;
    return static_cast<int64_t>(brk_);
}

// A bump allocator over a fixed mmap region. Real mmap semantics (MAP_FIXED,
// unmapping, remap) are not modelled; what a libc needs at startup is a large
// zeroed region at a stable address, and it gets one.
int64_t Syscalls::sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
                           int fd, uint64_t off) {
    (void)prot;
    if (fd >= 0 && !(flags & 0x20 /*MAP_ANONYMOUS*/)) {
        // A file mapping. Read the bytes in rather than share them: nothing here
        // writes back, and CPython maps its own executable while importing.
        const uint64_t base = mmap_next_;
        mmap_next_ = (mmap_next_ + len + 0xFFFF) & ~0xFFFFull;
        if (file_read) {
            std::vector<uint8_t> tmp(len);
            const int64_t got = file_read(fd, tmp.data(), len, off);
            if (got > 0) mem_.write_bytes(base, tmp.data(), static_cast<uint64_t>(got));
        }
        return static_cast<int64_t>(base);
    }
    if (addr && (flags & 0x10 /*MAP_FIXED*/)) { mem_.set(addr, 0, len); return static_cast<int64_t>(addr); }
    const uint64_t base = mmap_next_;
    mmap_next_ = (mmap_next_ + len + 0xFFFF) & ~0xFFFFull;
    return static_cast<int64_t>(base);
}

uint64_t Syscalls::host_nanos() {
    // Monotonic enough for a guest that only measures elapsed time.
    const auto t = std::clock();
    return static_cast<uint64_t>(t) * (1000000000ull / CLOCKS_PER_SEC);
}

}  // namespace a64
