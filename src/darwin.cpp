// The Darwin (macOS/Apple Silicon) kernel interface.
//
// A second personality alongside the Linux one, not a fork of it: the same `Files`
// layer, the same memory, the same CPU. Three things differ, and all three are
// load-bearing.
//
//  1. **`svc #0x80`, not `svc #0`.** Darwin uses a non-zero immediate, so the two
//     personalities can coexist in one build and be told apart at the trap itself
//     rather than by a mode flag. `svc()` routes on the immediate.
//  2. **The number is in x16, not x8**, and it is BSD numbering — write is 4, exit
//     is 1. Negative numbers are Mach traps, a completely separate table.
//  3. **Errors come back in the carry flag.** Success clears C and returns the
//     value in x0; failure *sets* C and puts a *positive* errno in x0. A Linux-style
//     negative return would be read as a huge successful result — a pointer, a
//     length — so getting this wrong is not a failed call, it is a wrong answer.
//
// The errno numbers themselves are mostly shared with Linux (both descend from
// the same BSD table), so `Files` results pass through with two exceptions, fixed
// up in `bsd_errno`.
#include "syscalls.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace a64 {

namespace {

// Darwin errno values that disagree with Linux's. Everything from 1..34 that we
// can actually produce is identical in both tables; these two are not.
int bsd_errno(int64_t linux_errno) {
    const int e = static_cast<int>(-linux_errno);
    if (e == 38) return 78;    // ENOSYS
    if (e == 11) return 35;    // EAGAIN
    return e;
}

constexpr int kBsdENOSYS = 78, kBsdEINVAL = 22, kBsdENOENT = 2;

// Darwin's `struct stat64` is 144 bytes and laid out nothing like Linux's, so the
// Linux buffer `Files` fills is translated rather than copied. Only the fields a
// program actually branches on are carried across: the type bits, the permission
// bits and the size.
void linux_stat_to_darwin(const uint8_t* lin, uint8_t* dar) {
    uint32_t mode;
    int64_t size;
    std::memcpy(&mode, lin + 16, 4);
    std::memcpy(&size, lin + 48, 8);
    std::memset(dar, 0, 144);
    const uint16_t mode16 = static_cast<uint16_t>(mode);
    std::memcpy(dar + 4, &mode16, 2);            // st_mode
    const uint16_t nlink = 1;
    std::memcpy(dar + 6, &nlink, 2);             // st_nlink
    std::memcpy(dar + 96, &size, 8);             // st_size
    const int64_t blocks = (size + 511) / 512;
    std::memcpy(dar + 104, &blocks, 8);          // st_blocks
    const int32_t blksize = 4096;
    std::memcpy(dar + 112, &blksize, 4);         // st_blksize
}

// Darwin's open(2) flags. O_CREAT and above differ from Linux's, so a guest asking
// for O_CREAT|O_TRUNC (0x0600 on Darwin) would be read as something else entirely.
int darwin_oflags_to_linux(int f) {
    int out = f & 3;                             // O_RDONLY/WRONLY/RDWR agree
    if (f & 0x0008) out |= 02000;                // O_APPEND
    if (f & 0x0200) out |= 0100;                 // O_CREAT
    if (f & 0x0400) out |= 01000;                // O_TRUNC
    if (f & 0x0800) out |= 0200;                 // O_EXCL
    if (f & 0x100000) out |= 0200000;            // O_DIRECTORY
    return out;
}

}  // namespace

// The commpage: a read-only page the Darwin kernel maps at a fixed address so that
// userland can read machine properties without a syscall. libsyscall builds
// `vm_page_size` from the page shift found here, and libplatform sizes its
// allocations in pages -- so an all-zero commpage means a page size of one byte, a
// rounded-up allocation of zero bytes, and `BUG IN LIBPLATFORM: Failed to allocate in
// os_alloc_once` from a kernel interface that looked like it was working.
//
// The offsets are xnu's `cpu_capabilities.h`. Filling in only the fields a userland
// libc reads is deliberate: an invented value in an unread field is harmless, but an
// invented value in a read one is a wrong answer that looks like a working guest.
void Syscalls::setup_commpage() {
    // Two base addresses, both filled identically.
    //
    // 0xF_FFFFC000 is _COMM_PAGE64_BASE_ADDRESS (nine hex digits, not eight -- writing
    // 0xFFFFC000 puts the page four bits low, where nothing reads it, and the guest
    // then computes a page size of zero). macOS 13 split the commpage in two, moving
    // the constant fields to a read-only page 32 KiB below, and libsystem_kernel on
    // Sequoia reads its page shift from *there*: a watch on the range showed a byte
    // read at 0xF_FFFF4037, which is KERNEL_PAGE_SHIFT's offset.
    //
    // Which field lives on which page is not something to guess at, so both get the
    // same layout. A duplicated field costs nothing; a missing one is read as zero and
    // turns into a wrong answer several hundred instructions away.
    auto fill = [this](uint64_t base) {
        mem_.set(base, 0, 0x4000);
        const char sig[] = "commpage 64-bit";
        mem_.write_bytes(base + 0x000, sig, sizeof sig);
        mem_.write<uint64_t>(base + 0x010, 0);          // CPU_CAPABILITIES64: claim nothing
        mem_.write<uint16_t>(base + 0x01E, 3);          // VERSION
        mem_.write<uint16_t>(base + 0x020, 0);          // CPU_CAPABILITIES
        mem_.write<uint8_t>(base + 0x022, 1);           // NCPUS
        mem_.write<uint8_t>(base + 0x024, 14);          // USER_PAGE_SHIFT_32: 16 KiB
        mem_.write<uint8_t>(base + 0x025, 14);          // USER_PAGE_SHIFT_64: 16 KiB
        mem_.write<uint8_t>(base + 0x026, 6);           // CACHE_LINESIZE shift (64 bytes)
        mem_.write<uint32_t>(base + 0x028, 1);          // SCHED_GEN
        mem_.write<uint32_t>(base + 0x02C, 0);          // MEMORY_PRESSURE
        mem_.write<uint32_t>(base + 0x030, 100);        // SPIN_COUNT
        mem_.write<uint8_t>(base + 0x034, 1);           // ACTIVE_CPUS
        mem_.write<uint8_t>(base + 0x035, 1);           // PHYSICAL_CPUS
        mem_.write<uint8_t>(base + 0x036, 1);           // LOGICAL_CPUS
        mem_.write<uint8_t>(base + 0x037, 14);          // KERNEL_PAGE_SHIFT: 16 KiB
        mem_.write<uint64_t>(base + 0x038, 8ull << 30); // MEMORY_SIZE: 8 GiB
        mem_.write<uint32_t>(base + 0x040, 0x1B588BB3); // CPUFAMILY: an Apple M-series
        mem_.write<uint32_t>(base + 0x044, 0);          // KDEBUG_ENABLE
        // The timebase, matched to what mach_timebase_info_trap reports: 1/1, so
        // mach_absolute_time is nanoseconds.
        mem_.write<uint32_t>(base + 0x0C0, 1);          // numer
        mem_.write<uint32_t>(base + 0x0C4, 1);          // denom
    };
    fill(0x0000'000F'FFFF'C000ull);
    fill(0x0000'000F'FFFF'4000ull);
}

// Returns false to stop the machine (only for exit).
bool Syscalls::svc_darwin() {
    const int64_t nr = static_cast<int64_t>(cpu_.xr(16));
    const uint64_t a0 = cpu_.xr(0), a1 = cpu_.xr(1), a2 = cpu_.xr(2);
    const uint64_t a3 = cpu_.xr(3);

    if (trace) {
        // All six, because a Mach trap's arguments are positional and getting the
        // layout wrong looks exactly like the guest passing nonsense.
        // x30 as well: these trap stubs are three instructions long, so the return
        // address is the only way to see which library asked.
        std::fprintf(stderr, "[mac] %lld(%llX, %llX, %llX, %llX, %llX, %llX)  lr=%llX\n",
                     static_cast<long long>(nr), static_cast<unsigned long long>(a0),
                     static_cast<unsigned long long>(a1), static_cast<unsigned long long>(a2),
                     static_cast<unsigned long long>(a3),
                     static_cast<unsigned long long>(cpu_.xr(4)),
                     static_cast<unsigned long long>(cpu_.xr(5)),
                     static_cast<unsigned long long>(cpu_.xr(30)));
    }

    int64_t r = 0;          // the success value
    int err = 0;            // non-zero means "set carry, return this in x0"

    // A Mach trap, not a BSD syscall: a different table reached through the same
    // instruction, distinguished only by the sign of x16.
    //
    // The return convention differs too. A Mach trap returns a `kern_return_t` in x0
    // and leaves the carry flag alone -- there is no errno and no flag. Reporting
    // failure the BSD way here would make a successful allocation look like an error
    // and vice versa.
    if (nr < 0) {
        const uint64_t a4 = cpu_.xr(4), a5 = cpu_.xr(5);
        constexpr int64_t kKernSuccess = 0, kKernFailure = 5, kKernInvalidArgument = 4;
        // A Mach VM allocation, from the same arena BSD mmap uses. Honours the
        // alignment mask and VM_FLAGS_ANYWHERE, and writes the address back through
        // the pointer the caller passed -- which is the part that matters: libmalloc
        // reads its zone address from there and does not check it against anything.
        auto vm_alloc = [&](uint64_t addr_ptr, uint64_t size, uint64_t mask,
                            uint64_t flags) -> int64_t {
            if (!size) return kKernInvalidArgument;
            const bool anywhere = (flags & 1) != 0;        // VM_FLAGS_ANYWHERE
            if (!anywhere) {
                // A fixed request: the address is already what the caller wants, and
                // memory here is allocated on touch, so honouring it is just zeroing.
                const uint64_t want = mem_.read<uint64_t>(addr_ptr);
                mem_.set(want, 0, size);
                return kKernSuccess;
            }
            const int64_t got = sys_mmap(0, size + mask, 0, 0x20 /*MAP_ANON*/, -1, 0);
            if (got < 0) return kKernFailure;
            const uint64_t aligned = (static_cast<uint64_t>(got) + mask) & ~mask;
            mem_.set(aligned, 0, size);
            mem_.write<uint64_t>(addr_ptr, aligned);
            return kKernSuccess;
        };

        switch (-nr) {
            // ---- Mach VM. libmalloc builds its zones through these, so a guest that
            // reaches malloc reaches here.
            case 10: r = vm_alloc(a1, a2, 0, a3); break;   // mach_vm_allocate_trap
            case 15: r = vm_alloc(a1, a2, a3, a4); break;  // mach_vm_map_trap
            case 12: r = kKernSuccess; break;              // mach_vm_deallocate: arena only grows
            case 14: r = kKernSuccess; break;              // mach_vm_protect: nothing modelled
            case 11: r = kKernSuccess; break;              // mach_vm_purgable_control
            // ---- Mach ports. Nothing here delivers messages, so a port is a number
            // that has to be non-zero and distinct; the guest stores it and compares
            // it, and only fails if it is zero.
            case 16: mem_.write<uint32_t>(a2, next_port_++); r = kKernSuccess; break;
            case 24: mem_.write<uint32_t>(a3, next_port_++); r = kKernSuccess; break;
            case 18: case 19: case 21: case 22: r = kKernSuccess; break;
            case 26: r = next_port_++; break;              // mach_reply_port
            case 27: r = 0x103; break;                     // thread_self_trap
            case 28: r = 0x107; break;                     // task_self_trap
            case 29: r = 0x10B; break;                     // host_self_trap
            case 61: case 62: r = kKernSuccess; break;     // swtch_pri, thread_switch
            case 89: {                                     // mach_timebase_info_trap
                // numer/denom of 1/1 makes mach_absolute_time() nanoseconds, which
                // is what the host clock already hands back.
                mem_.write<uint32_t>(a0, 1);
                mem_.write<uint32_t>(a0 + 4, 1);
                r = kKernSuccess;
                break;
            }
            default:
                std::fprintf(stderr, "[mac] unimplemented Mach trap %lld at PC %016llX\n",
                             static_cast<long long>(nr),
                             static_cast<unsigned long long>(cpu_.pc - 4));
                r = kKernFailure;
                break;
        }
        (void)a5;
        cpu_.setx(0, static_cast<uint64_t>(r));
        cpu_.c = false;
        return true;
    }

    switch (nr) {
        case 1:                                            // exit
            cpu_.exit_code = static_cast<int>(a0 & 0xFF);
            cpu_.halted = true;
            return true;
        case 3: case 396: r = sys_read(static_cast<int>(a0), a1, a2); break;   // read[_nocancel]
        case 4: case 397: r = sys_write(static_cast<int>(a0), a1, a2); break;  // write[_nocancel]
        case 120: r = sys_readv(static_cast<int>(a0), a1, a2); break;
        case 121: r = sys_writev(static_cast<int>(a0), a1, a2); break;
        case 5: case 398:                                  // open[_nocancel]
            r = files.open(guest_str(a0), darwin_oflags_to_linux(static_cast<int>(a1)),
                           static_cast<int>(a2));
            break;
        case 6: case 399: r = files.close(static_cast<int>(a0)); break;
        case 199: r = files.lseek(static_cast<int>(a0), static_cast<int64_t>(a1),
                                  static_cast<int>(a2)); break;
        case 33: r = files.access(guest_str(a0)); break;
        case 339: case 189: {                              // fstat64, fstat
            uint8_t lin[128], dar[144];
            r = files.fstat(static_cast<int>(a0), lin);
            if (r == 0) { linux_stat_to_darwin(lin, dar); mem_.write_bytes(a1, dar, sizeof dar); }
            break;
        }
        case 338: case 188: case 340: {                    // stat64, stat, lstat64
            uint8_t lin[128], dar[144];
            r = files.stat_path(guest_str(a0), lin);
            if (r == 0) { linux_stat_to_darwin(lin, dar); mem_.write_bytes(a1, dar, sizeof dar); }
            break;
        }
        // Darwin's mmap has the same argument order as Linux's, but MAP_ANON is
        // 0x1000 rather than 0x20, so the flag is translated before it is used.
        case 197: {
            const uint64_t dflags = a3;
            uint64_t lflags = 0;
            if (dflags & 0x0010) lflags |= 0x10;           // MAP_FIXED
            if (dflags & 0x1000) lflags |= 0x20;           // MAP_ANON -> MAP_ANONYMOUS
            r = sys_mmap(a0, a1, a2, lflags, static_cast<int>(cpu_.xr(4)), cpu_.xr(5));
            break;
        }
        case 73: r = 0; break;                             // munmap: the arena never shrinks
        case 74: r = 0; break;                             // mprotect: no protection modelled
        case 75: case 232: r = 0; break;                   // madvise, posix_madvise
        case 20: r = 1000; break;                          // getpid
        case 24: case 25: case 43: case 47: r = 1000; break;  // getuid/geteuid/getgid/getegid
        case 327: r = 0; break;                            // issetugid
        case 372: r = 1000; break;                         // thread_selfid
        case 366: r = 0; break;                            // bsdthread_register
        case 116: {                                        // gettimeofday
            const uint64_t ns = host_nanos();
            mem_.write<uint64_t>(a0, ns / 1000000000ull);
            mem_.write<uint32_t>(a0 + 8, static_cast<uint32_t>((ns % 1000000000ull) / 1000));
            r = 0;
            break;
        }
        case 500: {                                        // getentropy
            for (uint64_t i = 0; i < a1; ++i)
                mem_.write<uint8_t>(a0 + i, static_cast<uint8_t>(0x9E * (i + 1) + 0x37));
            r = 0;
            break;
        }
        case 202: case 274: err = kBsdENOENT; break;       // sysctl, sysctlbyname
        case 54: err = 25; break;                          // ioctl: ENOTTY, we are not a tty
        case 92: case 406: r = 0; break;                   // fcntl[_nocancel]
        case 294: err = kBsdEINVAL; break;                 // shared_region_check_np: no cache
        case 336: err = kBsdEINVAL; break;                 // proc_info
        default:
            if (unknown) unknown(static_cast<uint64_t>(nr));
            std::fprintf(stderr, "[mac] unimplemented syscall %lld at PC %016llX\n",
                         static_cast<long long>(nr),
                         static_cast<unsigned long long>(cpu_.pc - 4));
            err = kBsdENOSYS;
            break;
    }

    // `Files` speaks Linux, returning a negative errno. Darwin wants the sign in
    // the carry flag and the magnitude in x0.
    if (!err && r < 0) { err = bsd_errno(r); r = 0; }
    if (err) { cpu_.setx(0, static_cast<uint64_t>(err)); cpu_.c = true; }
    else     { cpu_.setx(0, static_cast<uint64_t>(r));   cpu_.c = false; }
    return true;
}

}  // namespace a64
