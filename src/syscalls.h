#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include "cpu.h"
#include "memory.h"
#include "files.h"
#include "loader.h"

namespace a64 {

class Syscalls {
public:
    Syscalls(Cpu& cpu, Memory& mem);

    // Where the heap and the mmap arena live. Set by the host after loading, so the
    // break starts just above the image.
    void set_brk(uint64_t addr) { brk_ = brk_start_ = addr; }
    void set_mmap_base(uint64_t addr) { mmap_next_ = addr; }

    Files files;
    // What /proc/self/exe should report; a libc reads it to find its own prefix.
    std::string exe_path;
    bool trace = false;
    std::function<void(int fd, const char* data, uint64_t len)> output;
    std::function<int64_t(char* dst, uint64_t len)> input;
    std::function<int64_t(int fd, void* dst, uint64_t len, uint64_t off)> file_read;
    std::function<void(uint64_t nr)> unknown;

    // Signal delivery, in signals.cpp. Returns false when nothing is installed --
    // then the caller reports the fault, which is the default action anyway.
    bool deliver_signal(int sig, uint64_t fault_addr);
    // The Darwin commpage, in darwin.cpp. The host places it before the guest starts,
    // because libsyscall reads the page size out of it during startup and a zero there
    // makes every allocation round to nothing.
    void setup_commpage();
    // A stand-in for dyld's own API object, in darwin.cpp. libdyld.dylib dispatches
    // `_dyld_get_active_platform` and friends through a global vtable that only real
    // dyld fills in, so having replaced dyld this has to fill it in too.
    void setup_dyld_apis(uint64_t gapis_addr);
    // libobjc's `__objc_opt_ro`, which dyld hands back from
    // `_dyld_for_objc_header_opt_ro` and libobjc needs to read the cache's class layout.
    void set_objc_opt_ro(uint64_t addr) { objc_opt_ro_ = addr; }
    // The main executable's mach_header, which _dyld_get_prog_image_header returns.
    void set_prog_header(uint64_t addr) { prog_header_ = addr; }
    // Where the cache-derived libraries live, for `_dyld_get_shared_cache_range`.
    void set_cache_range(uint64_t lo, uint64_t hi) { cache_lo_ = lo; cache_hi_ = hi; }
    // Non-zero once libobjc has handed over its callbacks. The host then has to call
    // `map_images` the way dyld does, or no class is ever registered.
    uint64_t objc_callbacks() const { return objc_callbacks_; }
    // The loaded-image list, which libobjc's `map_images` needs and which only the
    // loader has. Handed over before the guest starts.
    void set_objc_images(std::vector<std::string> paths, std::vector<uint64_t> headers) {
        objc_image_paths_ = std::move(paths);
        objc_image_headers_ = std::move(headers);
    }
    // Every mapped segment and the image it belongs to, for the "which image contains this
    // address" API. A flat list scanned linearly: there are a few hundred of them and it is
    // asked a handful of times.
    void set_image_segs(std::vector<LoadedImage::ImageSeg> segs) { image_segs_ = std::move(segs); }
    // The address a handler returns to when the guest supplied no restorer.
    static constexpr uint64_t kSigreturnMagic = 0x0000'0000'DEAD'0000ull;

private:
    bool svc(uint32_t imm);
    // The Darwin personality, in darwin.cpp. Reached through `svc #0x80`, which is
    // how a Mach-O guest traps -- so the two kernels coexist in one build and are
    // told apart at the instruction rather than by a mode flag.
    bool svc_darwin();
    // Mach IPC, in darwin.cpp: enough of mach_msg2_trap and MIG to answer the kernel
    // RPCs a libSystem startup makes.
    int64_t dyld_api_stub(uint32_t slot);
    void call_guest(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2);
    int64_t mach_msg2(uint64_t data, uint64_t options, uint64_t bits_size,
                      uint64_t remote_local, uint64_t voucher_id,
                      uint64_t desc_rcvname, uint64_t rcv_size);
    int64_t sys_write(int fd, uint64_t buf, uint64_t len);
    int64_t sys_read(int fd, uint64_t buf, uint64_t len);
    int64_t sys_writev(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_readv(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_brk(uint64_t addr);
    std::string guest_str(uint64_t addr) { return mem_.read_cstr(addr); }
    int64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, int fd, uint64_t off);
    int64_t sys_rt_sigaction(int sig, uint64_t act, uint64_t oact);
    int64_t sys_rt_sigreturn();
    static uint64_t host_nanos();

    // Threads, in threads.cpp. One emulated CPU running one guest thread at a time,
    // switched at futex/yield/exit and by preemption. These write x0 themselves,
    // because the thread that made the call may not be the one running on return.
    struct Thread {
        Cpu::Context ctx;
        uint64_t tid = 0;
        uint64_t clear_child_tid = 0;   // musl's join word: cleared and woken on exit
        uint64_t wait_addr = 0;
        bool waiting = false;           // blocked in futex(WAIT)
        bool exited = false;
    };
    std::vector<Thread> threads_;       // empty until the first clone
    size_t cur_thread_ = 0;
    uint64_t next_tid_ = 1001;

    void ensure_main_thread();
    void switch_to(size_t idx);
    bool schedule(bool must_move);
    uint64_t current_tid() const;
    int64_t sys_clone(uint64_t flags, uint64_t stack, uint64_t ptid, uint64_t tls, uint64_t ctid);
    int64_t sys_futex(uint64_t addr, int op, uint32_t val);
    int64_t sys_sched_yield();
    void thread_exit(int status);

    struct Handler { uint64_t func = 0, flags = 0, restorer = 0; };
    Handler handlers_[64];
    struct SigFrame { uint64_t frame; Cpu::Regs saved; };
    std::vector<SigFrame> sig_frames_;

    Cpu& cpu_;
    Memory& mem_;
    uint64_t brk_ = 0, brk_start_ = 0;
    // Set by the host, which owns the address-space layout. The default is only a
    // fallback; main.cpp places it clear of the image, the interpreter and the stack.
    uint64_t mmap_next_ = 0x0000'7F40'0000'0000ull;
    uint64_t tid_address_ = 0;
    // Mach port names. Nothing here delivers a message, so a port only has to be a
    // number that is non-zero and distinct: the guest stores it, compares it, and
    // fails only if it is zero. Handing out the same one twice would make two
    // different things compare equal.
    uint32_t next_port_ = 0x1103;
    // A task's special ports (TASK_BOOTSTRAP_PORT and friends), by `which_port`. The same
    // port every time it is asked for, because that is what it is.
    std::map<uint32_t, uint32_t> special_ports_;
    // Where the synthesised dyld vtable and its stubs live: clear of the image, the
    // libraries, the arena and the stack.
    static constexpr uint64_t kDyldStubBase = 0x0000'0003'0000'0000ull;
    // dyld's APIs class has several hundred virtual methods, and a slot past the end of
    // the table lands in whatever follows it -- the stubs, in the first version, so the
    // guest read three instructions as a function pointer and branched to them.
    static constexpr uint32_t kDyldSlots = 1024;
    uint64_t dyld_vtable_ = 0;
    // Where libobjc left its callbacks, so the host can call them the way dyld would.
    uint64_t objc_callbacks_ = 0;
    uint64_t objc_opt_ro_ = 0, objc_opt_rw_ = 0, prog_header_ = 0;
    uint64_t cache_lo_ = 0, cache_hi_ = 0;
    // The shared cache's coalesced selector strings, name -> address, for slot 84. Built
    // once by walking the pool; empty until something asks.
    bool sel_pool_built_ = false;
    std::unordered_map<std::string, uint64_t> sel_map_;
    static constexpr uint64_t kObjcOptRw = 0x0000'0003'0200'0000ull;
    static constexpr uint64_t kObjcOptRwSize = 1u << 20;
    std::vector<std::string> objc_image_paths_;
    std::vector<uint64_t> objc_image_headers_;
    std::vector<LoadedImage::ImageSeg> image_segs_;
    // Where map_images's two arrays and their path strings go.
    static constexpr uint64_t kObjcArena = 0x0000'0003'0100'0000ull;
};

}  // namespace a64
