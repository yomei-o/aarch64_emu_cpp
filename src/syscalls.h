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
    // Answer dyld API slot 111 (`_dyld_lookup_section_info`) instead of returning nothing.
    // Off by default, and the reason is in darwin.cpp: the answers are right, and they take
    // libobjc further than the rest of the emulator can currently follow. --dyld-sections.
    bool dyld_section_info = false;
    std::function<void(int fd, const char* data, uint64_t len)> output;
    std::function<int64_t(char* dst, uint64_t len)> input;
    std::function<int64_t(int fd, void* dst, uint64_t len, uint64_t off)> file_read;
    std::function<void(uint64_t nr)> unknown;
    // Run another program to completion and return its exit status, sharing this
    // process's descriptors. The host supplies it because loading a program means
    // reading files and choosing an address-space layout, which is the front end's
    // job -- `main.cpp` and `web/wasm_api.cpp` each have their own.
    //
    // Returning -1 means "could not start it", which `execve` reports as ENOENT.
    std::function<int(const std::string& path,
                      const std::vector<std::string>& argv,
                      const std::vector<std::string>& envp,
                      Files& files)> spawn;

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
    // Prints why the guest trapped, if it left a reason.  Apple's fatal paths -
    // os_crash, __abort_with_reason, libc's __chk failures, libdispatch's
    // DISPATCH_CLIENT_CRASH - write a message into their image's
    // `__DATA,__crash_info` and then execute BRK, so the trap on its own is the
    // report with the interesting half removed.  Wired to Cpu::on_brk.
    void report_crash_info();
    // Darwin thread-local storage. Fills in every `tlv_descriptor`'s thunk, which is
    // dyld's job and without which the first reference to a `_Thread_local` calls
    // through a null pointer -- or, in libsystem_c's case, aborts with "thread locals
    // not initialized" before the guest has printed anything.
    void setup_tlv(const std::vector<LoadedImage::TlvImage>& images);
    // Every image's `+load` methods. libobjc hands the callback over during its own
    // initializer, but running it there runs guest code that expects the libraries to
    // be up -- so the host holds it until the initializer list is finished, the way
    // dyld does.
    void run_objc_load_images();
    // The address a handler returns to when the guest supplied no restorer.
    static constexpr uint64_t kSigreturnMagic = 0x0000'0000'DEAD'0000ull;
    // The task's bootstrap port. Fixed rather than handed out from `next_port_`,
    // because the host writes it into the guest's `bootstrap_port` global before the
    // first instruction and `task_get_special_port` has to agree with what is already
    // there. A real Mac's is 0x807 on the machine this was measured on.
    static constexpr uint32_t kBootstrapPort = 0x807;


private:
    bool svc(uint32_t imm);
    // The Darwin personality, in darwin.cpp. Reached through `svc #0x80`, which is
    // how a Mach-O guest traps -- so the two kernels coexist in one build and are
    // told apart at the instruction rather than by a mode flag.
    bool svc_darwin();
    // Mach IPC, in darwin.cpp: enough of mach_msg2_trap and MIG to answer the kernel
    // RPCs a libSystem startup makes.
    int64_t dyld_api_stub(uint32_t slot);
    void call_guest(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3 = 0);
    int64_t mach_msg2(uint64_t data, uint64_t options, uint64_t bits_size,
                      uint64_t remote_local, uint64_t voucher_id,
                      uint64_t desc_rcvname, uint64_t rcv_size);
    int64_t sys_write(int fd, uint64_t buf, uint64_t len);
    int64_t sys_read(int fd, uint64_t buf, uint64_t len);
    int64_t sys_writev(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_readv(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_brk(uint64_t addr);
    std::string guest_str(uint64_t addr) { return mem_.read_cstr(addr); }
    // `shared_file` marks a MAP_SHARED file mapping, which has to be written back.
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
        // A workqueue worker's workloop, so that when it returns the *right* one
        // becomes requestable again.  Zero for an ordinary thread.
        uint64_t workloop = 0;
    };
    std::vector<Thread> threads_;       // empty until the first clone
    size_t cur_thread_ = 0;
    uint64_t next_tid_ = 1001;

    void ensure_main_thread();
    void switch_to(size_t idx);
    bool schedule(bool must_move);
    uint64_t current_tid() const;
    int64_t sys_clone(uint64_t flags, uint64_t stack, uint64_t ptid, uint64_t tls, uint64_t ctid);
    // fork/execve/wait4, in process.cpp. See the note there: the child is a *vfork*
    // child -- the parent is suspended and the two never run at the same time.
    int64_t sys_fork();
    int64_t sys_execve(uint64_t path, uint64_t argv, uint64_t envp);
    int64_t sys_wait4(int64_t pid, uint64_t status_addr);
    // Darwin posix_spawn, in darwin.cpp -- the struct layouts it decodes are
    // Darwin's, not POSIX's.
    int64_t sys_posix_spawn(uint64_t pid_addr, uint64_t path, uint64_t adesc,
                            uint64_t argv, uint64_t envp);
    bool in_vfork_child() const { return vfork_depth_ > 0; }
public:
    // True when a vfork child has just finished and the parent is waiting to be put
    // back. The run loop checks it; `vfork_resume()` does the putting back.
    bool vfork_pending() const { return vfork_returning_; }
    void vfork_resume();
private:
    // The parent's registers, saved across a vfork child. A vector because a child
    // may fork again -- `make` does, and `gcc` does under it.
    std::vector<Cpu::Context> vfork_saved_;
    // The parent's descriptor table, saved across a vfork child.
    //
    // Real vfork *shares* the table, and POSIX therefore forbids a child from touching
    // it -- but every real fork+exec does touch it, because redirecting the child's
    // standard streams is the entire point. CPython's `_posixsubprocess` dup2s the pipe
    // onto fd 1 and closes the rest, relying on fork having given it a copy.
    //
    // Sharing it left the *parent* with fd 1 pointing at the pipe after the child was
    // gone, so the parent's own `print` went into a buffer nobody read and the run
    // ended silently with status 1. The pipes themselves are shared_ptr, so what the
    // child wrote survives the copy -- which is the half that does have to be shared.
    std::vector<Files> vfork_files_;
    int vfork_depth_ = 0;
    // What the last child exited with, by pid, for wait4 to report.
    std::map<int, int> child_status_;
    int next_pid_ = 2000;
    // Set when a vfork child reaches execve or _exit: the run loop stops stepping and
    // `sys_fork` resumes the parent.
    bool vfork_returning_ = false;
    int vfork_child_pid_ = 0, vfork_child_status_ = 0;
    int64_t sys_bsdthread_create(uint64_t fn, uint64_t arg, uint64_t stack,
                                 uint64_t self, uint64_t flags);
    // Darwin's futex. Both write x0 *and* the carry flag themselves, because the
    // thread that made the call may not be the one running on return -- the same rule
    // every switching syscall here follows.
    int64_t sys_ulock_wait(uint32_t operation, uint64_t addr, uint64_t value);
    int64_t sys_ulock_wake(uint32_t operation, uint64_t addr);
    int64_t sys_psynch_cvwait(uint64_t cv, uint64_t mutex, bool timed);
    int64_t sys_psynch_cvsignal(uint64_t cv, bool broadcast);
    // Where `bsdthread_register` said new threads begin: libpthread's `_thread_start`,
    // not the start routine the guest passed to `pthread_create`.
    uint64_t bsdthread_entry_ = 0;
    // The *other* entry point bsdthread_register names: `_pthread_wqthread`, where a
    // workqueue worker starts.  A worker differs from a pthread in who owns the
    // stack - the kernel allocates it, and the `struct _pthread` inside it, before
    // the thread ever runs - which is why this needs its own creation path rather
    // than a flag on bsdthread_create.
    uint64_t wqthread_entry_ = 0;
    uint64_t pthread_size_ = 0;          // bsdthread_register's third argument
    // Workers asked for but not yet started.  libdispatch requests threads and
    // expects them to appear later, so a request is a promise, not a call.
    int workq_requested_ = 0;
    int workq_live_ = 0;
    // A workloop that has asked for a worker.  libdispatch requests threads for a
    // concurrent queue through kevent_id rather than workq_kernreturn, so this is
    // the path a linker actually takes.  Held by id so that re-registering the
    // same workloop while its worker is still running does not stack up threads.
    struct WorkloopRequest {
        uint64_t id = 0;
        uint8_t event[64] = {};      // the kevent_qos_s to hand the worker
    };
    std::vector<WorkloopRequest> workloop_pending_;
    std::vector<uint64_t> workloop_live_;
    // Creates one workqueue worker, or returns false if it cannot.  `event` is
    // null for a plain worker and points at a 64-byte kevent_qos_s for a workloop
    // one, which is a different entry convention rather than a different flag.
    bool spawn_workq_thread(bool overcommit, uint64_t workloop_id = 0,
                            const uint8_t* event = nullptr);
    // Starts any workers that have been asked for.  Called where the guest has
    // just given the scheduler a chance to run something else.
    void service_workq_requests();
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
    // What KERN_BOOTTIME reports, taken the first time it is asked and then fixed.
    uint64_t boot_time_ = 0;
    // Set by the host, which owns the address-space layout. The default is only a
    // fallback; main.cpp places it clear of the image, the interpreter and the stack.
    uint64_t mmap_next_ = 0x0000'7F40'0000'0000ull;
    // A file-backed MAP_SHARED mapping, and the whole reason it is remembered:
    // a shared mapping is how a program *writes* a file without ever calling
    // write(2), and ld does exactly that with its output.  The bytes have to go
    // back when the mapping is dropped or flushed, or the linker exits 0 having
    // produced nothing - which is precisely what it did.
    struct SharedMap {
        uint64_t base = 0, len = 0, off = 0;
        int fd = -1;
    };
    std::vector<SharedMap> shared_maps_;
    // Copies a shared mapping's bytes back to its file.  `all` writes every
    // mapping (exit); otherwise only the one covering `base`.
    void flush_shared_maps(uint64_t base, uint64_t len, bool all);
    uint64_t tid_address_ = 0;
    // Mach port names. Nothing here delivers a message, so a port only has to be a
    // number that is non-zero and distinct: the guest stores it, compares it, and
    // fails only if it is zero. Handing out the same one twice would make two
    // different things compare equal.
    uint32_t next_port_ = 0x1103;
    // A port's context word: one 64-bit value the owner may hang off any port,
    // set and read back through mach_port_{set,get}_context.  libxpc keeps its
    // connection object there.
    std::map<uint32_t, uint64_t> port_context_;
    // One special reply port per thread, which is what `thread_get_special_reply_port`
    // is for: a thread receives an XPC reply on its own port and keeps it.
    std::map<size_t, uint32_t> special_reply_ports_;
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
    uint64_t objc_load_images_ = 0, objc_infos_ = 0;
    size_t objc_info_count_ = 0;
    std::vector<std::string> objc_image_paths_;
    std::vector<uint64_t> objc_image_headers_;
    std::vector<LoadedImage::ImageSeg> image_segs_;
    // The guest-visible path string for an image, by mach_header. dyld hands these out as
    // `const char*`, and the host's copy of the list is std::strings -- so they are copied
    // into guest memory the first time one is asked for. `map_images` also writes paths,
    // but only if libobjc asked for them, and this cannot depend on that having happened.
    uint64_t image_path_addr(uint64_t header);
    std::unordered_map<uint64_t, uint64_t> path_addr_;
    static constexpr uint64_t kPathArena = 0x0000'0003'0300'0000ull;
    static constexpr uint64_t kPathArenaSize = 1u << 16;
    uint64_t path_next_ = 0;
    // Where map_images's two arrays and their path strings go.
    static constexpr uint64_t kObjcArena = 0x0000'0003'0100'0000ull;
    // The `mark image mutable` block map_images takes as its third argument. A block is
    // {isa, flags, reserved, invoke, descriptor} and libobjc calls `invoke(block, index)`,
    // so this needs a real function to point at -- see the note at `case 107`.
    // 0x3'0400'0000 is the main thread's TSD region, in main.cpp -- this arena has to
    // be somewhere else, and "somewhere else" is a list worth keeping in one place:
    // 0x3'0000'0000 dyld stubs, 0x3'0100'0000 objc infos, 0x3'0200'0000 opt_rw,
    // 0x3'0300'0000 paths, 0x3'0400'0000 TSD.
    static constexpr uint64_t kObjcBlock = 0x0000'0003'0500'0000ull;
    // Thread-local storage. `tlv_thunk_` is two instructions the descriptors point at;
    // `tlv_blocks_` is one guest allocation per (thread, image), made on first use and
    // seeded from that image's template.
    static constexpr uint64_t kTlvBase = 0x0000'0003'0600'0000ull;
    static constexpr uint64_t kTlvSize = 8u << 20;
    uint64_t tlv_thunk_ = 0, tlv_next_ = 0;
    std::vector<LoadedImage::TlvImage> tlv_images_;
    // Keyed on (image index, thread index): the same variable in two threads is two
    // allocations, which is the entire point of the mechanism.
    std::map<std::pair<uint32_t, size_t>, uint64_t> tlv_blocks_;
    uint64_t tlv_addr(uint64_t descriptor);
    static constexpr uint64_t kObjcBlockSize = 1u << 12;
};

}  // namespace a64
