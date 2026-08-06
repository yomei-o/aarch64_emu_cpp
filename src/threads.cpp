// Threads: `clone`, `futex`, and a scheduler that runs one of them at a time.
//
// One emulated CPU, N guest threads, switched by saving and restoring the whole
// register file. That is not how a real kernel does it, but it is enough for the
// thing a guest actually depends on — that another thread eventually *runs* — and
// it keeps the interpreter single-threaded, so no memory model question arises and
// load/store-exclusive can stay a plain load/store.
//
// Two places give the CPU up:
//
//  - **Voluntarily**, at `futex(WAIT)`, `sched_yield`, and thread exit. This is the
//    common path: musl blocks on a futex whenever a lock is contended.
//  - **By preemption**, every N instructions. A guest that spins instead of
//    blocking — and one exists in almost every libc, in the short spin before the
//    futex — would otherwise hold the CPU forever. Preemption is switched on only
//    when a second thread appears, so a single-threaded guest pays one branch.
//
// A switch has to be all-or-nothing: any syscall that may switch writes its own
// return value into x0 *before* switching, and returns without falling into the
// shared `cpu_.setx(0, r)` tail — which would otherwise land in whichever thread
// happens to be current afterwards.
#include "syscalls.h"
#include <cstdio>

namespace a64 {

namespace {
constexpr uint64_t kCloneVm     = 0x00000100;
constexpr uint64_t kCloneThread = 0x00010000;
// Long enough that switching is not the dominant cost, short enough that a spin
// of a few thousand iterations still yields. Nothing depends on the exact value.
constexpr uint64_t kPreemptEvery = 20000;
}  // namespace

// The main thread is not created by `clone`, so it does not exist as a Thread
// until the moment a second one does. Materialising it lazily keeps every
// single-threaded guest on exactly the path it had before threads existed.
void Syscalls::ensure_main_thread() {
    if (!threads_.empty()) return;
    Thread t;
    t.tid = 1000;
    t.clear_child_tid = tid_address_;
    threads_.push_back(t);
    cur_thread_ = 0;
}

uint64_t Syscalls::current_tid() const {
    return threads_.empty() ? 1000 : threads_[cur_thread_].tid;
}

// Save the running thread, make `idx` current. The caller has already decided that
// `idx` is runnable.
void Syscalls::switch_to(size_t idx) {
    if (idx == cur_thread_) return;
    threads_[cur_thread_].ctx = cpu_.save_context();
    cur_thread_ = idx;
    cpu_.load_context(threads_[idx].ctx);
}

// Round-robin from the one after the current, so a thread that yields does not
// immediately get picked again. Returns false when nothing else can run.
bool Syscalls::schedule(bool must_move) {
    // Workers asked for since the last switch are started here, which is the one
    // place that is both "the guest has stopped for a moment" and "a new thread
    // would be picked up".  Starting them inside workq_kernreturn instead would
    // add a thread to the list while the caller is mid-syscall.
    service_workq_requests();
    if (threads_.size() < 2) return !must_move;
    const size_t n = threads_.size();
    for (size_t k = 1; k <= n; ++k) {
        const size_t i = (cur_thread_ + k) % n;
        if (i == cur_thread_ && must_move) continue;
        if (threads_[i].exited || threads_[i].waiting) continue;
        switch_to(i);
        return true;
    }
    return false;
}

int64_t Syscalls::sys_clone(uint64_t flags, uint64_t stack, uint64_t ptid, uint64_t tls,
                            uint64_t ctid) {
    // Anything that does not share the address space is a fork, and there is one
    // address space here. Refusing loudly beats handing back a plausible pid and
    // letting the guest believe it has a child.
    if (!(flags & kCloneVm) || !(flags & kCloneThread)) {
        std::fprintf(stderr, "[sys] clone(%llX) is a fork, not a thread; unsupported\n",
                     static_cast<unsigned long long>(flags));
        return -38;                                          // ENOSYS
    }
    ensure_main_thread();

    Thread child;
    child.tid = next_tid_++;
    // The child resumes exactly where the parent is — just past the SVC — with a
    // stack of its own, its own thread pointer, and 0 in x0 to tell the two apart.
    child.ctx = cpu_.save_context();
    child.ctx.sp = stack;
    child.ctx.tpidr_el0 = tls;
    child.ctx.x[0] = 0;
    child.clear_child_tid = ctid;
    if (ptid) mem_.write<uint32_t>(ptid, static_cast<uint32_t>(child.tid));
    if (ctid) mem_.write<uint32_t>(ctid, static_cast<uint32_t>(child.tid));
    threads_.push_back(child);

    // From here the guest is concurrent, so the CPU has to be taken away from a
    // thread that never asks.
    cpu_.preempt_every = kPreemptEvery;
    cpu_.preempt_left = kPreemptEvery;
    cpu_.on_preempt = [this] { schedule(true); };
    return static_cast<int64_t>(child.tid);
}

// Called from the preemption hook and from sched_yield. A failure to find another
// runnable thread is not an error here — the current one simply keeps going.
int64_t Syscalls::sys_sched_yield() {
    cpu_.setx(0, 0);
    schedule(true);
    return 0;
}

// FUTEX_WAIT and FUTEX_WAKE, which is all musl needs. The private and
// clock-realtime flags change nothing for a single address space.
int64_t Syscalls::sys_futex(uint64_t addr, int op, uint32_t val) {
    const int base = op & 0x7F;
    if (base == 0 || base == 9) {                            // WAIT, WAIT_BITSET
        // The load and the compare are atomic with respect to the guest because
        // nothing else is running: the whole point of the check is that the value
        // may have changed between the guest's own load and this call.
        if (mem_.read<uint32_t>(addr) != val) {
            cpu_.setx(0, static_cast<uint64_t>(-11));        // EAGAIN
            return 0;
        }
        ensure_main_thread();
        cpu_.setx(0, 0);                                     // woken normally
        threads_[cur_thread_].waiting = true;
        threads_[cur_thread_].wait_addr = addr;
        if (!schedule(true)) {
            // Every thread is blocked on a futex nobody will post. That is a guest
            // deadlock, and reporting it beats spinning forever in a loop that looks
            // exactly like hard work.
            threads_[cur_thread_].waiting = false;
            throw CpuError{"all threads are blocked on a futex: deadlock", cpu_.pc, 0};
        }
        return 0;
    }
    if (base == 1 || base == 10) {                           // WAKE, WAKE_BITSET
        uint32_t woken = 0;
        for (Thread& t : threads_) {
            if (woken >= val) break;
            if (t.waiting && t.wait_addr == addr) { t.waiting = false; ++woken; }
        }
        cpu_.setx(0, woken);
        return 0;
    }
    // FUTEX_REQUEUE and friends. Waking everyone is not what they mean, but it is
    // never *wrong* — a spurious wake is allowed and the guest rechecks — whereas
    // ENOSYS would strand the waiters.
    for (Thread& t : threads_) if (t.waiting && t.wait_addr == addr) t.waiting = false;
    cpu_.setx(0, 0);
    return 0;
}

// Darwin's futex: `__ulock_wait` and `__ulock_wake`.
//
//     __ulock_wait(operation, addr, value, timeout_us)
//     __ulock_wake(operation, addr, wake_value)
//
// The same contract as FUTEX_WAIT/WAKE with three differences that matter here:
//
//  - the low byte of `operation` picks the comparison *width* -- the UL_*64 forms
//    compare eight bytes, the rest four. Comparing the wrong width against a lock
//    word whose upper half holds an owner is how a wait returns instantly, forever;
//  - `ULF_NO_ERRNO` asks for the error as a negative return value instead of through
//    the carry flag, and libpthread sets it. Answering the wrong way makes a
//    "nobody was waiting" into a valid small positive result;
//  - waking nobody is `-ENOENT`, not success. A caller that is told it woke someone
//    waits for an acknowledgement that never comes.
int64_t Syscalls::sys_ulock_wait(uint32_t operation, uint64_t addr, uint64_t value) {
    const unsigned op = operation & 0xFF;
    const bool wide = op == 4 || op == 5 || op == 6;   // the UL_*64 operations
    const bool no_errno = (operation & 0x0100'0000u) != 0;
    // Read and compare with nothing else running, which is what makes this atomic
    // from the guest's point of view: the value may have changed between the guest's
    // own load and this call, and that is the whole reason the kernel re-checks.
    const uint64_t now = wide ? mem_.read<uint64_t>(addr)
                              : static_cast<uint64_t>(mem_.read<uint32_t>(addr));
    const uint64_t want = wide ? value : (value & 0xFFFF'FFFFull);
    if (now != want) {
        // EAGAIN: the caller's reason for sleeping is already gone.
        cpu_.setx(0, static_cast<uint64_t>(no_errno ? -35 : 35));
        cpu_.c = !no_errno;
        return 0;
    }
    ensure_main_thread();
    cpu_.setx(0, 0);
    cpu_.c = false;
    threads_[cur_thread_].waiting = true;
    threads_[cur_thread_].wait_addr = addr;
    if (!schedule(true)) {
        threads_[cur_thread_].waiting = false;
        throw CpuError{"all threads are blocked in ulock_wait: deadlock", cpu_.pc, 0};
    }
    return 0;
}

int64_t Syscalls::sys_ulock_wake(uint32_t operation, uint64_t addr) {
    const bool all = (operation & 0x0000'0100u) != 0;   // ULF_WAKE_ALL
    const bool no_errno = (operation & 0x0100'0000u) != 0;
    unsigned woken = 0;
    for (Thread& t : threads_) {
        if (!t.waiting || t.wait_addr != addr) continue;
        t.waiting = false;
        ++woken;
        if (!all) break;
    }
    if (!woken) {
        cpu_.setx(0, static_cast<uint64_t>(no_errno ? -2 : 2));   // ENOENT
        cpu_.c = !no_errno;
        return 0;
    }
    cpu_.setx(0, 0);
    cpu_.c = false;
    return 0;
}

// `__psynch_cvwait` and friends: the older half of Darwin's synchronisation, which
// pthread condition variables still use even where mutexes have moved to ulock.
//
//     __psynch_cvwait(cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec)
//     __psynch_cvsignal(cv, cvlsgen, cvugen, mutex, mugen, thread, flags)
//     __psynch_cvbroad(cv, cvlsgen, cvugen, mutex, mugen, thread, flags)
//
// The generation counters are how the real kernel decides which waiters a signal
// applies to; here there is one CPU and a switch happens only where this code says
// so, so "who is waiting on this address" is the whole of the state and the counters
// are not consulted. What does have to be right is the *mutex*: the kernel drops it
// on the way into the wait and the caller expects to hold it again on the way out.
// Anyone blocked on it is therefore woken here.
int64_t Syscalls::sys_psynch_cvwait(uint64_t cv, uint64_t mutex, bool timed) {
    ensure_main_thread();
    for (Thread& t : threads_)
        if (t.waiting && t.wait_addr == mutex) t.waiting = false;
    cpu_.setx(0, 0);
    cpu_.c = false;
    threads_[cur_thread_].waiting = true;
    threads_[cur_thread_].wait_addr = cv;
    if (!schedule(true)) {
        threads_[cur_thread_].waiting = false;
        // A timed wait that nobody can satisfy is a *timeout*, which the caller is
        // written to handle -- CPython's `take_gil` retries. An untimed one is a
        // deadlock, and saying so beats spinning in something that looks like work.
        if (timed) {
            cpu_.setx(0, 60);                                // ETIMEDOUT
            cpu_.c = true;
            return 0;
        }
        throw CpuError{"all threads are blocked in psynch_cvwait: deadlock", cpu_.pc, 0};
    }
    return 0;
}

int64_t Syscalls::sys_psynch_cvsignal(uint64_t cv, bool broadcast) {
    unsigned woken = 0;
    for (Thread& t : threads_) {
        if (!t.waiting || t.wait_addr != cv) continue;
        t.waiting = false;
        ++woken;
        if (!broadcast) break;
    }
    cpu_.setx(0, woken);
    cpu_.c = false;
    return 0;
}

// Darwin creates a thread through `bsdthread_create`, not `clone`, and the shape of
// the call is different enough to be worth spelling out rather than translating.
//
//     bsdthread_create(fn, arg, stack, self, flags)
//
// The kernel does *not* start the thread at `fn`. It starts it at the entry point
// libpthread registered with `bsdthread_register` -- `_thread_start`, which falls
// straight into `_pthread_start` -- and passes `fn` and `arg` along as arguments:
//
//     thread_start(self, kport, fun, arg, stacksize, flags)
//
// So the emulator plays the same trick: a new Thread whose PC is the registered
// entry and whose registers carry the four values the trampoline expects. Nothing
// else about the thread has to be invented, because with PTHREAD_START_CUSTOM --
// which is what a `pthread_create` with a normal attribute sets -- libpthread has
// already allocated the stack *and* filled in the `struct _pthread` before the call.
//
// The thread pointer is the part the kernel really does own: Darwin's TPIDRRO_EL0
// points at the TSD array *inside* the pthread structure, 0xE0 bytes past its base,
// with the header fields at negative offsets. Getting that wrong is not a crash, it
// is `errno` landing on top of something else.
// ---------------------------------------------------------------------------
// The pthread workqueue: where libdispatch's worker threads come from
// ---------------------------------------------------------------------------
//
// libdispatch does not create threads.  It asks the kernel for them through
// libpthread's workqueue, and the kernel makes one by allocating a stack, laying a
// `struct _pthread` at the top of it, and entering `_pthread_wqthread` - the
// second entry point `bsdthread_register` names.  That last part is the whole
// reason this cannot be a flag on bsdthread_create: for an ordinary pthread,
// *libpthread* allocates the stack and the struct and the kernel only jumps; for a
// worker, the kernel owns both.
//
// The argument convention, which had to match libpthread's `_pthread_wqthread`
// exactly:
//
//     x0  self         the struct _pthread the kernel laid down
//     x1  kport        this thread's mach port
//     x2  stackaddr    the *low* end of the allocation
//     x3  keventlist   NULL: this is a plain worker, not a kevent one
//     x4  flags        WQ_FLAG_THREAD_NEWSPI, plus the QoS class
//     x5  nkevents     0, for the same reason as x3
//
// Getting x4 wrong is quiet: libpthread reads the QoS out of the low bits and
// carries on with a nonsense priority.  Getting the TSD wrong is loud, and
// usefully so - libpthread stops the process itself with "BUG IN CLIENT OF
// LIBPTHREAD: Unable to allocate thread port" when tsd[3] is empty, which is the
// same assertion bsdthread_create had to satisfy.
bool Syscalls::spawn_workq_thread(bool overcommit) {
    if (!wqthread_entry_) return false;
    ensure_main_thread();

    // The kernel's own stack allocation.  512 KiB is what Darwin gives a worker,
    // and the struct _pthread goes at the top, where libpthread expects to find
    // it - it computes the usable stack as everything below `self`.
    constexpr uint64_t kStackSize = 512 * 1024;
    const uint64_t pth = pthread_size_ ? ((pthread_size_ + 15) & ~15ull) : 0x1000;
    const uint64_t low = static_cast<uint64_t>(
        sys_mmap(0, kStackSize + pth, 3 /*RW*/, 0x1002 /*ANON|PRIVATE*/, -1, 0));
    if (!low || low > 0xFFFF'FFFF'FFFF'0000ull) return false;
    const uint64_t self = low + kStackSize;        // the struct, above the stack

    Thread w;
    w.tid = next_tid_++;
    w.ctx = cpu_.save_context();
    w.ctx.pc = wqthread_entry_;
    w.ctx.sp = self;                               // grows down into the stack
    w.ctx.tpidr_el0 = self + 0xE0;                 // the TSD array, as elsewhere
    const uint64_t port = next_port_++;
    mem_.write<uint64_t>(self + 0xE0, self);       // tsd[0]: pthread_self
    mem_.write<uint64_t>(self + 0xF8, port);       // tsd[3]: the mach port

    constexpr uint64_t kWqFlagNewSpi = 0x0001'0000;
    constexpr uint64_t kWqFlagOvercommit = 0x0002'0000;
    constexpr uint64_t kQosDefault = 4;            // QOS_CLASS_DEFAULT
    w.ctx.x[0] = self;
    w.ctx.x[1] = port;
    w.ctx.x[2] = low;
    w.ctx.x[3] = 0;
    w.ctx.x[4] = kWqFlagNewSpi | (overcommit ? kWqFlagOvercommit : 0) | kQosDefault;
    w.ctx.x[5] = 0;
    w.ctx.x[30] = 0;                               // a worker never returns
    threads_.push_back(w);
    ++workq_live_;
    if (trace)
        std::fprintf(stderr, "[proc] workq worker tid %llu at %llX, stack %llX\n",
                     static_cast<unsigned long long>(w.tid),
                     static_cast<unsigned long long>(wqthread_entry_),
                     static_cast<unsigned long long>(low));
    return true;
}

void Syscalls::service_workq_requests() {
    // A cap, because a request is a promise and libdispatch will happily ask for
    // one per available core per queue.  Enough that a parallel phase makes
    // progress, few enough that a runaway request loop stops.
    constexpr int kMaxWorkers = 8;
    while (workq_requested_ > 0 && workq_live_ < kMaxWorkers) {
        --workq_requested_;
        if (!spawn_workq_thread(false)) break;
    }
    if (workq_requested_ > 0 && workq_live_ >= kMaxWorkers) workq_requested_ = 0;
}

int64_t Syscalls::sys_bsdthread_create(uint64_t fn, uint64_t arg, uint64_t stack,
                                       uint64_t self, uint64_t flags) {
    if (!bsdthread_entry_) {
        std::fprintf(stderr, "[mac] bsdthread_create before bsdthread_register\n");
        return -1;
    }
    ensure_main_thread();

    Thread child;
    child.tid = next_tid_++;
    child.ctx = cpu_.save_context();
    child.ctx.pc = bsdthread_entry_;
    child.ctx.sp = stack;
    // 0xE0: the offset from `struct _pthread` to its TSD array. main.cpp places the
    // main thread's the same way, and for the same reason.
    child.ctx.tpidr_el0 = self + 0xE0;
    // The port goes in x1 *and* into the thread's own TSD, because libpthread reads it
    // back from there rather than from the argument:
    //
    //     ldr w8, [x19, #0xf8]      ; self->tsd[3], _PTHREAD_TSD_SLOT_MACH_THREAD_SELF
    //     add w9, w8, #1            ; and it must be neither 0 nor -1
    //     cmp w9, #1
    //     b.ls  <BUG IN CLIENT OF LIBPTHREAD: Unable to allocate thread port>
    //
    // 0xf8 is 0xe0 + 3*8: the TSD array, slot three. Setting up that array is the
    // kernel's job on a real machine, which is why libpthread treats an empty slot as
    // a bug in whoever created the thread rather than in itself.
    const uint64_t port = next_port_++;
    child.ctx.x[0] = self;
    child.ctx.x[1] = port;
    mem_.write<uint64_t>(self + 0xE0, self);       // tsd[0]: pthread_self
    mem_.write<uint64_t>(self + 0xF8, port);       // tsd[3]: the mach port
    child.ctx.x[2] = fn;
    child.ctx.x[3] = arg;
    child.ctx.x[4] = stack;
    // PTHREAD_START_TSD_BASE_SET. The kernel does not merely set the thread pointer,
    // it *says* it did, by adding this bit to the flags it passes on -- and libpthread
    // checks, then stops the process itself when the bit is missing:
    //
    //     BUG IN LIBPTHREAD: thread_set_tsd_base() wasn't called by the kernel
    //
    // Which is the whole argument for reading the guest's strings: the thread pointer
    // was already right, and nothing about a missing status bit would have been
    // guessable from the crash address.
    child.ctx.x[5] = flags | 0x1000'0000ull;
    // x30 is whatever the creating thread had. A thread that returns from its start
    // routine goes through libpthread's own exit path, so this is never used -- but
    // a plausible address would hide the case where it is, and zero does not.
    child.ctx.x[30] = 0;
    threads_.push_back(child);
    if (trace)
        std::fprintf(stderr, "[thr] bsdthread_create -> tid %llu, entry %012llX, "
                             "fn %012llX, sp %012llX  (%zu threads)\n",
                     static_cast<unsigned long long>(child.tid),
                     static_cast<unsigned long long>(bsdthread_entry_),
                     static_cast<unsigned long long>(fn),
                     static_cast<unsigned long long>(stack), threads_.size());

    cpu_.preempt_every = kPreemptEvery;
    cpu_.preempt_left = kPreemptEvery;
    cpu_.on_preempt = [this] {
        const size_t was = cur_thread_;
        const bool moved = schedule(true);
        if (trace)
            std::fprintf(stderr, "[thr] preempt %zu -> %zu (%s)\n", was, cur_thread_,
                         moved ? "switched" : "stayed");
    };
    // The return value is the new thread's `self`, which is what libpthread stores.
    return static_cast<int64_t>(self);
}

// exit(2) ends one thread; exit_group(2) ends the process. Before threads existed
// the two were the same call, and treating exit as exit_group here would kill the
// program the first time any worker finished.
void Syscalls::thread_exit(int status) {
    if (threads_.size() < 2) {
        cpu_.exit_code = status;
        cpu_.halted = true;
        return;
    }
    Thread& me = threads_[cur_thread_];
    me.exited = true;
    me.waiting = false;
    // musl's pthread_join waits on this word, and the kernel is what clears it and
    // wakes the joiner. Skip it and join() hangs on a thread that has already gone.
    if (me.clear_child_tid) {
        mem_.write<uint32_t>(me.clear_child_tid, 0);
        for (Thread& t : threads_)
            if (t.waiting && t.wait_addr == me.clear_child_tid) t.waiting = false;
    }
    if (!schedule(true)) {
        cpu_.exit_code = status;
        cpu_.halted = true;
    }
}

}  // namespace a64
