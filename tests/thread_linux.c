// Threads, without a libc: raw `clone`, raw `futex`, and the compiler's atomics —
// which on AArch64 means real LDAXR/STLXR loops, so this also tests the exclusive
// monitor under preemption.
//
// The oracle is the host doing the same additions in one thread. That is the whole
// claim worth making: N threads racing on one counter must produce exactly the
// number one thread would, and a lost update anywhere in 100,000 increments changes
// it. An emulator whose STXR always succeeds passes every single-threaded test and
// fails this one.
//
// Linux-only by name (`_linux`), because Darwin creates threads through
// bsdthread_create and Mach ports, not clone -- run_macho.sh skips it rather than
// pretending the two are the same call.
#include "harness.h"

#define NTHREADS 4
#define NITER    25000

#ifdef A64_NATIVE

TEST_MAIN {
    int64_t counter = 0;
    for (int t = 0; t < NTHREADS; t++)
        for (int k = 0; k < NITER; k++) counter++;
    say("threads: ");
    dec(NTHREADS);
    say("counter: ");
    dec(counter);
    finish();
}

#else

static volatile int64_t counter;
static volatile int32_t done;
_Alignas(16) static uint64_t stacks[NTHREADS][2048];

static void worker(void) {
    for (int k = 0; k < NITER; k++) __atomic_add_fetch(&counter, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&done, 1, __ATOMIC_SEQ_CST);
    a64_sys(98, (int64_t)&done, 1 /*FUTEX_WAKE*/, NTHREADS);
}

// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD -- the set that
// means "another thread of this process" rather than "a child process".
#define THREAD_FLAGS 0x10F00

// The child cannot simply return into C: clone hands it a brand new stack, and the
// C frame it would return into belongs to the parent. So the child's whole life is
// in the asm -- call the worker, then exit(2) -- and only the parent falls out.
static int64_t spawn(void (*fn)(void), void* stack_top) {
    register int64_t x0 __asm__("x0") = THREAD_FLAGS;
    register int64_t x1 __asm__("x1") = (int64_t)stack_top;
    register int64_t x2 __asm__("x2") = 0;      // parent_tid
    register int64_t x3 __asm__("x3") = 0;      // tls
    register int64_t x4 __asm__("x4") = 0;      // child_tid
    register int64_t x8 __asm__("x8") = 220;    // clone
    register void (*fnr)(void) __asm__("x9") = fn;
    __asm__ volatile(
        "svc #0\n\t"
        "cbnz x0, 1f\n\t"          // non-zero: the parent, and x0 is the new tid
        "blr x9\n\t"               // the child, on its own stack
        "mov x8, #93\n\t"          // exit(0) -- this thread only
        "mov x0, #0\n\t"
        "svc #0\n"
        "1:"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8), "r"(fnr)
        : "memory", "x30", "cc");
    return x0;
}

TEST_MAIN {
    for (int t = 0; t < NTHREADS; t++) spawn(worker, &stacks[t][2048]);

    // Join by blocking on the counter of finished threads. futex(WAIT) checks the
    // value against what we just read and only sleeps if it still matches, which is
    // what makes the race between the check and the sleep harmless.
    for (;;) {
        int32_t cur = __atomic_load_n(&done, __ATOMIC_SEQ_CST);
        if (cur >= NTHREADS) break;
        a64_sys(98, (int64_t)&done, 0 /*FUTEX_WAIT*/, cur);
    }

    say("threads: ");
    dec(NTHREADS);
    say("counter: ");
    dec(counter);
    finish();
}

#endif
