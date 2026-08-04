// Lets one source file be both the guest program and its own oracle.
//
// Built for AArch64 it is freestanding: no libc, `_start`, and the two syscalls it
// needs written by hand. Built natively (-DA64_NATIVE) it is an ordinary program
// using printf. `run_tests.sh` builds both and diffs the output, so "the emulator
// is right" means "it produced the same bytes the host did", not "the number looked
// plausible" — which is the only claim worth making about an arithmetic core.
//
// Fixed-width types throughout, deliberately: `long` is 64-bit on the AArch64 side
// and 32-bit on a Windows host, so a test written with `long` would diff for a
// reason that has nothing to do with the emulator.
#pragma once
#include <stdint.h>

#ifdef A64_NATIVE

#include <stdio.h>
static void out(const char* s, uint64_t n) { fwrite(s, 1, (size_t)n, stdout); }
static void finish(void) { fflush(stdout); }
#define TEST_MAIN int main(void)

// The file primitives, in the three shapes below, all report failure as a negative
// value -- so a test can be written once and mean the same thing in each build.
static int64_t t_open(const char* p) {
    FILE* f = fopen(p, "rb");
    return f ? (int64_t)(intptr_t)f : -1;
}
static int64_t t_read(int64_t h, char* b, uint64_t n) {
    return (int64_t)fread(b, 1, (size_t)n, (FILE*)(intptr_t)h);
}
static int64_t t_fsize(int64_t h) {
    FILE* f = (FILE*)(intptr_t)h;
    long cur = ftell(f);
    fseek(f, 0, SEEK_END);
    long e = ftell(f);
    fseek(f, cur, SEEK_SET);
    return (int64_t)e;
}
static void t_close(int64_t h) { fclose((FILE*)(intptr_t)h); }
#define TEST_DATA "harness.h"

#elif defined(A64_DARWIN)

// The same tests, run through the Darwin personality instead of the Linux one, so
// the Mach-O loader and the BSD syscall path are checked against the *same* host
// oracle the ELF build is. Three things differ and nothing else does: the trap is
// `svc #0x80`, the number is in x16, and the numbering is BSD's (write 4, exit 1).
// Darwin reports failure by *setting the carry flag* and returning a positive
// errno, where Linux returns a negative one. `cset ..., cs` reads the flag back
// out, so the convention itself is under test: if the emulator forgot to set C,
// a failing open would look like a valid file descriptor.
static int64_t a64_sys(int64_t n, int64_t a, int64_t b, int64_t c) {
    register int64_t x16 __asm__("x16") = n, x0 __asm__("x0") = a;
    register int64_t x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    int64_t failed;
    __asm__ volatile("svc #0x80\n\tcset %1, cs"
                     : "+r"(x0), "=r"(failed)
                     : "r"(x16), "r"(x1), "r"(x2) : "memory", "cc");
    return failed ? -x0 : x0;
}
static void out(const char* s, uint64_t n) { a64_sys(4, 1, (int64_t)s, (int64_t)n); }
static void finish(void) { a64_sys(1, 0, 0, 0); }

static int64_t t_open(const char* p) { return a64_sys(5, (int64_t)p, 0 /*O_RDONLY*/, 0); }
static int64_t t_read(int64_t h, char* b, uint64_t n) {
    return a64_sys(3, h, (int64_t)b, (int64_t)n);
}
static int64_t t_fsize(int64_t h) {
    uint8_t st[144];                             // Darwin's struct stat64
    int64_t r = a64_sys(339 /*fstat64*/, h, (int64_t)st, 0);
    if (r < 0) return r;
    int64_t size;
    __builtin_memcpy(&size, st + 96, 8);         // st_size
    return size;
}
static void t_close(int64_t h) { a64_sys(6, h, 0, 0); }
#define TEST_DATA "/harness.h"
// Mach-O prefixes C symbols with an underscore, so the C function `start` is the
// linker's `_start` -- which is what -Wl,-e,_start asks for.
#define TEST_MAIN void start(void)

#else

static int64_t a64_sys(int64_t n, int64_t a, int64_t b, int64_t c) {
    register int64_t x8 __asm__("x8") = n, x0 __asm__("x0") = a;
    register int64_t x1 __asm__("x1") = b, x2 __asm__("x2") = c;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
    return x0;
}
static void out(const char* s, uint64_t n) { a64_sys(64, 1, (int64_t)s, (int64_t)n); }
static void finish(void) { a64_sys(93, 0, 0, 0); }
#define TEST_MAIN void _start(void)

// AArch64 Linux has no plain open(2): it is openat with AT_FDCWD (-100).
static int64_t t_open(const char* p) { return a64_sys(56, -100, (int64_t)p, 0 /*O_RDONLY*/); }
static int64_t t_read(int64_t h, char* b, uint64_t n) {
    return a64_sys(63, h, (int64_t)b, (int64_t)n);
}
static int64_t t_fsize(int64_t h) {
    uint8_t st[128];                             // Linux aarch64 struct stat
    int64_t r = a64_sys(80 /*fstat*/, h, (int64_t)st, 0);
    if (r < 0) return r;
    int64_t size;
    __builtin_memcpy(&size, st + 48, 8);         // st_size
    return size;
}
static void t_close(int64_t h) { a64_sys(57, h, 0, 0); }
#define TEST_DATA "/harness.h"

#endif

static void hex64(uint64_t v) {
    char b[19];
    b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 16; i++) b[2 + i] = "0123456789abcdef"[(v >> ((15 - i) * 4)) & 15];
    b[18] = '\n';
    out(b, 19);
}
static void say(const char* s) {
    uint64_t n = 0;
    while (s[n]) n++;
    out(s, n);
}
