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
