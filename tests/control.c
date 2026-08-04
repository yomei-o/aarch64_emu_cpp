/* Branches, conditional selects and the flag paths, plus a recursive call so the
   link register and the frame pointer get exercised. */
#include "harness.h"

static uint64_t fib(uint64_t n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

static uint64_t collatz(uint64_t n) {
    uint64_t steps = 0;
    while (n != 1) { n = (n & 1) ? 3 * n + 1 : n / 2; steps++; }
    return steps;
}

TEST_MAIN {
    hex64(fib(24));
    hex64(collatz(97));
    for (int64_t v = -3; v <= 3; v++) {
        uint64_t r = 0;
        if (v < 0) r = 1; else if (v == 0) r = 2; else r = 3;
        r = r * 10 + (v < 0 ? 7u : 9u);                      /* CSEL */
        r += (v >= -1 && v <= 1) ? 100 : 200;                /* CCMP chain */
        hex64(r);
    }
    volatile uint64_t big = 0xFFFFFFFFFFFFFFF0ULL;
    hex64(big + 0x20);                                        /* unsigned wrap */
    volatile int64_t imax = 0x7FFFFFFFFFFFFFFFLL;             /* volatile: the overflow has
                                                                 to happen at run time, not be
                                                                 folded (and diagnosed) by the
                                                                 two compilers differently */
    hex64((uint64_t)(imax + 1));
    uint64_t sw = 0;
    for (int i = 0; i < 8; i++) {
        switch (i) {                                          /* a jump table */
            case 0: sw += 3; break;
            case 1: sw += 5; break;
            case 2: sw += 7; break;
            case 3: sw += 11; break;
            case 4: sw += 13; break;
            default: sw = sw * 2 + i; break;
        }
    }
    hex64(sw);
    finish();
}
