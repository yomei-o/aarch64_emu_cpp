/* The integer core, checked against the host computing the same expressions. */
#include "harness.h"
TEST_MAIN {
    volatile int64_t a = -1234567890123LL, b = 7654321;
    hex64((uint64_t)(a + b));
    hex64((uint64_t)(a - b));
    hex64((uint64_t)(a * b));
    hex64((uint64_t)(a / b));
    hex64((uint64_t)(a % b));
    hex64((uint64_t)a / (uint64_t)b);
    hex64((uint64_t)(a >> 13));
    hex64((uint64_t)a >> 13);
    hex64((uint64_t)(a << 7));
    hex64((uint64_t)(a ^ b));
    hex64((uint64_t)(a & 0x00ff00ff00ff00ffLL));
    hex64((uint64_t)(a | 0x0f0f0f0fLL));
    hex64((uint64_t)(~a));
    hex64((uint64_t)(-a));

    volatile int32_t x = -70000, y = 300;
    hex64((uint32_t)(x / y));
    hex64((uint32_t)(x % y));
    hex64((uint32_t)(x * y));
    hex64((uint32_t)(x >> 3));
    hex64((uint32_t)x >> 3);
    hex64((uint32_t)(x + y));
    hex64((uint32_t)(x ^ y));

    /* comparisons and selects: the NZCV paths */
    hex64((uint64_t)(a < b));
    hex64((uint64_t)((uint64_t)a < (uint64_t)b));
    hex64((uint64_t)(a <= b));
    hex64((uint64_t)(a > b));
    hex64((uint64_t)(x < y ? 111 : 222));
    hex64((uint64_t)(a == -1234567890123LL));

    /* bit counting: CLZ, RBIT, and the CNT/UADDLV lowering of popcount */
    hex64((uint64_t)__builtin_clzll((uint64_t)b));
    hex64((uint64_t)__builtin_ctzll((uint64_t)b));
    hex64((uint64_t)__builtin_popcountll((uint64_t)a));
    hex64(__builtin_bswap64((uint64_t)a));
    hex64((uint64_t)__builtin_bswap32((uint32_t)x));

    /* 64x64 -> high half, and mixed-width multiply */
    volatile uint64_t big = 0xdeadbeefcafef00dULL;
    hex64((uint64_t)((unsigned __int128)big * big >> 64));
    hex64((uint64_t)(int64_t)((__int128)(int64_t)big * (int64_t)big >> 64));
    hex64((uint64_t)((int64_t)x * (int64_t)y));
    finish();
}
