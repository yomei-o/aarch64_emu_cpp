/* Loads and stores: every width, both extensions, and the addressing modes.
   This is the largest surface in the decoder and the easiest to get subtly wrong
   -- a missed sign-extension or a writeback that uses the new base instead of the
   old one produces a number that looks fine. */
#include "harness.h"

static uint8_t buf[256];

TEST_MAIN {
    for (int i = 0; i < 256; i++) buf[i] = (uint8_t)(i * 7 + 3);

    /* widths, zero- and sign-extended */
    hex64(*(uint8_t*)(buf + 5));
    hex64((uint64_t)(int64_t)*(int8_t*)(buf + 5));
    hex64(*(uint16_t*)(buf + 6));
    hex64((uint64_t)(int64_t)*(int16_t*)(buf + 6));
    hex64(*(uint32_t*)(buf + 8));
    hex64((uint64_t)(int64_t)*(int32_t*)(buf + 8));
    hex64(*(uint64_t*)(buf + 16));
    hex64((uint64_t)(uint32_t)(int32_t)*(int16_t*)(buf + 6));

    /* stores of each width, read back wide */
    *(uint8_t*)(buf + 100) = 0xA5;
    *(uint16_t*)(buf + 102) = 0x1234;
    *(uint32_t*)(buf + 104) = 0xdeadbeef;
    *(uint64_t*)(buf + 112) = 0x0123456789abcdefULL;
    hex64(*(uint64_t*)(buf + 96));
    hex64(*(uint64_t*)(buf + 104));
    hex64(*(uint64_t*)(buf + 112));

    /* indexed addressing: a scaled register offset and a walking pointer */
    volatile int64_t idx = 13;
    hex64(*(uint32_t*)(buf + idx * 4));
    uint8_t* p = buf + 200;
    uint64_t acc = 0;
    for (int i = 0; i < 8; i++) acc = acc * 31 + *p++;      /* post-index */
    hex64(acc);
    for (int i = 0; i < 8; i++) acc = acc * 31 + *--p;      /* pre-index */
    hex64(acc);

    /* a struct copy, which the compiler turns into LDP/STP */
    struct S { uint64_t a, b, c, d; };
    volatile struct S s1 = {0x1111111111111111ULL, 0x2222222222222222ULL,
                            0x3333333333333333ULL, 0x4444444444444444ULL};
    struct S s2;
    s2 = *(struct S*)&s1;
    hex64(s2.a ^ s2.b ^ s2.c ^ s2.d);
    hex64(s2.a + s2.b + s2.c + s2.d);

    /* unaligned access, which AArch64 allows for ordinary loads */
    hex64(*(uint64_t*)(buf + 3));
    hex64(*(uint32_t*)(buf + 7));
    finish();
}
