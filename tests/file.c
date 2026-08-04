// The file syscalls, checked the same way everything else is: against the host
// reading the same bytes.
//
// This is the only test of the *error* convention, and the two personalities
// disagree about it completely — Linux returns a negative errno in x0, Darwin sets
// the carry flag and returns a positive one. An emulator that forgets the flag
// hands back a small positive number where a failure was expected, which reads as
// a perfectly good file descriptor. So opening something that is not there is not
// a corner case here; it is the point.
#include "harness.h"

static void dec(int64_t v) {
    char b[24];
    int i = 24;
    int neg = v < 0;
    uint64_t u = neg ? (uint64_t)(-v) : (uint64_t)v;
    if (!u) b[--i] = '0';
    while (u) { b[--i] = (char)('0' + (u % 10)); u /= 10; }
    if (neg) b[--i] = '-';
    b[23] = '\n';
    out(b + i, (uint64_t)(23 - i + 1));
}

TEST_MAIN {
    int64_t h = t_open(TEST_DATA);
    if (h < 0) {
        say("open failed\n");
    } else {
        int64_t size = t_fsize(h);
        say("size>0: ");
        dec(size > 0);

        // A checksum of the first kilobyte rather than the bytes themselves: the
        // point is that the emulator read the same file the host did, and a
        // mismatch shows up in one number instead of a screenful.
        char buf[1024];
        int64_t got = t_read(h, buf, sizeof buf);
        uint64_t sum = 1469598103934665603ull;
        for (int64_t i = 0; i < got; i++) {
            sum ^= (uint8_t)buf[i];
            sum *= 1099511628211ull;
        }
        say("read: ");
        dec(got);
        say("fnv: ");
        hex64(sum);
        t_close(h);
    }

    // The failure path. Only the sign matters -- the errno numbers themselves differ
    // between the host and the guest, and between Linux and Darwin.
    int64_t bad = t_open("/definitely-not-here-4a91");
    say("missing<0: ");
    dec(bad < 0);

    finish();
}
