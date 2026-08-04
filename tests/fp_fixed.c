// FP <-> fixed-point conversion: FCVTZS, FCVTZU, SCVTF, UCVTF with a scale.
//
// These sit next to the integer conversions and differ only in one bit and a
// six-bit scale field, which is exactly the sort of neighbour that gets decoded by
// accident. They are also the ones a plain C program almost never emits, so nothing
// else in this suite would notice: CPython was the first thing to reach one, 229
// million instructions in, converting a float timeout into a lock deadline.
//
// Everything is compared as a *bit pattern*, so a result that is close is still a
// failure.
#include "harness.h"

#ifdef A64_NATIVE

#include <math.h>
static uint64_t fcvtzu_fx(double v, int fb) {
    double s = v * ldexp(1.0, fb);
    return s <= 0 ? 0 : (uint64_t)s;
}
static int64_t fcvtzs_fx(double v, int fb) { return (int64_t)(v * ldexp(1.0, fb)); }
static double scvtf_fx(int64_t v, int fb) { return (double)v / ldexp(1.0, fb); }
static double ucvtf_fx(uint64_t v, int fb) { return (double)v / ldexp(1.0, fb); }
#define FCVTZU(v, FB) fcvtzu_fx((v), (FB))
#define FCVTZS(v, FB) fcvtzs_fx((v), (FB))
#define SCVTF(v, FB)  scvtf_fx((v), (FB))
#define UCVTF(v, FB)  ucvtf_fx((v), (FB))

#else

// The scale is an immediate, so each case is its own instruction rather than a
// loop over a variable.
#define FCVTZU(v, FB) ({ uint64_t r_; double v_ = (v); \
    __asm__("fcvtzu %0, %d1, #" #FB : "=r"(r_) : "w"(v_)); r_; })
#define FCVTZS(v, FB) ({ int64_t r_; double v_ = (v); \
    __asm__("fcvtzs %0, %d1, #" #FB : "=r"(r_) : "w"(v_)); r_; })
#define SCVTF(v, FB)  ({ double r_; int64_t v_ = (v); \
    __asm__("scvtf %d0, %1, #" #FB : "=w"(r_) : "r"(v_)); r_; })
#define UCVTF(v, FB)  ({ double r_; uint64_t v_ = (v); \
    __asm__("ucvtf %d0, %1, #" #FB : "=w"(r_) : "r"(v_)); r_; })

#endif

static void bits(double d) {
    uint64_t u;
    __builtin_memcpy(&u, &d, 8);
    hex64(u);
}

TEST_MAIN {
    say("fcvtzu\n");
    hex64(FCVTZU(0.5, 1));
    hex64(FCVTZU(3.14159265358979, 28));
    hex64(FCVTZU(123.456, 8));
    hex64(FCVTZU(1.0 / 3.0, 32));
    hex64(FCVTZU(1.0e-7, 52));
    hex64(FCVTZU(-2.5, 4));            // negative saturates to 0 unsigned
    hex64(FCVTZU(0.9999999, 63));

    say("fcvtzs\n");
    hex64((uint64_t)FCVTZS(-3.14159265358979, 28));
    hex64((uint64_t)FCVTZS(0.5, 1));
    hex64((uint64_t)FCVTZS(-123.456, 8));
    hex64((uint64_t)FCVTZS(1.0e-9, 60));

    say("scvtf\n");
    bits(SCVTF(1, 1));
    bits(SCVTF(-843314857, 28));
    bits(SCVTF(31604, 8));
    bits(SCVTF(-1, 60));

    say("ucvtf\n");
    bits(UCVTF(0xFFFFFFFFull, 32));
    bits(UCVTF(1, 63));
    bits(UCVTF(1000000, 20));

    finish();
}
