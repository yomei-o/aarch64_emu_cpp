// The ARMv8.1 "LSE" atomics: CAS, SWP and the LD<op> family.
//
// Apple's libraries use these everywhere instead of an LDXR/STXR retry loop, so
// running libSystem needs the whole group rather than a useful subset. They also sit
// in an encoding corner that is easy to mis-split: `casa x8, x9, [x0]` differs from
// `stxp` only in bit 23, and this emulator decoded the first as the second until a
// real macOS binary walked into it 518 instructions in.
//
// Each case does the operation on a cell and prints both halves of the result -- the
// value returned *and* the value left in memory -- because an implementation can
// easily get one right and the other wrong. The host computes the same answers in
// plain C, which is what makes them answers rather than opinions.
#include "harness.h"

static uint64_t cell;
static uint32_t cell32;
static uint64_t pair_cell[2];

static void show(const char* name, uint64_t got, uint64_t left) {
    say(name);
    say(" ret=");
    hex64(got);
    say("     mem=");
    hex64(left);
}

#ifdef A64_NATIVE

// The reference semantics, spelled out. Every one of these is "return the old value,
// leave f(old, operand) in memory".
#define DEF_RMW(name, expr)                                                      \
    static void name(uint64_t init, uint64_t opnd) {                             \
        const uint64_t old = init, operand = opnd;                               \
        (void)operand;                                                           \
        show(#name, old, (expr));                                                \
    }
DEF_RMW(ldadd,  old + operand)
DEF_RMW(ldclr,  old & ~operand)
DEF_RMW(ldeor,  old ^ operand)
DEF_RMW(ldset,  old | operand)
DEF_RMW(ldsmax, (int64_t)old > (int64_t)operand ? old : operand)
DEF_RMW(ldsmin, (int64_t)old < (int64_t)operand ? old : operand)
DEF_RMW(ldumax, old > operand ? old : operand)
DEF_RMW(ldumin, old < operand ? old : operand)
DEF_RMW(swp,    operand)

static void cas(uint64_t init, uint64_t want, uint64_t val) {
    show("cas", init, init == want ? val : init);
}
static void cas32(uint32_t init, uint32_t want, uint32_t val) {
    show("cas32", init, init == want ? val : init);
}
static void casb(uint8_t init, uint8_t want, uint8_t val) {
    show("casb", init, (uint64_t)(uint8_t)(init == want ? val : init));
}
static void casp(uint64_t a, uint64_t b, uint64_t wa, uint64_t wb) {
    const int hit = (a == wa && b == wb);
    show("casp.lo", a, hit ? 0xAAAA : a);
    show("casp.hi", b, hit ? 0xBBBB : b);
}
static void ldxp_stxp(uint64_t a, uint64_t b) {
    show("ldxp.lo", a, 0x1111);
    show("ldxp.hi", b, 0x2222);
}
static void ldapr(uint64_t init) { show("ldapr", init, init); }

#else

#define LSE ".arch armv8.1-a\n\t"

// LD<op> Xs, Xt, [Xn]: Xs is the operand, Xt receives the old value.
#define DEF_RMW(name, mnemonic)                                                  \
    static void name(uint64_t init, uint64_t opnd) {                             \
        cell = init;                                                             \
        uint64_t old, *p = &cell, v = opnd;                                      \
        __asm__ volatile(LSE mnemonic " %2, %0, [%1]"                            \
                         : "=&r"(old) : "r"(p), "r"(v) : "memory");              \
        show(#name, old, cell);                                                  \
    }
DEF_RMW(ldadd,  "ldadd")
DEF_RMW(ldclr,  "ldclr")
DEF_RMW(ldeor,  "ldeor")
DEF_RMW(ldset,  "ldset")
DEF_RMW(ldsmax, "ldsmax")
DEF_RMW(ldsmin, "ldsmin")
DEF_RMW(ldumax, "ldumax")
DEF_RMW(ldumin, "ldumin")
DEF_RMW(swp,    "swp")

// CAS Xs, Xt, [Xn]: Xs is the comparand *and* the destination for the old value,
// which is the part that makes the register allocation fiddly and the semantics
// useful.
static void cas(uint64_t init, uint64_t want, uint64_t val) {
    cell = init;
    uint64_t s = want, *p = &cell, t = val;
    __asm__ volatile(LSE "cas %0, %2, [%1]" : "+r"(s) : "r"(p), "r"(t) : "memory");
    show("cas", s, cell);
}
static void cas32(uint32_t init, uint32_t want, uint32_t val) {
    cell32 = init;
    uint32_t s = want, t = val;
    uint32_t* p = &cell32;
    __asm__ volatile(LSE "cas %w0, %w2, [%1]" : "+r"(s) : "r"(p), "r"(t) : "memory");
    show("cas32", s, cell32);
}
static void casb(uint8_t init, uint8_t want, uint8_t val) {
    volatile uint8_t byte = init;
    uint32_t s = want, t = val;
    uint8_t* p = (uint8_t*)&byte;
    __asm__ volatile(LSE "casb %w0, %w2, [%1]" : "+r"(s) : "r"(p), "r"(t) : "memory");
    show("casb", s & 0xFF, byte);
}
// CASP needs even/odd register pairs, so the registers are named rather than left to
// the allocator.
static void casp(uint64_t a, uint64_t b, uint64_t wa, uint64_t wb) {
    pair_cell[0] = a;
    pair_cell[1] = b;
    register uint64_t s0 __asm__("x2") = wa, s1 __asm__("x3") = wb;
    register uint64_t t0 __asm__("x4") = 0xAAAA, t1 __asm__("x5") = 0xBBBB;
    uint64_t* p = pair_cell;
    __asm__ volatile(LSE "casp x2, x3, x4, x5, [%2]"
                     : "+r"(s0), "+r"(s1) : "r"(p), "r"(t0), "r"(t1) : "memory");
    show("casp.lo", s0, pair_cell[0]);
    show("casp.hi", s1, pair_cell[1]);
}
static void ldxp_stxp(uint64_t a, uint64_t b) {
    pair_cell[0] = a;
    pair_cell[1] = b;
    register uint64_t r0 __asm__("x6"), r1 __asm__("x7");
    register uint64_t w0 __asm__("x8") = 0x1111, w1 __asm__("x9") = 0x2222;
    uint64_t* p = pair_cell;
    uint64_t status;
    __asm__ volatile("ldxp x6, x7, [%3]\n\t"
                     "stxp %w0, x8, x9, [%3]"
                     : "=&r"(status), "=r"(r0), "=r"(r1)
                     : "r"(p), "r"(w0), "r"(w1) : "memory");
    show("ldxp.lo", r0, pair_cell[0]);
    show("ldxp.hi", r1, pair_cell[1]);
}
static void ldapr(uint64_t init) {
    cell = init;
    uint64_t v, *p = &cell;
    __asm__ volatile(".arch armv8.4-a\n\tldapr %0, [%1]" : "=r"(v) : "r"(p) : "memory");
    show("ldapr", v, cell);
}

#endif

TEST_MAIN {
    ldadd(0x1000, 0x234);
    ldclr(0xFFFF, 0x0F0F);
    ldeor(0xF0F0, 0xFFFF);
    ldset(0x1010, 0x0101);
    // Signed against unsigned on the same pair, so a max that compares the wrong way
    // shows up rather than agreeing by luck.
    ldsmax(0xFFFFFFFFFFFFFFFFull, 1);
    ldsmin(0xFFFFFFFFFFFFFFFFull, 1);
    ldumax(0xFFFFFFFFFFFFFFFFull, 1);
    ldumin(0xFFFFFFFFFFFFFFFFull, 1);
    swp(0xDEADBEEF, 0xCAFEF00D);

    cas(0x1234, 0x1234, 0x5678);          // matches: swaps
    cas(0x1234, 0x9999, 0x5678);          // does not match: leaves it alone
    cas32(0xAAAABBBB, 0xAAAABBBB, 0xCCCCDDDD);
    cas32(0xAAAABBBB, 0x0, 0xCCCCDDDD);
    casb(0x7F, 0x7F, 0x80);
    casb(0x7F, 0x00, 0x80);
    casp(0x1111, 0x2222, 0x1111, 0x2222);  // both halves match
    casp(0x1111, 0x2222, 0x1111, 0x9999);  // only one: must not store
    ldxp_stxp(0x3333, 0x4444);
    ldapr(0x55AA55AA);
    finish();
}
