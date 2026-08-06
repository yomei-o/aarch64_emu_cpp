// Pointer authentication (ARMv8.3, and what every arm64e binary uses).
//
// Apple's system libraries are arm64e, so libSystem is full of `paciasp` on entry
// and `retaa` on return. The emulator implements PAC as the identity — signing
// leaves the pointer alone, authenticating accepts it — which is precisely what an
// ARMv8.3 CPU does when pointer authentication is *disabled*.
//
// What can be tested against a host that has no PAC at all is the property that
// holds either way: **a sign followed by the matching authenticate returns the
// original pointer**, and stripping a signed pointer returns the original too.
// Those are true on real hardware with live keys and true here, so the host can
// predict them, and a decoder that mistook `pacia` for something else would break
// them immediately. (It did: the Rm field of that group is really `opcode2`, and
// nothing looked at it, so `pacia x0, x1` decoded as RBIT and reversed the bits.)
#include "harness.h"

#ifdef A64_NATIVE

#define ROUNDTRIP_IB(v, m) (v)
#define ROUNDTRIP_IA(v, m) (v)
#define ROUNDTRIP_DA(v, m) (v)
#define STRIP_I(v, m)      (v)
#define ROUNDTRIP_ZA(v)    (v)
static uint64_t call_retaa(uint64_t v) { return v + 1; }
#define LDRAA_AT(base, off)  ((base)[(off) / 8])
#define LDRAB_AT(base, off)  ((base)[(off) / 8])
#define LDRAA_WB(base, off)  ((base) += (off) / 8, (base)[0])

#else

// The PAC instructions are an ARMv8.3 extension, and neither the plain
// aarch64-linux-gnu nor the arm64-apple-macos target enables it by default. `.arch`
// in front of each block asks the assembler for it without changing how the rest of
// the file is compiled.
#define PAUTH ".arch armv8.3-a\n\t"

// Sign with one key, authenticate with the same key: the pointer must come back.
#define ROUNDTRIP_IA(v, m) ({ uint64_t p_ = (v), m_ = (m); \
    __asm__(PAUTH "pacia %0, %1\n\tautia %0, %1" : "+r"(p_) : "r"(m_)); p_; })
#define ROUNDTRIP_IB(v, m) ({ uint64_t p_ = (v), m_ = (m); \
    __asm__(PAUTH "pacib %0, %1\n\tautib %0, %1" : "+r"(p_) : "r"(m_)); p_; })
#define ROUNDTRIP_DA(v, m) ({ uint64_t p_ = (v), m_ = (m); \
    __asm__(PAUTH "pacda %0, %1\n\tautda %0, %1" : "+r"(p_) : "r"(m_)); p_; })
// Sign, then *strip*: XPACI discards the signature rather than checking it, so this
// must give the original back without ever authenticating.
#define STRIP_I(v, m) ({ uint64_t p_ = (v), m_ = (m); \
    __asm__(PAUTH "pacia %0, %1\n\txpaci %0" : "+r"(p_) : "r"(m_)); p_; })
// The zero-modifier forms, which is what a compiler emits for a plain code pointer.
#define ROUNDTRIP_ZA(v) ({ uint64_t p_ = (v); \
    __asm__(PAUTH "paciza %0\n\tautiza %0" : "+r"(p_)); p_; })

// The shape every arm64e function has: sign the return address into the frame on
// entry, and return through it with RETAA. If RETAA read its Rn field instead of
// X30 — the encoding puts 11111 there — this would branch to zero.
__asm__(
    ".arch armv8.3-a\n"
    ".text\n"
    ".globl call_retaa_asm\n"
    "call_retaa_asm:\n"
    "  paciasp\n"
    "  add x0, x0, #1\n"
    "  retaa\n");
// The explicit asm label matters: Mach-O prefixes C symbols with an underscore, so
// without it the reference is to `_call_retaa_asm` and the .globl above defines
// `call_retaa_asm`. Naming it verbatim makes one declaration work for both formats.
extern uint64_t call_retaa_asm(uint64_t) __asm__("call_retaa_asm");
static uint64_t call_retaa(uint64_t v) { return call_retaa_asm(v); }

// LDRAA/LDRAB: load, authenticating the address in the base register first. The
// offset is what makes them worth a test of their own -- **ten bits, signed, and
// scaled by eight**, where every neighbouring encoding takes an unscaled nine. An
// emulator that misses these does not fault: bit 21 is set and bits 11:10 are 01 or
// 11, which the generic decode reads as an ordinary pre- or post-indexed LDR, and
// it quietly loads from an eighth of the intended offset. That is how it went
// unnoticed here until libc++abi fetched a personality routine through one, got the
// adjacent field, and branched into the ASCII of "CLNGC++".
//
// So the offsets below are deliberately not zero and not one slot: only a decode
// that both scales and sign-extends gets all four right.
#define LDRAA_AT(base, off) ({ uint64_t r_; const uint64_t* b_ = (base); \
    __asm__(PAUTH "ldraa %0, [%1, #" #off "]" : "=r"(r_) : "r"(b_) : "memory"); r_; })
#define LDRAB_AT(base, off) ({ uint64_t r_; const uint64_t* b_ = (base); \
    __asm__(PAUTH "ldrab %0, [%1, #" #off "]" : "=r"(r_) : "r"(b_) : "memory"); r_; })
// The writeback form, which is the one libc++abi uses: the base must end up at the
// address that was loaded from, not where it started.
#define LDRAA_WB(base, off) ({ uint64_t r_; \
    __asm__(PAUTH "ldraa %0, [%1, #" #off "]!" : "=r"(r_), "+r"(base) :: "memory"); r_; })

#endif

TEST_MAIN {
    const uint64_t p = 0x0000000123456789ull, m = 0x00000000DEADBEEFull;
    say("ia: ");
    hex64(ROUNDTRIP_IA(p, m));
    say("ib: ");
    hex64(ROUNDTRIP_IB(p, m));
    say("da: ");
    hex64(ROUNDTRIP_DA(p, m));
    say("strip: ");
    hex64(STRIP_I(p, m));
    say("za: ");
    hex64(ROUNDTRIP_ZA(p));
    say("retaa: ");
    hex64(call_retaa(41));

    // Eight slots, each holding its own index in the high nibble so a load from the
    // wrong one is obvious rather than plausible.
    static const uint64_t slots[8] = {
        0xA000000000000000ull, 0xA111111111111111ull, 0xA222222222222222ull,
        0xA333333333333333ull, 0xA444444444444444ull, 0xA555555555555555ull,
        0xA666666666666666ull, 0xA777777777777777ull,
    };
    const uint64_t* base = slots;
    say("ldraa +32: ");
    hex64(LDRAA_AT(base, 32));                     // slots[4]
    say("ldrab +56: ");
    hex64(LDRAB_AT(base, 56));                     // slots[7]
    // Negative, from the far end: the sign bit is the tenth, not the ninth.
    const uint64_t* end = slots + 7;
    say("ldraa -48: ");
    hex64(LDRAA_AT(end, -48));                     // slots[1]
    // Writeback: the value *and* where the base was left.
    const uint64_t* wb = slots;
    say("ldraa +24!: ");
    hex64(LDRAA_WB(wb, 24));                       // slots[3]
    say("wb base: ");
    hex64((uint64_t)(wb - slots));                 // must be 3
    finish();
}
