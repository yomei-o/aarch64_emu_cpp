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
    finish();
}
