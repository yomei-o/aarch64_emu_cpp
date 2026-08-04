// The SHA1 and SHA256 instructions.
//
// These arrived the way everything else here did — a real guest executed one and
// the decoder stopped. CPython's startup runs `sha1h s0, s0` and
// `pmull v0.1q, v0.1d, v0.1d` on a register against itself, which is a library
// asking "does this CPU have the crypto extension?" by trying it.
//
// That makes implementing them a decision, not a chore: answer the probe and the
// library will use the full instruction set for every hash it computes afterwards.
// So they are implemented exactly, straight from the ARM pseudocode, and checked
// against the host — `hashlib.sha256(...).hexdigest()` under the emulator has to
// equal the host's for the same input, which it does. A "nearly right" round
// function here would produce digests that are wrong and look completely normal.
#include "cpu.h"
#include <cstring>

namespace a64 {

namespace {

uint32_t rol32(uint32_t x, unsigned n) { n &= 31; return n ? ((x << n) | (x >> (32 - n))) : x; }
uint32_t ror32(uint32_t x, unsigned n) { n &= 31; return n ? ((x >> n) | (x << (32 - n))) : x; }

uint32_t choose(uint32_t x, uint32_t y, uint32_t z)   { return ((y ^ z) & x) ^ z; }
uint32_t parity(uint32_t x, uint32_t y, uint32_t z)   { return x ^ y ^ z; }
uint32_t majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | ((x | y) & z); }

uint32_t sigma0(uint32_t x) { return ror32(x, 2) ^ ror32(x, 13) ^ ror32(x, 22); }
uint32_t sigma1(uint32_t x) { return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25); }
uint32_t ssig0(uint32_t x)  { return ror32(x, 7) ^ ror32(x, 18) ^ (x >> 3); }
uint32_t ssig1(uint32_t x)  { return ror32(x, 17) ^ ror32(x, 19) ^ (x >> 10); }

// A V128 as four 32-bit words, word 0 being the low one.
uint32_t w(const V128& v, unsigned i) {
    return static_cast<uint32_t>((i < 2 ? v.lo : v.hi) >> ((i & 1) * 32));
}
void setw_(V128& v, unsigned i, uint32_t val) {
    uint64_t& half = (i < 2) ? v.lo : v.hi;
    const unsigned sh = (i & 1) * 32;
    half = (half & ~(0xFFFFFFFFull << sh)) | (static_cast<uint64_t>(val) << sh);
}
V128 make(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    V128 v{};
    setw_(v, 0, a); setw_(v, 1, b); setw_(v, 2, c); setw_(v, 3, d);
    return v;
}

}  // namespace

bool Cpu::exec_crypto(uint32_t insn) {
    const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;

    // ---- Cryptographic two-register SHA: 0101 1110 size 10100 opcode 10 Rn Rd --
    if ((insn & 0xFF3E0C00u) == 0x5E280800u) {
        const unsigned opcode = (insn >> 12) & 0x1F;
        if (opcode == 0) {                                        // SHA1H Sd, Sn
            vreg[rd] = {rol32(w(vreg[rn], 0), 30), 0};
            return true;
        }
        if (opcode == 1) {                                        // SHA1SU1 Vd.4S, Vn.4S
            const V128 d = vreg[rd], n = vreg[rn];
            uint32_t t[4];
            // T = Vd EOR (Vn logically shifted right by 32 across all 128 bits)
            for (unsigned i = 0; i < 4; ++i)
                t[i] = w(d, i) ^ (i < 3 ? w(n, i + 1) : 0u);
            V128 r = make(rol32(t[0], 1), rol32(t[1], 1), rol32(t[2], 1),
                          rol32(t[3], 1) ^ rol32(t[0], 2));
            vreg[rd] = r;
            return true;
        }
        if (opcode == 2) {                                        // SHA256SU0 Vd.4S, Vn.4S
            const V128 d = vreg[rd], n = vreg[rn];
            uint32_t T[4] = {w(d, 1), w(d, 2), w(d, 3), w(n, 0)};
            V128 r{};
            for (unsigned i = 0; i < 4; ++i) setw_(r, i, ssig0(T[i]) + w(d, i));
            vreg[rd] = r;
            return true;
        }
        return false;
    }

    // ---- Cryptographic three-register SHA: 0101 1110 size 0 Rm 0 opcode 00 Rn Rd
    if ((insn & 0xFF208C00u) == 0x5E000000u) {
        const unsigned opcode = (insn >> 12) & 7;
        V128 X = vreg[rd], Y = vreg[rn], W = vreg[rm];
        switch (opcode) {
            case 0: case 1: case 2: {                             // SHA1C / SHA1P / SHA1M
                uint32_t y = w(Y, 0);                             // Sn: only the low word
                for (unsigned e = 0; e < 4; ++e) {
                    uint32_t t;
                    if (opcode == 0)      t = choose(w(X, 1), w(X, 2), w(X, 3));
                    else if (opcode == 1) t = parity(w(X, 1), w(X, 2), w(X, 3));
                    else                  t = majority(w(X, 1), w(X, 2), w(X, 3));
                    y = y + rol32(w(X, 0), 5) + t + w(W, e);
                    setw_(X, 1, rol32(w(X, 1), 30));
                    // <Y,X> = ROL(Y:X, 32) over 160 bits: the top word of X becomes
                    // the new Y and the old Y drops into the bottom of X.
                    const uint32_t newy = w(X, 3);
                    X = make(y, w(X, 0), w(X, 1), w(X, 2));
                    y = newy;
                }
                vreg[rd] = X;
                return true;
            }
            case 3: {                                             // SHA1SU0 Vd,Vn,Vm
                const V128 d = vreg[rd];
                uint32_t r[4] = {w(Y, 0), w(Y, 1), w(d, 2), w(d, 3)};
                for (unsigned i = 0; i < 4; ++i) r[i] ^= w(d, i) ^ w(W, i);
                vreg[rd] = make(r[0], r[1], r[2], r[3]);
                return true;
            }
            case 4: case 5: {                                     // SHA256H / SHA256H2
                const bool part1 = (opcode == 4);
                V128 a = part1 ? X : Y, b = part1 ? Y : X;        // H2 swaps the roles
                if (!part1) { a = vreg[rn]; b = vreg[rd]; }
                V128 xx = part1 ? vreg[rd] : vreg[rn];
                V128 yy = part1 ? vreg[rn] : vreg[rd];
                for (unsigned e = 0; e < 4; ++e) {
                    const uint32_t chs = choose(w(yy, 0), w(yy, 1), w(yy, 2));
                    const uint32_t maj = majority(w(xx, 0), w(xx, 1), w(xx, 2));
                    const uint32_t t = w(yy, 3) + sigma1(w(yy, 0)) + chs + w(W, e);
                    setw_(xx, 3, t + w(xx, 3));
                    setw_(yy, 3, t + sigma0(w(xx, 0)) + maj);
                    // <Y,X> = ROL(Y:X, 32) over 256 bits.
                    const V128 nx = make(w(yy, 3), w(xx, 0), w(xx, 1), w(xx, 2));
                    const V128 ny = make(w(xx, 3), w(yy, 0), w(yy, 1), w(yy, 2));
                    xx = nx; yy = ny;
                }
                vreg[rd] = part1 ? xx : yy;
                return true;
            }
            case 6: {                                             // SHA256SU1 Vd,Vn,Vm
                const V128 d = vreg[rd], n = vreg[rn], m = vreg[rm];
                const uint32_t T0[4] = {w(n, 1), w(n, 2), w(n, 3), w(m, 0)};
                uint32_t r[4];
                uint32_t T1[2] = {w(m, 2), w(m, 3)};
                for (unsigned e = 0; e < 2; ++e) r[e] = ssig1(T1[e]) + w(d, e) + T0[e];
                const uint32_t T1b[2] = {r[0], r[1]};
                for (unsigned e = 2; e < 4; ++e) r[e] = ssig1(T1b[e - 2]) + w(d, e) + T0[e];
                vreg[rd] = make(r[0], r[1], r[2], r[3]);
                return true;
            }
            default: return false;
        }
    }
    return false;
}

}  // namespace a64
