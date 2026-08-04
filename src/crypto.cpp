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

// ---- AES ------------------------------------------------------------------
//
// The S-box is *computed* from its definition rather than written out: the
// multiplicative inverse in GF(2^8) modulo x^8+x^4+x^3+x+1, then the affine map
// b = s ^ rol(s,1) ^ rol(s,2) ^ rol(s,3) ^ rol(s,4) ^ 0x63. Two hundred and fifty-six
// hex bytes copied by hand is exactly the kind of table that is wrong in one place and
// produces ciphertext that looks like ciphertext. Generated, it can also be checked
// against the four values everyone knows — S[0]=0x63, S[1]=0x7C, S[0x10]=0xCA,
// S[0xFF]=0x16 — and against the round trip inv[S[x]] == x for all 256.

uint8_t gmul(uint8_t a, uint8_t b) {          // GF(2^8) multiply, AES polynomial
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        const bool hi = (a & 0x80) != 0;
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1B;
        b = static_cast<uint8_t>(b >> 1);
    }
    return p;
}

struct AesTables {
    uint8_t sbox[256] = {0}, inv_sbox[256] = {0};
    AesTables() {
        uint8_t inverse[256] = {0};
        for (int x = 1; x < 256; ++x)
            for (int y = 1; y < 256; ++y)
                if (gmul(static_cast<uint8_t>(x), static_cast<uint8_t>(y)) == 1) {
                    inverse[x] = static_cast<uint8_t>(y);
                    break;
                }
        for (int x = 0; x < 256; ++x) {
            const uint8_t s = inverse[x];           // inverse[0] stays 0, as AES defines
            uint8_t b = s;
            for (int r = 1; r <= 4; ++r)
                b ^= static_cast<uint8_t>((s << r) | (s >> (8 - r)));
            sbox[x] = static_cast<uint8_t>(b ^ 0x63);
        }
        for (int x = 0; x < 256; ++x) inv_sbox[sbox[x]] = static_cast<uint8_t>(x);
    }
};
const AesTables& aes() { static const AesTables t; return t; }

// The state is 16 bytes, column-major: byte i is row i%4 of column i/4. ShiftRows
// rotates row r left by r columns, which as a byte permutation is this; the inverse
// rotates right.
constexpr uint8_t kShift[16]    = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
constexpr uint8_t kInvShift[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

void get_bytes(const V128& v, uint8_t* out) {
    for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(v.lo >> (i * 8));
    for (int i = 0; i < 8; ++i) out[8 + i] = static_cast<uint8_t>(v.hi >> (i * 8));
}
V128 put_bytes(const uint8_t* b) {
    V128 v{};
    for (int i = 0; i < 8; ++i) v.lo |= static_cast<uint64_t>(b[i]) << (i * 8);
    for (int i = 0; i < 8; ++i) v.hi |= static_cast<uint64_t>(b[8 + i]) << (i * 8);
    return v;
}

// MixColumns and its inverse, per column, with the standard coefficients.
void mix_columns(uint8_t* s, bool inverse) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* p = s + c * 4;
        const uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
        if (!inverse) {
            p[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            p[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            p[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            p[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        } else {
            p[0] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9);
            p[1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13);
            p[2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11);
            p[3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14);
        }
    }
}

}  // namespace

bool Cpu::exec_crypto(uint32_t insn) {
    const unsigned rm = (insn >> 16) & 0x1F, rn = (insn >> 5) & 0x1F, rd = insn & 0x1F;

    // ---- Cryptographic AES: 0100 1110 00 10100 opcode 10 Rn Rd ---------------
    //
    // Four instructions that are *fragments* of a round, which is why no AES library
    // could stand in for them: AESE is AddRoundKey + ShiftRows + SubBytes with the key
    // in Vd, AESMC is MixColumns alone, and the round is composed by the caller. Note
    // the order in the ARM pseudocode — the EOR happens first, and both AESE and AESD
    // read *and* write Vd.
    //
    // libcorecrypto's `ccaes_arm_encrypt_key256` is what asked, 178,729 instructions
    // into the macOS guest.
    if ((insn & 0xFF3E0C00u) == 0x4E280800u) {
        const unsigned opcode = (insn >> 12) & 0x1F;
        if (opcode < 4 || opcode > 7) return false;
        uint8_t st[16];
        if (opcode == 4 || opcode == 5) {                    // AESE / AESD
            uint8_t d[16], n[16];
            get_bytes(vreg[rd], d);
            get_bytes(vreg[rn], n);
            for (int i = 0; i < 16; ++i) d[i] = static_cast<uint8_t>(d[i] ^ n[i]);
            const uint8_t* perm = (opcode == 4) ? kShift : kInvShift;
            const uint8_t* box  = (opcode == 4) ? aes().sbox : aes().inv_sbox;
            for (int i = 0; i < 16; ++i) st[i] = box[d[perm[i]]];
        } else {                                             // AESMC / AESIMC
            get_bytes(vreg[rn], st);
            mix_columns(st, opcode == 7);
        }
        vreg[rd] = put_bytes(st);
        return true;
    }

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
