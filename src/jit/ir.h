// A small register-memory IR for dynamic translation.
//
// A frontend (one per guest ISA) turns a straight-line run of guest instructions
// into a vector of `Op`; a backend (the threaded handlers in backend_threaded.cpp,
// WebAssembly built at run time in backend_wasm.cpp, native code later) turns that
// into something runnable.
//
// Values live in *slots*: byte offsets from the base of the guest state
// (`env`).  Guest registers are slots, and so are the temporaries - a block runs
// with its temporaries in the same memory as the registers, so every operand is
// just an offset and there is no register allocation to do.  A backend that
// wants machine registers (a native emitter) caches slots in them; the IR does
// not care.  A useful consequence: because nothing is cached outside `env`, a
// block can be left at any op boundary and the interpreter picks up from the
// state in memory.
//
// All slot values are 64 bits.  Operations narrower than that say so in `sz`
// and leave the result zero extended, which is what makes a 32-bit register
// write come out right for free.
//
// The ops fall in three groups.  The *generic* ones (moves, integer arithmetic,
// address arithmetic, extensions, loads and stores, compare-and-branch, exits and
// the interpreter) mean the same for every guest.  The rest belong to one ISA - x86
// flags and stack, A64 flags and bitfields - and are implemented by that guest's
// own files; they share the enum so that the backends can treat all ops alike.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace jit {

// Op kinds, in one list so that the enum and the names below cannot drift apart.
//
// Generic:
//   Nop
//   Mov: d = a.  MovI: d = imm.
//   Add AddI Sub SubI And AndI Or OrI Xor XorI: 64-bit d = a OP b (or imm).
//   Bin / BinI: d = a OP b (b a slot, or imm), cc = BinOp, the result truncated to
//     sz bytes (4 or 8) and zero extended.  Shift counts are b & (8*sz - 1).
//   Un: d = OP(a), cc = UnOp, at sz bytes.
//   Lea: d = (a + (c << cc) + imm), truncated to sz bytes (4 or 8).
//   Ext: d = extend(a) from sz bytes to cc bytes (4 or 8); kFlagSigned sign extends.
//   Put: sub-register write: sz=1 low byte of a replaced by b; sz=2 low word;
//     sz=0x81 bits 8..15 (AH, CH, DH, BH).  GetH: d = (a >> 8) & 0xFF.
//   Ld / LdS: d = load(a + (c << cc) + imm), sz bytes, zero / sign extended (LdS
//     keeps the destination width, 4 or 8, in imm2).  St: store b likewise.
//   Sel: d = slot[c] ? a : b.
//   Exit: rip = imm.  ExitInd: rip = slot a.
//   JccGen / JccGenI: rip = cond(a, b | d-as-imm32) ? imm : imm2, cc = Cond, sz
//     bytes compared.
//   Interp: run the guest instruction at (block start + pc) with the interpreter;
//     imm2 = where the block expects to be afterwards, anything else ends it.
//   ChkFlush: after an instruction that stored to memory: leave if translated code
//     was just invalidated; rip = imm.
// A store carrying kFlagChk does that check itself, with rip = imm2.
//
// x86 (ops_x86.cpp): SetFl JccFl Alu AluI IncDec ShlI ShrI SarI Shift ShiftI
//   ShiftSlow Imul ImulI Group3 CcSet CcSetI CcMat CcClear JccCmp JccCmpI Push
//   PushI Pop Ret Call.
// A64 (ops_a64.cpp):
//   A64BinS / A64BinSI: Bin that also sets NZCV (cc: Add, Sub, And, Andn).
//   A64Csel: d = cond(cc) ? a : f(b); imm = 0 csel, 1 csinc, 2 csinv, 3 csneg.
//   A64Jcc: B.cond.  A64Ccmp / A64CcmpI: conditional compare; imm2 is the NZCV to
//     take when the condition fails, imm = 1 for CCMN; the immediate form keeps its
//     operand in d.
//   A64Sbfm / A64Bfm / A64Ubfm: the bitfield moves: imm = wmask, imm2 = tmask,
//     c = immr, cc = imms.
#define JIT_OP_KINDS(X) \
    X(Nop) X(Mov) X(MovI) X(Add) X(AddI) X(Sub) X(SubI) X(And) X(AndI) X(Or) X(OrI) X(Xor) X(XorI) \
    X(Bin) X(BinI) X(Un) X(Lea) X(Ext) X(Put) X(GetH) X(Ld) X(LdS) X(St) X(Sel) \
    X(Exit) X(ExitInd) X(JccGen) X(JccGenI) X(Interp) X(ChkFlush) \
    X(SetFl) X(JccFl) X(Alu) X(AluI) X(IncDec) X(ShlI) X(ShrI) X(SarI) X(Shift) X(ShiftI) X(ShiftSlow) \
    X(Imul) X(ImulI) X(Group3) X(CcSet) X(CcSetI) X(CcMat) X(CcClear) X(JccCmp) X(JccCmpI) \
    X(Push) X(PushI) X(Pop) X(Ret) X(Call) \
    X(A64BinS) X(A64BinSI) X(A64Csel) X(A64Jcc) X(A64Ccmp) X(A64CcmpI) X(A64Sbfm) X(A64Bfm) X(A64Ubfm)

enum class OpKind : uint8_t {
#define JIT_X(n) n,
    JIT_OP_KINDS(JIT_X)
#undef JIT_X
    kCount
};

inline const char* op_name(OpKind k) {
    static const char* const names[] = {
#define JIT_X(n) #n,
        JIT_OP_KINDS(JIT_X)
#undef JIT_X
    };
    return static_cast<size_t>(k) < sizeof names / sizeof names[0] ? names[static_cast<size_t>(k)] : "?";
}

constexpr size_t kOpKinds = static_cast<size_t>(OpKind::kCount);

enum class BinOp : uint8_t { Add, Sub, And, Or, Xor, Andn, Orn, Eon, Mul, Shl, Shr, Sar, Ror, UDiv0, SDiv0 };
enum class UnOp : uint8_t { Clz, Rbit, Rev, Rev16, Rev32 };
enum class Cond : uint8_t { Eq, Ne, Ltu, Geu, Leu, Gtu, Lts, Ges, Les, Gts, Tst, Ntst };

struct Op {
    OpKind kind = OpKind::Nop;
    uint8_t sz = 8;
    uint8_t cc = 0;
    uint8_t flags = 0;
    uint32_t pc = 0;        // offset of the guest instruction from the block start
    uint16_t ni = 0;        // natively translated instructions finished once this op is done (an
                            // Interp op does not count itself: the interpreter does)
    int32_t d = 0, a = 0, b = 0, c = 0;
    int64_t imm = 0, imm2 = 0;
};

enum : uint8_t {
    kFlagEager = 1,   // compute the guest flags too
    kFlagA32 = 2,     // addresses wrap at 32 bits
    kFlagSigned = 4,  // Ext: sign extend
    kFlagMem = 8,     // Group3: the operand is in memory
    kFlagRex = 16,    // Group3: a REX prefix was present (byte register numbering)
    kFlagChk = 32,    // a store: check for invalidated code afterwards; next pc in imm2
};

struct IrBlock {
    uint64_t start = 0;
    uint32_t guest_bytes = 0;
    uint32_t insns = 0;      // guest instructions run natively (not Interp)
    bool effects = false;    // an interpreted instruction has effects beyond CPU state and memory
    std::vector<Op> ops;
};

}  // namespace jit
