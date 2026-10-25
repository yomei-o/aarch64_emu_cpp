// The AArch64 guest's ops for the x86-64 native backend: the flag-setting arithmetic (the
// host's flags are read back one by one into the guest's N, Z, C, V bytes), conditional
// select and the conditional branch.  Anything else runs through its threaded handler.
#include "native_cond_x64.h"

namespace jit {

#ifdef JIT_HAVE_NATIVE

using namespace x64;


int guest_native_cells(const Op& o) {
    switch (o.kind) {
        case OpKind::A64Jcc: return 2;
        default: return 0;
    }
}

bool guest_native_emit(NativeGen& g, const Op& o) {
    Asm& a = g.a;
    const GuestSlots& s = g.s;
    switch (o.kind) {
    case OpKind::A64BinS: case OpKind::A64BinSI: {
        const BinOp op = static_cast<BinOp>(o.cc);
        if (op != BinOp::Add && op != BinOp::Sub && op != BinOp::And && op != BinOp::Andn) return false;
        if (o.sz != 4 && o.sz != 8) return false;
        const bool w = o.sz == 8;
        const bool eager = (o.flags & kFlagEager) != 0;
        g.ld_sz(RAX, o.a, o.sz);
        if (o.kind == OpKind::A64BinSI) a.movi(RCX, w ? o.imm : static_cast<int64_t>(static_cast<uint32_t>(o.imm)));
        else g.ld_sz(RCX, o.b, o.sz);
        switch (op) {
            case BinOp::Add: a.alu_rr(ADD, w, RAX, RCX); break;
            case BinOp::Sub: a.alu_rr(SUB, w, RAX, RCX); break;
            case BinOp::And: a.alu_rr(AND, w, RAX, RCX); break;
            default: a.not_r(w, RCX); a.alu_rr(AND, w, RAX, RCX); break;
        }
        if (eager) {
            a.setcc(S, RDX);  a.store8(RBX, s.fl_n, RDX);
            a.setcc(E, RDX);  a.store8(RBX, s.fl_z, RDX);
            if (op == BinOp::Add) { a.setcc(B, RDX); a.store8(RBX, s.fl_c, RDX); a.setcc(O, RDX); a.store8(RBX, s.fl_v, RDX); }
            else if (op == BinOp::Sub) { a.setcc(AE, RDX); a.store8(RBX, s.fl_c, RDX); a.setcc(O, RDX); a.store8(RBX, s.fl_v, RDX); }
            else { a.movi(RDX, 0); a.store8(RBX, s.fl_c, RDX); a.store8(RBX, s.fl_v, RDX); }
        }
        g.st(o.d, RAX);
        return true;
    }
    case OpKind::A64Csel: {
        const bool w = o.sz == 8;
        g.ld_sz(RAX, o.a, o.sz);
        g.ld_sz(RCX, o.b, o.sz);
        switch (o.imm) {
            case 1: a.alu_ri(ADD, w, RCX, 1); break;     // CSINC
            case 2: a.not_r(w, RCX); break;              // CSINV
            case 3: a.neg_r(w, RCX); break;              // CSNEG
            default: break;
        }
        const int hcc = arm_cond(g, o.cc);
        if (hcc >= 0) a.cmov(hcc ^ 1, w, RAX, RCX);      // the condition failed: take the alternative
        if (!w) a.mov_rr32(RAX, RAX);
        g.st(o.d, RAX);
        return true;
    }
    case OpKind::A64Jcc: {
        const int hcc = arm_cond(g, o.cc);
        if (hcc < 0) { g.exit_static(static_cast<uint64_t>(o.imm), g.insns); g.next_cell(); return true; }
        Label taken;
        a.jcc(hcc, taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), g.insns);
        a.bind(taken);
        g.exit_static(static_cast<uint64_t>(o.imm), g.insns);
        return true;
    }
    default:
        return false;
    }
}

#endif  // JIT_HAVE_NATIVE

}  // namespace jit
