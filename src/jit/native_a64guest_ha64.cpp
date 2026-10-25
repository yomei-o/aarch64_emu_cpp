// The AArch64 guest's ops for the AArch64 native backend: the flag-setting arithmetic (the
// host's flags are the guest's, read back into the guest's N, Z, C, V bytes), conditional
// select and the conditional branch.  Anything else runs through its threaded handler.
#include "native_cond_a64.h"

namespace jit {

#ifdef JIT_NATIVE_A64

using namespace a64;

namespace {

constexpr uint32_t kBICS = 0xEA200000u;

}  // namespace

int guest_native_cells(const Op& o) {
    switch (o.kind) {
        case OpKind::A64Jcc: return 2;
        default: return 0;
    }
}

bool guest_native_emit(NativeGenA& g, const Op& o) {
    Asm& a = g.a;
    const GuestSlots& s = g.s;
    switch (o.kind) {
    case OpKind::A64BinS: case OpKind::A64BinSI: {
        const BinOp op = static_cast<BinOp>(o.cc);
        if (op != BinOp::Add && op != BinOp::Sub && op != BinOp::And && op != BinOp::Andn) return false;
        if (o.sz != 4 && o.sz != 8) return false;
        const bool x = o.sz == 8;
        const bool eager = (o.flags & kFlagEager) != 0;
        g.ld_sz(0, o.a, o.sz);
        if (o.kind == OpKind::A64BinSI) a.mov_imm(1, x ? static_cast<uint64_t>(o.imm) : static_cast<uint32_t>(o.imm));
        else g.ld_sz(1, o.b, o.sz);
        switch (op) {
            case BinOp::Add: a.alu(eager ? ADDS : ADD, x, 0, 0, 1); break;
            case BinOp::Sub: a.alu(eager ? SUBS : SUB, x, 0, 0, 1); break;
            case BinOp::And: a.alu(eager ? ANDS : AND, x, 0, 0, 1); break;
            default: a.alu(eager ? kBICS : BIC, x, 0, 0, 1); break;
        }
        if (eager) {   // the host N, Z, C, V are the guest ones (C is no-borrow after a subtraction, clear after a logic op)
            a.cset(false, 2, MI); a.strb(2, ra::ENV, s.fl_n);
            a.cset(false, 2, EQ); a.strb(2, ra::ENV, s.fl_z);
            a.cset(false, 2, HS); a.strb(2, ra::ENV, s.fl_c);
            a.cset(false, 2, VS); a.strb(2, ra::ENV, s.fl_v);
        }
        g.st(o.d, 0);
        return true;
    }
    case OpKind::A64Csel: {
        const bool x = o.sz == 8;
        g.ld_sz(0, o.a, o.sz);
        g.ld_sz(1, o.b, o.sz);
        switch (o.imm) {
            case 1: a.add_imm(x, 1, 1, 1); break;                   // CSINC
            case 2: a.alu(ORN, x, 1, XZR, 1); break;                // CSINV
            case 3: a.alu(SUB, x, 1, XZR, 1); break;                // CSNEG
            default: break;
        }
        const int hcc = arm_cond(g, o.cc);
        if (hcc >= 0) a.csel(x, 0, 0, 1, hcc);                      // the condition holds: keep a
        if (!x) a.mov_rr32(0, 0);
        g.st(o.d, 0);
        return true;
    }
    case OpKind::A64Jcc: {
        const int hcc = arm_cond(g, o.cc);
        if (hcc < 0) { g.exit_static(static_cast<uint64_t>(o.imm), g.insns); g.next_cell(); return true; }
        Label taken;
        a.b_cond(hcc, taken);
        g.exit_static(static_cast<uint64_t>(o.imm2), g.insns);
        a.bind(taken);
        g.exit_static(static_cast<uint64_t>(o.imm), g.insns);
        return true;
    }
    default:
        return false;
    }
}

#endif  // JIT_NATIVE_A64

}  // namespace jit
