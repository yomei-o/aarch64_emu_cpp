// The native backend for AArch64 hosts: the same idea as backend_native.cpp (hot blocks
// become machine code that works on the guest register file in memory, static exits jump
// straight to the next block's code, ops it does not generate itself run through their
// threaded handlers), with AArch64 instructions.
//
// Registers while generated code runs: x19 = the guest register file, x20 = the translator
// context, x21 = instructions finished, x22 = the budget, x23 / x24 = the guest's page caches.
#include "engine.h"
#include "native_host.h"

#ifdef JIT_NATIVE_A64

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "native_gen_a64.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif
#endif

namespace jit {

using namespace a64;

struct Engine::NativeState {
    uint8_t* base = nullptr;
    size_t cap = 0, used = 0;
    uint64_t (*entry)(uint8_t*, Ctx*, const uint8_t*, uint64_t) = nullptr;
    const uint8_t* leave = nullptr;
};

namespace {

// ---- helpers the generated code calls (the same as the x86-64 backend's) -------------------

void note_fault(Ctx* c, uint64_t rip) {
    c->eng->nexc_ = std::current_exception();
    c->nfault = 1;
    c->fault_rip = rip;
}

// ---- executable memory --------------------------------------------------------------------

uint8_t* alloc_exec(size_t n) {
#ifdef _WIN32
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
#elif defined(__APPLE__)
    void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    return p == MAP_FAILED ? nullptr : static_cast<uint8_t*>(p);
#else
    void* p = mmap(nullptr, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? nullptr : static_cast<uint8_t*>(p);
#endif
}

void free_exec(uint8_t* p, size_t n) {
#ifdef _WIN32
    (void)n;
    VirtualFree(p, 0, MEM_RELEASE);
#else
    munmap(p, n);
#endif
}

// Code was just written at [p, p + n): make the instruction stream see it.
void sync_code(uint8_t* p, size_t n) {
#ifdef _WIN32
    FlushInstructionCache(GetCurrentProcess(), p, n);
#elif defined(__APPLE__)
    sys_icache_invalidate(p, n);
#else
    __builtin___clear_cache(reinterpret_cast<char*>(p), reinterpret_cast<char*>(p + n));
#endif
}

struct WriteScope {   // Apple silicon: JIT memory is writable or executable per thread, not both
    WriteScope() {
#ifdef __APPLE__
        pthread_jit_write_protect_np(0);
#endif
    }
    ~WriteScope() {
#ifdef __APPLE__
        pthread_jit_write_protect_np(1);
#endif
    }
};

// The size of the code arena: 64 MiB, or JIT_NATIVE_ARENA_KB (for testing the path that starts
// over when the arena fills up).
size_t arena_size() {
    if (const char* v = std::getenv(JIT_ENV("JIT_NATIVE_ARENA_KB"))) {
        const size_t kb = static_cast<size_t>(std::strtoull(v, nullptr, 10));
        if (kb >= 2048) return kb << 10;
    }
    return size_t(64) << 20;
}

}  // namespace

// meta = guest address of the instruction << 8 | access size
uint64_t native_read_helper(Ctx* c, uint64_t addr, uint64_t meta) {
    try {
        switch (meta & 0xFF) {
            case 1: return Glue::rd8(*c->mem, addr);
            case 2: return Glue::rd16(*c->mem, addr);
            case 4: return Glue::rd32(*c->mem, addr);
            default: return Glue::rd64(*c->mem, addr);
        }
    } catch (...) {
        note_fault(c, meta >> 8);
        return 0;
    }
}

void native_write_helper(Ctx* c, uint64_t addr, uint64_t val, uint64_t meta) {
    try {
        switch (meta & 0xFF) {
            case 1: Glue::wr8(*c->mem, addr, static_cast<uint8_t>(val)); break;
            case 2: Glue::wr16(*c->mem, addr, static_cast<uint16_t>(val)); break;
            case 4: Glue::wr32(*c->mem, addr, static_cast<uint32_t>(val)); break;
            default: Glue::wr64(*c->mem, addr, val); break;
        }
    } catch (...) {
        note_fault(c, meta >> 8);
    }
}

// Runs one op through its threaded handler.  1: the block goes on; 0: the op ended it;
// 2: it raised an exception.
int native_generic_helper(Ctx* c, const Uop* u, uint64_t start) {
    try {
        return jit_generic(c, u);
    } catch (...) {
        note_fault(c, c->in_interp ? 0 : start + u->pc);
        return 2;
    }
}

// Compares the offset in the page (x3) with the last offset an access of `size` bytes fits at.
void cmp_page_limit(Asm& a, int size) {
    const uint32_t limit = (1u << kTlbPageBits) - static_cast<uint32_t>(size);
    if (limit < 4096) {
        a.cmp_imm(true, 3, limit);
    } else {
        a.mov_imm(16, limit);
        a.cmp(true, 3, 16);
    }
}

void NativeGenA::mem_read(int size, uint64_t rip) {
    const uint64_t meta = (rip << 8) | static_cast<uint64_t>(size);
    auto slow_call = [this, meta] {
        a.mov_rr(1, 0);
        a.mov_rr(0, ra::CTX);
        a.mov_imm(2, meta);
        call(reinterpret_cast<const void*>(&native_read_helper));
        check_fault();
    };
    if (!inline_tlb) { slow_call(); return; }
    labels.emplace_back();
    Label* slow = &labels.back();
    labels.emplace_back();
    Label* done = &labels.back();
    a.lsr_imm(true, 1, 0, kTlbPageBits);                   // x1 = page
    a.ubfm(true, 2, 1, 0, kTlbBits - 1);                   // x2 = page & mask
    a.alu(a64::ADD, true, 2, ra::TLBR, 2, LSL, 4);         // x2 = the cache entry
    a.ldr64(3, 2, 0);
    a.cmp(true, 1, 3);
    a.b_cond(NE, *slow);
    a.ubfm(true, 3, 0, 0, kTlbPageBits - 1);               // x3 = offset in the page
    cmp_page_limit(a, size);
    a.b_cond(HI, *slow);                                   // straddles the page
    a.ldr64(2, 2, 8);                                      // x2 = host base
    switch (size) {
        case 1: a.ldrb_rr(0, 2, 3); break;
        case 2: a.ldrh_rr(0, 2, 3); break;
        case 4: a.ldr32_rr(0, 2, 3); break;
        default: a.ldr64_rr(0, 2, 3); break;
    }
    a.bind(*done);
    stubs.push_back([this, slow, done, slow_call] {
        a.bind(*slow);
        slow_call();
        a.b(*done);
    });
}

void NativeGenA::mem_write(int size, uint64_t rip) {
    const uint64_t meta = (rip << 8) | static_cast<uint64_t>(size);
    auto slow_call = [this, meta] {
        a.mov_rr(1, 0);
        a.mov_rr(0, ra::CTX);
        a.mov_rr(2, 4);
        a.mov_imm(3, meta);
        call(reinterpret_cast<const void*>(&native_write_helper));
        check_fault();
    };
    if (!inline_tlb) { slow_call(); return; }
    labels.emplace_back();
    Label* slow = &labels.back();
    labels.emplace_back();
    Label* done = &labels.back();
    a.lsr_imm(true, 1, 0, kTlbPageBits);
    a.ubfm(true, 2, 1, 0, kTlbBits - 1);
    a.alu(a64::ADD, true, 2, ra::TLBW, 2, LSL, 4);
    a.ldr64(3, 2, 0);
    a.cmp(true, 1, 3);
    a.b_cond(NE, *slow);
    a.ubfm(true, 3, 0, 0, kTlbPageBits - 1);
    cmp_page_limit(a, size);
    a.b_cond(HI, *slow);
    a.ldr64(2, 2, 8);
    switch (size) {
        case 1: a.strb_rr(4, 2, 3); break;
        case 2: a.strh_rr(4, 2, 3); break;
        case 4: a.str32_rr(4, 2, 3); break;
        default: a.str64_rr(4, 2, 3); break;
    }
    a.bind(*done);
    stubs.push_back([this, slow, done, slow_call] {
        a.bind(*slow);
        slow_call();
        a.b(*done);
    });
}

bool Engine::native_init() {
    if (nat_) return true;
    uint8_t* mem_base = alloc_exec(arena_size());
    if (!mem_base) return false;
    nat_ = new NativeState;
    nat_->base = mem_base;
    nat_->cap = arena_size();
    Asm a(mem_base);
    a.stp_pre(FP, LR, SP, -96);
    a.stp(19, 20, SP, 16);
    a.stp(21, 22, SP, 32);
    a.stp(23, 24, SP, 48);
    a.stp(25, 26, SP, 64);
    a.stp(27, 28, SP, 80);
    a.mov_rr(ra::ENV, 0);
    a.mov_rr(ra::CTX, 1);
    a.mov_rr(16, 2);
    a.mov_rr(ra::LIMIT, 3);
    a.mov_imm(ra::COUNT, 0);
    a.mov_imm(ra::TLBR, reinterpret_cast<uintptr_t>(Glue::tlb_read_base(mem)));
    a.mov_imm(ra::TLBW, reinterpret_cast<uintptr_t>(Glue::tlb_write_base(mem)));
    a.br(16);
    // leave:
    const size_t leave_at = a.bytes();
    a.mov_rr(0, ra::COUNT);
    a.ldp(19, 20, SP, 16);
    a.ldp(21, 22, SP, 32);
    a.ldp(23, 24, SP, 48);
    a.ldp(25, 26, SP, 64);
    a.ldp(27, 28, SP, 80);
    a.ldp_post(FP, LR, SP, 96);
    a.ret();
    {
        WriteScope ws;
        std::memcpy(mem_base, a.w.data(), a.bytes());
    }
    sync_code(mem_base, a.bytes());
    nat_->entry = reinterpret_cast<uint64_t (*)(uint8_t*, Ctx*, const uint8_t*, uint64_t)>(mem_base);
    nat_->leave = mem_base + leave_at;
    nat_->used = (a.bytes() + 15) & ~size_t(15);
    return true;
}

void Engine::native_shutdown() {
    if (!nat_) return;
    free_exec(nat_->base, nat_->cap);
    delete nat_;
    nat_ = nullptr;
}

void Engine::native_reset() {
    if (!nat_) return;
    ++native_gen;
    unlink_all();
    for (auto& b : all_) {
        b->nat = nullptr;
        b->nat_failed = false;
        b->ncells.reset();
    }
    nat_->used = static_cast<size_t>((nat_->leave - nat_->base) + 64);
    nat_->used = (nat_->used + 15) & ~size_t(15);
}

// Runs the chain of machine code starting at b.  False: a helper caught an exception.
bool Engine::native_run(Block* b, Ctx& ctx, uint64_t limit, uint32_t* done) {
    ctx.nfault = 0;
    if (limit > (uint64_t(1) << 62)) limit = uint64_t(1) << 62;
    *done = static_cast<uint32_t>(nat_->entry(ctx.env, &ctx, b->nat, limit));
    return ctx.nfault == 0;
}

namespace {

inline int cc_of(Cond c) {
    switch (c) {
        case Cond::Eq: return EQ;
        case Cond::Ne: return NE;
        case Cond::Ltu: return LO;
        case Cond::Geu: return HS;
        case Cond::Leu: return LS;
        case Cond::Gtu: return HI;
        case Cond::Lts: return LT;
        case Cond::Ges: return GE;
        case Cond::Les: return LE;
        case Cond::Gts: return GT;
        case Cond::Tst: return NE;
        default: return EQ;   // Ntst
    }
}

inline bool fits_imm12(int64_t v) { return v >= 0 && v < 4096; }

// x0 = the effective address of a load or store
void emit_address(NativeGenA& g, const Op& o) {
    g.ld(0, o.a);
    if (o.c != g.s.zero) {
        g.ld(1, o.c);
        g.a.alu(a64::ADD, true, 0, 0, 1, LSL, o.cc);
    }
    if (o.imm) {
        if (fits_imm12(o.imm)) g.a.add_imm(true, 0, 0, static_cast<uint32_t>(o.imm));
        else if (fits_imm12(-o.imm)) g.a.sub_imm(true, 0, 0, static_cast<uint32_t>(-o.imm));
        else { g.a.mov_imm(1, static_cast<uint64_t>(o.imm)); g.a.alu(a64::ADD, true, 0, 0, 1); }
    }
    if (o.flags & kFlagA32) g.a.mov_rr32(0, 0);
}

// Run the op through its threaded handler.
void emit_generic(NativeGenA& g) {
    g.fallback();
    g.labels.emplace_back();
    Label* l = &g.labels.back();
    g.a.cmp_imm(false, 0, 1);
    g.a.b_cond(NE, *l);
    g.stubs.push_back([&g, l] {
        g.a.bind(*l);
        g.a.cmp_imm(false, 0, 2);
        Label notfault;
        g.a.b_cond(NE, notfault);
        g.a.b_abs(g.leave);
        g.a.bind(notfault);
        // The op ended the block; it says how far it got, if it knows.
        g.a.ldr32(0, ra::CTX, static_cast<int32_t>(offsetof(Ctx, partial)));
        g.a.cmp_imm(false, 0, 0);
        Label have;
        g.a.b_cond(GE, have);
        g.a.mov_imm(0, static_cast<uint64_t>(g.insns));
        g.a.bind(have);
        g.a.alu(a64::ADD, true, ra::COUNT, ra::COUNT, 0);
        g.a.b_abs(g.leave);
    });
}

}  // namespace

void Engine::native_compile(Block* b) {
    if (b->nat || b->nat_failed) return;
    if (!native_init()) { native_on = false; return; }
    if (b->ir_ops.empty() || b->stub) { b->nat_failed = true; return; }
    if (nat_->cap - nat_->used < (1u << 20)) {
        if (depth_ > 1) return;   // code is running further up: try again later
        native_reset();
    }
    const std::vector<Op>& ops = b->ir_ops;
    uint8_t* where = nat_->base + nat_->used;
    Asm a(where);
    const int insns = static_cast<int>(b->insns);

    size_t ncells = 0;
    for (const Op& q : ops) {
        if (q.kind == OpKind::Exit) ++ncells;
        else if (q.kind == OpKind::JccGen || q.kind == OpKind::JccGenI) ncells += 2;
        else ncells += static_cast<size_t>(guest_native_cells(q));
    }
    b->ncells.reset(new uintptr_t[ncells ? ncells : 1]());
    size_t cell_next = 0;

    NativeGenA g{a, *this, *b, slots, b->start, insns, nat_->leave,
                 {}, [&]() { return &b->ncells[cell_next++]; }};
    g.inline_tlb = Glue::tlb_read_base(mem) != nullptr && !std::getenv(JIT_ENV("JIT_NATIVE_NOTLB"));
    b->single.clear();
    const GuestSlots& s = slots;

    for (size_t i = 0; i < ops.size() && !g.failed; ++i) {
        const Op& o = ops[i];
        const uint64_t rip_here = b->start + o.pc;
        g.fallback = [&, i] {
            std::unique_ptr<Uop[]> two(new Uop[2]);
            two[0] = b->code[i];
            make_stop_op(two[1]);
            a.mov_rr(0, ra::CTX);
            a.mov_imm(1, reinterpret_cast<uintptr_t>(two.get()));
            a.mov_imm(2, b->start);
            g.call(reinterpret_cast<const void*>(&native_generic_helper));
            b->single.push_back(std::move(two));
        };
        // x0 = a OP imm  (an immediate that fits goes in the instruction)
        auto op_imm = [&](uint32_t alu_op, bool x, int64_t imm) {
            if (alu_op == a64::ADD && fits_imm12(imm)) a.add_imm(x, 0, 0, static_cast<uint32_t>(imm));
            else if (alu_op == a64::SUB && fits_imm12(imm)) a.sub_imm(x, 0, 0, static_cast<uint32_t>(imm));
            else {
                a.mov_imm(1, x ? static_cast<uint64_t>(imm) : static_cast<uint32_t>(imm));
                a.alu(alu_op, x, 0, 0, 1);
            }
        };
        switch (o.kind) {
            case OpKind::Nop: break;
            case OpKind::Mov: g.ld(0, o.a); g.st(o.d, 0); break;
            case OpKind::MovI: g.st_imm(o.d, o.imm); break;
            case OpKind::Add: case OpKind::Sub: case OpKind::And: case OpKind::Or: case OpKind::Xor: {
                g.ld(0, o.a); g.ld(1, o.b);
                const uint32_t op = o.kind == OpKind::Add ? a64::ADD : o.kind == OpKind::Sub ? a64::SUB
                                    : o.kind == OpKind::And ? a64::AND : o.kind == OpKind::Or ? a64::ORR : a64::EOR;
                a.alu(op, true, 0, 0, 1);
                g.st(o.d, 0);
                break;
            }
            case OpKind::AddI: case OpKind::SubI: case OpKind::AndI: case OpKind::OrI: case OpKind::XorI: {
                g.ld(0, o.a);
                const uint32_t op = o.kind == OpKind::AddI ? a64::ADD : o.kind == OpKind::SubI ? a64::SUB
                                    : o.kind == OpKind::AndI ? a64::AND : o.kind == OpKind::OrI ? a64::ORR : a64::EOR;
                op_imm(op, true, o.imm);
                g.st(o.d, 0);
                break;
            }
            case OpKind::Bin: case OpKind::BinI: {
                const bool imm = o.kind == OpKind::BinI;
                const bool x = o.sz == 8;
                const BinOp op = static_cast<BinOp>(o.cc);
                const int bits = x ? 64 : 32;
                g.ld(0, o.a);
                auto load_b = [&] {
                    if (imm) a.mov_imm(1, x ? static_cast<uint64_t>(o.imm) : static_cast<uint32_t>(o.imm));
                    else g.ld(1, o.b);
                };
                switch (op) {
                    case BinOp::Add: case BinOp::Sub: case BinOp::And: case BinOp::Or: case BinOp::Xor:
                        if (imm) {
                            op_imm(op == BinOp::Add ? a64::ADD : op == BinOp::Sub ? a64::SUB : op == BinOp::And ? a64::AND
                                   : op == BinOp::Or ? a64::ORR : a64::EOR, x, o.imm);
                        } else {
                            g.ld(1, o.b);
                            a.alu(op == BinOp::Add ? a64::ADD : op == BinOp::Sub ? a64::SUB : op == BinOp::And ? a64::AND
                                  : op == BinOp::Or ? a64::ORR : a64::EOR, x, 0, 0, 1);
                        }
                        break;
                    case BinOp::Andn: load_b(); a.alu(a64::BIC, x, 0, 0, 1); break;
                    case BinOp::Orn: load_b(); a.alu(a64::ORN, x, 0, 0, 1); break;
                    case BinOp::Eon: load_b(); a.alu(a64::EON, x, 0, 0, 1); break;
                    case BinOp::Mul: load_b(); a.mul(x, 0, 0, 1); break;
                    case BinOp::UDiv0: load_b(); a.udiv(x, 0, 0, 1); break;
                    case BinOp::SDiv0: load_b(); a.sdiv(x, 0, 0, 1); break;
                    case BinOp::Shl: case BinOp::Shr: case BinOp::Sar: case BinOp::Ror: {
                        if (imm) {
                            const int n = static_cast<int>(o.imm & (bits - 1));
                            if (n == 0) { if (!x) a.mov_rr32(0, 0); }
                            else if (op == BinOp::Shl) a.lsl_imm(x, 0, 0, n);
                            else if (op == BinOp::Shr) a.lsr_imm(x, 0, 0, n);
                            else if (op == BinOp::Sar) a.asr_imm(x, 0, 0, n);
                            else a.ror_imm(x, 0, 0, n);
                        } else {
                            g.ld(1, o.b);
                            a.shiftv(op == BinOp::Shl ? LSL : op == BinOp::Shr ? LSR : op == BinOp::Sar ? ASR : ROR, x, 0, 0, 1);
                        }
                        break;
                    }
                }
                g.st(o.d, 0);
                break;
            }
            case OpKind::Un: {
                const bool x = o.sz == 8;
                const UnOp op = static_cast<UnOp>(o.cc);
                g.ld(0, o.a);
                switch (op) {
                    case UnOp::Clz: a.clz(x, 0, 0); break;
                    case UnOp::Rbit: a.rbit(x, 0, 0); break;
                    case UnOp::Rev: a.rev(x, 0, 0); break;
                    case UnOp::Rev16: a.rev16(x, 0, 0); break;
                    default: if (x) a.rev32(0, 0); else { emit_generic(g); continue; } break;
                }
                g.st(o.d, 0);
                break;
            }
            case OpKind::Lea:
                g.ld(0, o.a);
                if (o.c != s.zero) { g.ld(1, o.c); a.alu(a64::ADD, true, 0, 0, 1, LSL, o.cc); }
                if (o.imm) op_imm(a64::ADD, true, o.imm);
                if (o.sz == 4) a.mov_rr32(0, 0);
                g.st(o.d, 0);
                break;
            case OpKind::Ext:
                if (o.flags & kFlagSigned) {
                    if (o.sz == 1) a.ldrsb(0, ra::ENV, o.a);
                    else if (o.sz == 2) a.ldrsh(0, ra::ENV, o.a);
                    else a.ldrsw(0, ra::ENV, o.a);
                    if (o.cc == 4) a.mov_rr32(0, 0);
                } else {
                    g.ld_sz(0, o.a, o.sz);
                }
                g.st(o.d, 0);
                break;
            case OpKind::Put:
                g.ld(0, o.a); g.ld(1, o.b);
                if (o.sz == 1) a.bfm(true, 0, 1, 0, 7);
                else if (o.sz == 2) a.bfm(true, 0, 1, 0, 15);
                else a.bfm(true, 0, 1, 56, 7);   // bits 8..15
                g.st(o.d, 0);
                break;
            case OpKind::GetH:
                a.ldrb(0, ra::ENV, o.a + 1); g.st(o.d, 0); break;
            case OpKind::Sel:
                g.ld(0, o.b); g.ld(1, o.a); g.ld(2, o.c);
                a.cmp_imm(true, 2, 0);
                a.csel(true, 0, 1, 0, NE);
                g.st(o.d, 0);
                break;

            case OpKind::Ld: case OpKind::LdS: {
                emit_address(g, o);
                g.mem_read(o.sz, rip_here);
                if (o.kind == OpKind::LdS) {
                    if (o.sz == 1) a.sxtb(true, 0, 0); else if (o.sz == 2) a.sxth(true, 0, 0); else a.sxtw(0, 0);
                    if (o.imm2 == 4) a.mov_rr32(0, 0);
                }
                g.st(o.d, 0);
                break;
            }
            case OpKind::St: {
                emit_address(g, o);
                g.ld(4, o.b);
                g.mem_write(o.sz, rip_here);
                if (o.flags & kFlagChk) g.chk_flush(static_cast<uint64_t>(o.imm2), o.ni);
                break;
            }
            case OpKind::ChkFlush:
                g.chk_flush(static_cast<uint64_t>(o.imm), o.ni);
                break;

            case OpKind::Exit:
                g.exit_static(static_cast<uint64_t>(o.imm), insns);
                break;
            case OpKind::ExitInd:
                g.ld(0, o.a); g.st(s.rip, 0);
                g.leave_indirect(insns);
                break;
            case OpKind::JccGen: case OpKind::JccGenI: {
                const Cond cond = static_cast<Cond>(o.cc);
                const bool x = o.sz == 8;
                g.ld(0, o.a);
                if (o.kind == OpKind::JccGen) {
                    g.ld(1, o.b);
                    if (cond == Cond::Tst || cond == Cond::Ntst) a.tst(x, 0, 1); else a.cmp(x, 0, 1);
                } else if (cond != Cond::Tst && cond != Cond::Ntst && fits_imm12(o.d)) {
                    a.cmp_imm(x, 0, static_cast<uint32_t>(o.d));
                } else {
                    a.mov_imm(1, x ? static_cast<uint64_t>(static_cast<int64_t>(o.d)) : static_cast<uint32_t>(o.d));
                    if (cond == Cond::Tst || cond == Cond::Ntst) a.tst(x, 0, 1); else a.cmp(x, 0, 1);
                }
                g.labels.emplace_back();
                Label* taken = &g.labels.back();
                a.b_cond(cc_of(cond), *taken);
                g.exit_static(static_cast<uint64_t>(o.imm2), insns);
                a.bind(*taken);
                g.exit_static(static_cast<uint64_t>(o.imm), insns);
                break;
            }
            default:
                if (!guest_native_emit(g, o)) emit_generic(g);
                break;
        }
    }
    if (g.failed) { b->nat_failed = true; b->single.clear(); b->ncells.reset(); return; }
    a.brk();   // every block ends in an exit; this is for the debugger
    for (auto& f : g.stubs) f();
    if (nat_->used + a.bytes() > nat_->cap) { b->nat_failed = true; return; }
    {
        WriteScope ws;
        std::memcpy(where, a.w.data(), a.bytes());
    }
    sync_code(where, a.bytes());
    if (const char* dir = std::getenv(JIT_ENV("JIT_NATIVE_DUMP"))) {   // for the disassembler: one file per block
        char path[512];
        std::snprintf(path, sizeof path, "%s/blk_%04llu_%llx.bin", dir, (unsigned long long)n_native_blocks,
                      (unsigned long long)b->start);
        if (std::FILE* f = std::fopen(path, "wb")) { std::fwrite(a.w.data(), 1, a.bytes(), f); std::fclose(f); }
    }
    b->nat = where;
    nat_->used += (a.bytes() + 15) & ~size_t(15);
    ++n_native_blocks;
}

}  // namespace jit

#endif  // JIT_NATIVE_A64
