// The native backend: hot blocks become machine code, generated when a block has run a
// few dozen times.  Only for x86-64 hosts so far.
//
// A block's IR is turned into straight-line x86-64 that reads and writes the guest
// registers in memory (they are 64-bit cells at fixed offsets from rbx), so it has none
// of the threaded backend's per-op dispatch.  What it generates itself: moves,
// integer arithmetic, extensions, address arithmetic, loads and stores (through small C++
// helpers that do the page cache lookup), and the block's exits.  Every other op - the
// flag-setting ones, the interpreter, a division - is run by calling its threaded
// handler through `jit_generic`, so every op the frontends can produce already works.
//
// Blocks do not return to C++ one at a time.  An exit whose target is known goes through
// a word that holds the target's machine code once there is some (and the engine fills it
// in the first time it sees where the exit went), so a hot loop stays in generated code
// until it runs out of instruction budget or leaves translated code.
//
// Exceptions never cross generated frames: the helpers catch whatever the guest raises,
// remember it, and the generated code checks a flag and leaves; the engine rethrows.
#include "engine.h"
#include "native_host.h"

#if !defined(JIT_NATIVE_X64) && !defined(JIT_NATIVE_A64)

namespace jit {
bool Engine::native_init() { return false; }
void Engine::native_compile(Block*) {}
void Engine::native_reset() {}
bool Engine::native_run(Block*, Ctx&, uint64_t, uint32_t*) { return true; }
void Engine::native_shutdown() {}
}  // namespace jit

#elif defined(JIT_NATIVE_X64)

#include "native_gen.h"

#ifdef JIT_HAVE_NATIVE

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace jit {

using namespace x64;

struct Engine::NativeState {
    uint8_t* base = nullptr;
    size_t cap = 0, used = 0;
    uint64_t (*entry)(uint8_t*, Ctx*, const uint8_t*, uint64_t) = nullptr;
    const uint8_t* leave = nullptr;
};

namespace {

#ifdef _WIN32
constexpr int ARG1 = RCX, ARG2 = RDX, ARG3 = R8, ARG4 = R9;
#else
constexpr int ARG1 = RDI, ARG2 = RSI, ARG3 = RDX, ARG4 = RCX;
#endif

// ---- helpers the generated code calls ---------------------------------------------

void note_fault(Ctx* c, uint64_t rip) {
    c->eng->nexc_ = std::current_exception();
    c->nfault = 1;
    c->fault_rip = rip;
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

namespace {

// Runs one op through its threaded handler.  1: the block goes on; 0: the op ended it;
// 2: it raised an exception.
int nat_generic(Ctx* c, const Uop* u, uint64_t start) {
    try {
        return jit_generic(c, u);
    } catch (...) {
        note_fault(c, c->in_interp ? 0 : start + u->pc);
        return 2;
    }
}

// ---- executable memory --------------------------------------------------------------

uint8_t* alloc_exec(size_t n) {
#ifdef _WIN32
    return static_cast<uint8_t*>(VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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

namespace {
void call_abs(NativeGen& g, const void* fn) {
    g.a.movi(RAX, static_cast<int64_t>(reinterpret_cast<uintptr_t>(fn)));
    g.a.call_r(RAX);
}
}  // namespace

void NativeGen::mem_read(int size, uint64_t rip) {
    const int64_t meta = static_cast<int64_t>((rip << 8) | static_cast<uint64_t>(size));
    auto slow_call = [this, meta] {
        a.mov_rr(ARG2, RAX);
        a.mov_rr(ARG1, R12);
        a.movi(ARG3, meta);
        call_abs(*this, reinterpret_cast<const void*>(&native_read_helper));
        check_fault();
    };
    if (!inline_tlb) { slow_call(); return; }
    labels.emplace_back();
    Label* slow = &labels.back();
    labels.emplace_back();
    Label* done = &labels.back();
    a.mov_rr(RCX, RAX);
    a.shift_i(SHR, true, RCX, kTlbPageBits);              // rcx = page
    a.mov_rr32(RDX, RCX);
    a.alu_ri(AND, false, RDX, (1 << kTlbBits) - 1);
    a.shift_i(SHL, false, RDX, 4);
    a.alu_rr(ADD, true, RDX, R15);                        // rdx = the cache entry
    a.alu_rm(CMP, true, RCX, RDX, 0);
    a.jcc(NE, *slow);
    a.mov_rr32(RCX, RAX);
    a.alu_ri(AND, false, RCX, (1 << kTlbPageBits) - 1);   // rcx = offset in the page
    a.alu_ri(CMP, false, RCX, (1 << kTlbPageBits) - size);
    a.jcc(A, *slow);                                      // straddles the page
    a.alu_rm(ADD, true, RCX, RDX, 8);                     // rcx = host address
    switch (size) {
        case 1: a.load8u(RAX, RCX, 0); break;
        case 2: a.load16u(RAX, RCX, 0); break;
        case 4: a.load32(RAX, RCX, 0); break;
        default: a.load64(RAX, RCX, 0); break;
    }
    a.bind(*done);
    stubs.push_back([this, slow, done, slow_call] {
        a.bind(*slow);
        slow_call();
        a.jmp(*done);
    });
}

void NativeGen::mem_write(int size, uint64_t rip) {
    const int64_t meta = static_cast<int64_t>((rip << 8) | static_cast<uint64_t>(size));
    auto slow_call = [this, meta] {
        a.mov_rr(ARG2, RAX);
        a.mov_rr(ARG1, R12);
        a.mov_rr(ARG3, R9);
        a.movi(ARG4, meta);
        call_abs(*this, reinterpret_cast<const void*>(&native_write_helper));
        check_fault();
    };
    if (!inline_tlb) { slow_call(); return; }
    labels.emplace_back();
    Label* slow = &labels.back();
    labels.emplace_back();
    Label* done = &labels.back();
    a.mov_rr(RCX, RAX);
    a.shift_i(SHR, true, RCX, kTlbPageBits);
    a.mov_rr32(RDX, RCX);
    a.alu_ri(AND, false, RDX, (1 << kTlbBits) - 1);
    a.shift_i(SHL, false, RDX, 4);
    a.alu_rr(ADD, true, RDX, RBP);                        // the write cache
    a.alu_rm(CMP, true, RCX, RDX, 0);
    a.jcc(NE, *slow);
    a.mov_rr32(RCX, RAX);
    a.alu_ri(AND, false, RCX, (1 << kTlbPageBits) - 1);
    a.alu_ri(CMP, false, RCX, (1 << kTlbPageBits) - size);
    a.jcc(A, *slow);
    a.alu_rm(ADD, true, RCX, RDX, 8);
    switch (size) {
        case 1: a.store8(RCX, 0, R9); break;
        case 2: a.store16(RCX, 0, R9); break;
        case 4: a.store32(RCX, 0, R9); break;
        default: a.store64(RCX, 0, R9); break;
    }
    a.bind(*done);
    stubs.push_back([this, slow, done, slow_call] {
        a.bind(*slow);
        slow_call();
        a.jmp(*done);
    });
}

// The entry point (called from C++) and the shared exit.
//   entry(env, ctx, fn, limit): sets up the registers generated code expects and jumps to fn.
//   leave: returns the instruction count.
bool Engine::native_init() {
    if (nat_) return true;
    uint8_t* mem = alloc_exec(arena_size());
    if (!mem) return false;
    GMemory& mem_ = this->mem;
    nat_ = new NativeState;
    nat_->base = mem;
    nat_->cap = arena_size();
    Asm a(mem);
    a.push(RBX); a.push(R12); a.push(R13); a.push(R14); a.push(R15); a.push(RBP);
    a.alu_ri(SUB, true, RSP, 40);
    a.mov_rr(RBX, ARG1);
    a.mov_rr(R12, ARG2);
    a.mov_rr(RAX, ARG3);
    a.mov_rr(R14, ARG4);
    a.movi(R13, 0);
    a.movi(R15, static_cast<int64_t>(reinterpret_cast<uintptr_t>(Glue::tlb_read_base(mem_))));
    a.movi(RBP, static_cast<int64_t>(reinterpret_cast<uintptr_t>(Glue::tlb_write_base(mem_))));
    a.jmp_r(RAX);
    // leave:
    const size_t leave_at = a.pos();
    a.mov_rr(RAX, R13);
    a.alu_ri(ADD, true, RSP, 40);
    a.pop(RBP); a.pop(R15); a.pop(R14); a.pop(R13); a.pop(R12); a.pop(RBX);
    a.ret();
    std::memcpy(mem, a.b.data(), a.b.size());
    nat_->entry = reinterpret_cast<uint64_t (*)(uint8_t*, Ctx*, const uint8_t*, uint64_t)>(mem);
    nat_->leave = mem + leave_at;
    nat_->used = (a.b.size() + 15) & ~size_t(15);
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
    // keep the entry code at the start of the arena
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
        case Cond::Eq: return E;
        case Cond::Ne: return NE;
        case Cond::Ltu: return B;
        case Cond::Geu: return AE;
        case Cond::Leu: return BE;
        case Cond::Gtu: return A;
        case Cond::Lts: return L;
        case Cond::Ges: return GE;
        case Cond::Les: return LE;
        case Cond::Gts: return G;
        case Cond::Tst: return NE;
        default: return E;   // Ntst
    }
}

inline bool fits32(int64_t v) { return v >= INT32_MIN && v <= INT32_MAX; }

// rax = the effective address of a load or store
void emit_address(NativeGen& g, const Op& o) {
    g.ld(RAX, o.a);
    if (o.c != g.s.zero) {
        g.ld(RCX, o.c);
        if (o.cc) g.a.shift_i(SHL, true, RCX, o.cc);
        g.a.alu_rr(ADD, true, RAX, RCX);
    }
    if (o.imm) {
        if (fits32(o.imm)) g.a.alu_ri(ADD, true, RAX, static_cast<int32_t>(o.imm));
        else { g.a.movi(RCX, o.imm); g.a.alu_rr(ADD, true, RAX, RCX); }
    }
    if (o.flags & kFlagA32) g.a.mov_rr32(RAX, RAX);
}

// Run the op through its threaded handler.
void emit_generic(NativeGen& g) {
    g.fallback();
    g.labels.emplace_back();
    Label* l = &g.labels.back();
    g.a.alu_ri(CMP, false, RAX, 1);
    g.a.jcc(NE, *l);
    g.stubs.push_back([&g, l] {
        g.a.bind(*l);
        g.a.alu_ri(CMP, false, RAX, 2);
        g.a.jcc_abs(E, g.leave);
        // The op ended the block; it says how far it got, if it knows.
        g.a.load32(RAX, R12, static_cast<int32_t>(offsetof(Ctx, partial)));
        g.a.test_rr(false, RAX, RAX);
        Label done;
        g.a.jcc(NS, done);
        g.a.movi(RAX, g.insns);
        g.a.bind(done);
        g.a.alu_rr(ADD, true, R13, RAX);
        g.a.jmp_abs(g.leave);
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

    NativeGen g{a, *this, *b, slots, b->start, insns, nat_->leave,
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
            a.movi(ARG3, static_cast<int64_t>(b->start));
            a.movi(ARG2, static_cast<int64_t>(reinterpret_cast<uintptr_t>(two.get())));
            a.mov_rr(ARG1, R12);
            call_abs(g, reinterpret_cast<const void*>(&nat_generic));
            b->single.push_back(std::move(two));
        };
        auto rr_op = [&](int alu, bool w) {   // rax = a OP b
            g.ld(RAX, o.a);
            a.alu_rm(alu, w, RAX, RBX, o.b);
        };
        auto ri_op = [&](int alu, bool w, int64_t imm) {   // rax = a OP imm
            if (fits32(imm)) a.alu_ri(alu, w, RAX, static_cast<int32_t>(imm));
            else { a.movi(RCX, imm); a.alu_rr(alu, w, RAX, RCX); }
        };
        switch (o.kind) {
            case OpKind::Nop: break;
            case OpKind::Mov:
                g.ld(RAX, o.a); g.st(o.d, RAX); break;
            case OpKind::MovI:
                g.st_imm(o.d, o.imm); break;
            case OpKind::Add: rr_op(ADD, true); g.st(o.d, RAX); break;
            case OpKind::Sub: rr_op(SUB, true); g.st(o.d, RAX); break;
            case OpKind::And: rr_op(AND, true); g.st(o.d, RAX); break;
            case OpKind::Or: rr_op(OR, true); g.st(o.d, RAX); break;
            case OpKind::Xor: rr_op(XOR, true); g.st(o.d, RAX); break;
            case OpKind::AddI: g.ld(RAX, o.a); ri_op(ADD, true, o.imm); g.st(o.d, RAX); break;
            case OpKind::SubI: g.ld(RAX, o.a); ri_op(SUB, true, o.imm); g.st(o.d, RAX); break;
            case OpKind::AndI: g.ld(RAX, o.a); ri_op(AND, true, o.imm); g.st(o.d, RAX); break;
            case OpKind::OrI: g.ld(RAX, o.a); ri_op(OR, true, o.imm); g.st(o.d, RAX); break;
            case OpKind::XorI: g.ld(RAX, o.a); ri_op(XOR, true, o.imm); g.st(o.d, RAX); break;

            case OpKind::Bin: case OpKind::BinI: {
                const bool imm = o.kind == OpKind::BinI;
                const bool w = o.sz == 8;
                const BinOp op = static_cast<BinOp>(o.cc);
                const int bits = w ? 64 : 32;
                // operand b into rcx (as 32 or 64 bits)
                auto load_b = [&] {
                    if (imm) a.movi(RCX, w ? o.imm : static_cast<int64_t>(static_cast<uint32_t>(o.imm)));
                    else g.ld(RCX, o.b);
                };
                switch (op) {
                    case BinOp::Add: case BinOp::Sub: case BinOp::And: case BinOp::Or: case BinOp::Xor: {
                        const int alu = op == BinOp::Add ? ADD : op == BinOp::Sub ? SUB : op == BinOp::And ? AND
                                        : op == BinOp::Or ? OR : XOR;
                        g.ld(RAX, o.a);
                        if (imm) ri_op(alu, w, w ? o.imm : static_cast<int32_t>(o.imm));
                        else a.alu_rm(alu, w, RAX, RBX, o.b);
                        g.st(o.d, RAX);
                        break;
                    }
                    case BinOp::Andn: case BinOp::Orn: case BinOp::Eon:
                        g.ld(RAX, o.a); load_b(); a.not_r(w, RCX);
                        a.alu_rr(op == BinOp::Andn ? AND : op == BinOp::Orn ? OR : XOR, w, RAX, RCX);
                        g.st(o.d, RAX);
                        break;
                    case BinOp::Mul:
                        g.ld(RAX, o.a);
                        if (imm) { load_b(); a.imul_rr(w, RAX, RCX); }
                        else a.imul_rm(w, RAX, RBX, o.b);
                        g.st(o.d, RAX);
                        break;
                    case BinOp::Shl: case BinOp::Shr: case BinOp::Sar: case BinOp::Ror: {
                        const int sh = op == BinOp::Shl ? SHL : op == BinOp::Shr ? SHR : op == BinOp::Sar ? SAR : ROR;
                        g.ld(RAX, o.a);
                        if (imm) {
                            const int n = static_cast<int>(o.imm & (bits - 1));
                            if (n) a.shift_i(sh, w, RAX, n);
                            else if (!w) a.mov_rr32(RAX, RAX);   // keep the result 32 bits wide
                        } else {
                            g.ld(RCX, o.b);
                            a.shift_cl(sh, w, RAX);
                        }
                        g.st(o.d, RAX);
                        break;
                    }
                    default:   // UDiv0, SDiv0
                        emit_generic(g);
                        break;
                }
                break;
            }
            case OpKind::Un: {
                const UnOp op = static_cast<UnOp>(o.cc);
                if (op == UnOp::Rev && (o.sz == 4 || o.sz == 8)) {
                    g.ld(RAX, o.a);
                    a.bswap(o.sz == 8, RAX);
                    g.st(o.d, RAX);
                } else {
                    emit_generic(g);
                }
                break;
            }
            case OpKind::Lea:
                g.ld(RAX, o.a);
                if (o.c != s.zero) {
                    g.ld(RCX, o.c);
                    if (o.cc) a.shift_i(SHL, true, RCX, o.cc);
                    a.alu_rr(ADD, true, RAX, RCX);
                }
                if (o.imm) ri_op(ADD, true, o.imm);
                if (o.sz == 4) a.mov_rr32(RAX, RAX);
                g.st(o.d, RAX);
                break;
            case OpKind::Ext:
                if (o.flags & kFlagSigned) {
                    if (o.sz == 1) a.load8s(RAX, RBX, o.a);
                    else if (o.sz == 2) a.load16s(RAX, RBX, o.a);
                    else a.load32s(RAX, RBX, o.a);
                    if (o.cc == 4) a.mov_rr32(RAX, RAX);
                } else {
                    g.ld_sz(RAX, o.a, o.sz);
                }
                g.st(o.d, RAX);
                break;
            case OpKind::Put:
                g.ld(RAX, o.a);
                if (o.sz == 1) { a.alu_ri(AND, true, RAX, ~0xFF); a.load8u(RCX, RBX, o.b); }
                else if (o.sz == 2) { a.alu_ri(AND, true, RAX, ~0xFFFF); a.load16u(RCX, RBX, o.b); }
                else { a.alu_ri(AND, true, RAX, ~0xFF00); a.load8u(RCX, RBX, o.b); a.shift_i(SHL, false, RCX, 8); }
                a.alu_rr(OR, true, RAX, RCX);
                g.st(o.d, RAX);
                break;
            case OpKind::GetH:
                a.load8u(RAX, RBX, o.a + 1); g.st(o.d, RAX); break;
            case OpKind::Sel:
                g.ld(RAX, o.b); g.ld(RCX, o.a);
                a.alu_mi(CMP, true, RBX, o.c, 0);
                a.cmov(NE, true, RAX, RCX);
                g.st(o.d, RAX);
                break;

            case OpKind::Ld: case OpKind::LdS: {
                emit_address(g, o);
                g.mem_read(o.sz, rip_here);
                if (o.kind == OpKind::LdS) {
                    a.movsx64(RAX, RAX, o.sz * 8);
                    if (o.imm2 == 4) a.mov_rr32(RAX, RAX);
                }
                g.st(o.d, RAX);
                break;
            }
            case OpKind::St: {
                emit_address(g, o);
                g.ld(R9, o.b);
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
                g.ld(RAX, o.a); g.st(s.rip, RAX);
                g.leave_indirect(insns);
                break;
            case OpKind::JccGen: case OpKind::JccGenI: {
                const Cond cond = static_cast<Cond>(o.cc);
                const bool w = o.sz == 8;
                g.ld(RAX, o.a);
                if (cond == Cond::Tst || cond == Cond::Ntst) {
                    if (o.kind == OpKind::JccGen) a.test_rm(w, RAX, RBX, o.b);
                    else if (fits32(o.d)) a.test_ri(w, RAX, o.d);
                    else { a.movi(RCX, o.d); a.test_rr(w, RAX, RCX); }
                } else if (o.kind == OpKind::JccGen) {
                    a.alu_rm(CMP, w, RAX, RBX, o.b);
                } else {
                    a.alu_ri(CMP, w, RAX, o.d);
                }
                g.labels.emplace_back();
                Label* taken = &g.labels.back();
                a.jcc(cc_of(cond), *taken);
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
    a.u8(0xCC);   // every block ends in an exit; this is for the debugger
    for (auto& f : g.stubs) f();
    if (nat_->used + a.b.size() > nat_->cap) { b->nat_failed = true; return; }
    std::memcpy(where, a.b.data(), a.b.size());
    if (const char* dir = std::getenv(JIT_ENV("JIT_NATIVE_DUMP"))) {   // for the disassembler: one file per block
        char path[512];
        std::snprintf(path, sizeof path, "%s/blk_%04llu_%llx.bin", dir, (unsigned long long)n_native_blocks,
                      (unsigned long long)b->start);
        if (std::FILE* f = std::fopen(path, "wb")) { std::fwrite(a.b.data(), 1, a.b.size(), f); std::fclose(f); }
    }
    b->nat = where;
    nat_->used += (a.b.size() + 15) & ~size_t(15);
    ++n_native_blocks;
}

}  // namespace jit

#endif  // JIT_HAVE_NATIVE
#endif  // the host
