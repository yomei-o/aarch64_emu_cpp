// The WebAssembly backend: hot blocks become WebAssembly functions built at run
// time.
//
// Only in the browser (and node) build, because it needs the JavaScript side to
// compile what it produces.  A block starts out in the threaded backend; once it
// has run a few dozen times its IR is turned into a function in a module that
// imports the emulator's own linear memory and function table, so the code it
// generates reads and writes the guest registers, probes the guest page cache
// and calls back into C++ exactly as the threaded handlers do - only without a
// handler call per op.
//
// What it translates itself: moves, integer arithmetic, address arithmetic, the
// guest memory accesses (the page cache probe is inline, a miss calls C++),
// stack operations, flag conditions and the block's exits.  Anything else - an
// instruction with eagerly computed flags, a multiply, a divide, the interpreter
// - is run by calling the op's threaded handler through `jit_generic`, so
// every op the frontend can produce already works here.
#include "engine.h"

#ifdef __EMSCRIPTEN__

#include <emscripten.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>



#include "wasm_gen.h"

namespace jit {

namespace {

using Cpu = GCpu;
using Memory = GMemory;

// ---- helpers the generated code calls ---------------------------------------

uint64_t wr_read(Memory* m, uint64_t addr, uint32_t size) {
    switch (size) {
        case 1: return Glue::rd8(*m, addr);
        case 2: return Glue::rd16(*m, addr);
        case 4: return Glue::rd32(*m, addr);
        default: return Glue::rd64(*m, addr);
    }
}

void wr_write(Memory* m, uint64_t addr, uint32_t size, uint64_t v) {
    switch (size) {
        case 1: Glue::wr8(*m, addr, static_cast<uint8_t>(v)); break;
        case 2: Glue::wr16(*m, addr, static_cast<uint16_t>(v)); break;
        case 4: Glue::wr32(*m, addr, static_cast<uint32_t>(v)); break;
        default: Glue::wr64(*m, addr, v); break;
    }
}

// ---- a small WebAssembly assembler ------------------------------------------

// $chain(env, ctx, fn, limit) -> instructions finished.  Runs block functions one
// after another - each returns the next one's table index in its high half - until
// one has no successor ready or `limit` instructions are done.
void build_chain_function(Buf& code) {
    Buf b;
    auto get = [&](int l) { b.u8(0x20); b.uleb(l); };
    auto set = [&](int l) { b.u8(0x21); b.uleb(l); };
    // params: 0 env, 1 ctx, 2 fn, 3 limit; locals: 4 total (i32), 5 r (i64)
    b.uleb(2);
    b.uleb(1); b.u8(0x7F);
    b.uleb(1); b.u8(0x7E);
    b.u8(0x02); b.u8(0x40);                 // block
    b.u8(0x03); b.u8(0x40);                 // loop
      get(0); get(1); get(2); b.u8(0x11); b.uleb(T_BLOCK); b.uleb(0);   // r = fn(env, ctx)
      set(5);
      get(4); get(5); b.u8(0xA7); b.u8(0x6A); set(4);                    // total += (i32) r
      get(5); b.u8(0x42); b.sleb(32); b.u8(0x88); b.u8(0xA7); set(2);    // fn = (i32)(r >> 32)
      get(2); b.u8(0x45); b.u8(0x0D); b.uleb(1);                         // fn == 0: leave
      get(4); get(3); b.u8(0x4F); b.u8(0x0D); b.uleb(1);                 // total >= limit (signed): leave
      b.u8(0x0C); b.uleb(0);                                             // again
    b.u8(0x0B);                              // end loop
    b.u8(0x0B);                              // end block
    get(4);
    b.u8(0x0B);                              // end func
    code.append(b);
}


}  // namespace

// ---- the JavaScript half ------------------------------------------------------

// Instantiates a module of `n` functions f0..f(n-1) and puts them in the function
// table; returns the index of f0, or -1.
EM_JS(int, jitwasm_install, (const uint8_t* p, int len, int n), {
    try {
        var mod = new WebAssembly.Module(HEAPU8.slice(p, p + len));
        var inst = new WebAssembly.Instance(mod, {env: {memory: wasmMemory, table: wasmTable}});
        var base = wasmTable.length;
        wasmTable.grow(n + 1);
        for (var i = 0; i < n; i++) wasmTable.set(base + i, inst.exports['f' + i]);
        wasmTable.set(base + n, inst.exports['chain']);
        return base;
    } catch (e) {
        console.error('jit wasm: ' + e);
        return -1;
    }
});

void Engine::wasm_queue(Block* b) {
    if (std::getenv(JIT_ENV("JIT_DEBUG"))) std::fprintf(stderr, "[jit] queue %llx\n", (unsigned long long)b->start);
    b->wasm_queued = true;
    wasm_pending_.push_back(b);
    if (wasm_pending_.size() >= wasm_batch) wasm_compile_pending();
}

void Engine::wasm_compile_pending() {
    if (wasm_pending_.empty()) return;
    std::vector<Block*> blocks;
    blocks.swap(wasm_pending_);

    Env env;
    env.tlb_read = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Glue::tlb_read_base(mem)));
    env.tlb_write = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(Glue::tlb_write_base(mem)));
    env.mem_ptr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&mem));
    env.epoch_addr = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&epoch));
    env.read_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&wr_read));
    env.write_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&wr_write));
    env.generic_fn = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&jit_generic));

    env.slots = slots;

    std::vector<Buf> bodies;
    std::vector<Block*> used;
    for (Block* b : blocks) {
        if (b->valid && !b->stub && !b->ir_ops.empty()) used.push_back(b);
    }
    std::vector<Buf> extras;
    guest_wasm_extras(extras);
    // Function indices: the blocks, then the guest's extra functions, then $chain.
    env.extra_base = static_cast<uint32_t>(used.size());
    used.clear();
    for (Block* b : blocks) {
        if (!b->valid || b->stub || b->ir_ops.empty()) continue;
        const std::vector<Op>& ops = b->ir_ops;
        // The one-op programs for the ops done by calling their handlers.
        b->single.clear();
        Buf gbuf;
        Gen g(env, gbuf);
        g.start = b->start;
        // One word per static exit: where the next block's function goes once it has one.
        size_t ncells = 0;
        for (const Op& q : ops)
            ncells += (q.kind == OpKind::Exit) ? 1 : guest_wasm_cells(q);
        b->cells.reset(new uint32_t[ncells ? ncells : 1]());
        size_t cell_next = 0;
        auto cell_addr = [&](size_t k) {
            return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&b->cells[k]));
        };
        const int insns = static_cast<int>(b->insns);

        for (size_t i = 0; i < ops.size(); ++i) {
            const Op& o = ops[i];
            const int pc = static_cast<int>(o.pc);
            const bool eager = (o.flags & kFlagEager) != 0;
            auto fallback = [&] {
                ++wasm_fallbacks[static_cast<size_t>(o.kind)];
                std::unique_ptr<Uop[]> two(new Uop[2]);
                two[0] = b->code[i];
                make_stop_op(two[1]);
                g.generic(two.get(), insns);
                b->single.push_back(std::move(two));
            };
            switch (o.kind) {
                case OpKind::Nop: break;
                case OpKind::Mov:
                    g.get(L_ENV); g.slot_get(o.a); g.st64(o.d); break;
                case OpKind::MovI:
                    g.get(L_ENV); g.i64c(o.imm); g.st64(o.d); break;
                case OpKind::Add: case OpKind::Sub: case OpKind::And: case OpKind::Or: case OpKind::Xor: {
                    g.get(L_ENV); g.slot_get(o.a); g.slot_get(o.b);
                    g.op(o.kind == OpKind::Add ? Gen::I64_ADD : o.kind == OpKind::Sub ? Gen::I64_SUB
                         : o.kind == OpKind::And ? Gen::I64_AND : o.kind == OpKind::Or ? Gen::I64_OR : Gen::I64_XOR);
                    g.st64(o.d);
                    break;
                }
                case OpKind::AddI: case OpKind::SubI: case OpKind::AndI: case OpKind::OrI: case OpKind::XorI: {
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(o.imm);
                    g.op(o.kind == OpKind::AddI ? Gen::I64_ADD : o.kind == OpKind::SubI ? Gen::I64_SUB
                         : o.kind == OpKind::AndI ? Gen::I64_AND : o.kind == OpKind::OrI ? Gen::I64_OR : Gen::I64_XOR);
                    g.st64(o.d);
                    break;
                }
                case OpKind::Lea:
                    g.get(L_ENV);
                    g.slot_get(o.a); g.slot_get(o.c); g.i64c(o.cc); g.op(Gen::I64_SHL); g.op(Gen::I64_ADD);
                    if (o.imm) { g.i64c(o.imm); g.op(Gen::I64_ADD); }
                    if (o.sz == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    g.st64(o.d);
                    break;
                case OpKind::Ext: {
                    g.get(L_ENV); g.slot_get(o.a);
                    if (o.flags & kFlagSigned) {
                        g.op(o.sz == 1 ? Gen::I64_EXT8 : o.sz == 2 ? Gen::I64_EXT16 : Gen::I64_EXT32);
                        if (o.cc == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    } else {
                        g.mask(o.sz);
                    }
                    g.st64(o.d);
                    break;
                }
                case OpKind::Put:
                    g.get(L_ENV);
                    if (o.sz == 1) {
                        g.slot_get(o.a); g.i64c(~0xFFll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFF); g.op(Gen::I64_AND); g.op(Gen::I64_OR);
                    } else if (o.sz == 2) {
                        g.slot_get(o.a); g.i64c(~0xFFFFll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFFFF); g.op(Gen::I64_AND); g.op(Gen::I64_OR);
                    } else {
                        g.slot_get(o.a); g.i64c(~0xFF00ll); g.op(Gen::I64_AND);
                        g.slot_get(o.b); g.i64c(0xFF); g.op(Gen::I64_AND); g.i64c(8); g.op(Gen::I64_SHL); g.op(Gen::I64_OR);
                    }
                    g.st64(o.d);
                    break;
                case OpKind::GetH:
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(8); g.op(Gen::I64_SHR_U); g.i64c(0xFF); g.op(Gen::I64_AND);
                    g.st64(o.d); break;
                case OpKind::Sel:
                    g.get(L_ENV); g.slot_get(o.a); g.slot_get(o.b); g.slot_get(o.c); g.i64c(0); g.op(Gen::I64_NE);
                    g.op(0x1B); g.st64(o.d); break;
                case OpKind::Ld: {
                    g.address(o);
                    g.emit_read(o.sz, pc);
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);
                    break;
                }
                case OpKind::LdS: {
                    g.address(o);
                    g.emit_read(o.sz, pc);
                    g.op(o.sz == 1 ? Gen::I64_EXT8 : o.sz == 2 ? Gen::I64_EXT16 : Gen::I64_EXT32);
                    if (o.imm2 == 4) { g.i64c(0xFFFFFFFFll); g.op(Gen::I64_AND); }
                    g.set(L_V);
                    g.get(L_ENV); g.get(L_V); g.st64(o.d);
                    break;
                }
                case OpKind::St: {
                    g.address(o);
                    g.slot_get(o.b); g.set(L_V);
                    g.emit_write(o.sz, pc);
                    g.chk_flush(o);
                    break;
                }
                case OpKind::Exit:
                    g.get(L_ENV); g.i64c(o.imm); g.st64(env.slots.rip);
                    g.leave_static(cell_addr(cell_next++), insns);
                    break;
                case OpKind::ExitInd:
                    g.get(L_ENV); g.slot_get(o.a); g.st64(env.slots.rip); g.ret(insns); break;
                case OpKind::ShlI: case OpKind::ShrI: case OpKind::SarI:
                    g.get(L_ENV); g.slot_get(o.a); g.i64c(o.imm & 63);
                    g.op(o.kind == OpKind::ShlI ? Gen::I64_SHL : o.kind == OpKind::ShrI ? Gen::I64_SHR_U : Gen::I64_SHR_S);
                    g.st64(o.d); break;
                default: {
                    BlockGen bg{g, env, b, o, pc, insns, eager,
                                [&] { return cell_addr(cell_next++); }, fallback};
                    if (!guest_wasm_emit(bg)) fallback();
                    break;
                }
            }
        }
        // Every block ends in an exit that returns; this is for the validator.
        g.i64c(insns);
        g.op(0x0B);

        Buf body;
        // locals: 3 x i32, 5 x i64
        Buf code;
        code.uleb(2);
        code.uleb(3); code.u8(0x7F);
        code.uleb(5); code.u8(0x7E);
        code.append(gbuf);
        body.uleb(code.b.size());
        body.append(code);
        bodies.push_back(std::move(body));
        used.push_back(b);
    }

    Buf m;
    const uint8_t header[] = {0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00};
    m.bytes(header, sizeof header);
    auto section = [&](uint8_t id, const Buf& content) {
        m.u8(id);
        m.uleb(content.b.size());
        m.append(content);
    };
    {   // types
        Buf s;
        s.uleb(6);
        const uint8_t t0[] = {0x60, 2, 0x7F, 0x7F, 1, 0x7E};                 // a block: (env, ctx) -> i64
        const uint8_t t1[] = {0x60, 3, 0x7F, 0x7E, 0x7F, 1, 0x7E};           // slow read
        const uint8_t t2[] = {0x60, 4, 0x7F, 0x7E, 0x7F, 0x7E, 0};           // slow write
        const uint8_t t3[] = {0x60, 5, 0x7E, 0x7E, 0x7E, 0x7F, 0x7E, 1, 0x7E};   // flags
        const uint8_t t4[] = {0x60, 2, 0x7F, 0x7F, 1, 0x7F};                 // jit_generic
        const uint8_t t5[] = {0x60, 4, 0x7F, 0x7F, 0x7F, 0x7F, 1, 0x7F};     // chain
        s.bytes(t0, sizeof t0); s.bytes(t1, sizeof t1); s.bytes(t2, sizeof t2); s.bytes(t3, sizeof t3);
        s.bytes(t4, sizeof t4); s.bytes(t5, sizeof t5);
        section(1, s);
    }
    {   // imports: the emulator's memory and function table
        Buf s;
        s.uleb(2);
        s.name("env"); s.name("memory"); s.u8(0x02); s.u8(0x00); s.uleb(1);
        s.name("env"); s.name("table"); s.u8(0x01); s.u8(0x70); s.u8(0x00); s.uleb(0);
        section(2, s);
    }
    {   // functions
        Buf s;
        s.uleb(bodies.size() + extras.size() + 1);
        for (size_t i = 0; i < bodies.size(); ++i) s.uleb(T_BLOCK);
        for (size_t i = 0; i < extras.size(); ++i) s.uleb(T_EXTRA);
        s.uleb(T_CHAIN);
        section(3, s);
    }
    {   // exports f0, f1, ...
        Buf s;
        s.uleb(bodies.size() + 1);
        for (size_t i = 0; i < bodies.size(); ++i) {
            std::string n = "f" + std::to_string(i);
            s.name(n.c_str());
            s.u8(0x00);
            s.uleb(i);
        }
        s.name("chain");
        s.u8(0x00);
        s.uleb(bodies.size() + extras.size());
        section(7, s);
    }
    {   // code
        Buf s;
        s.uleb(bodies.size() + extras.size() + 1);
        for (const Buf& b : bodies) s.append(b);
        for (const Buf& f : extras) {
            s.uleb(f.b.size());
            s.append(f);
        }
        Buf cb;
        build_chain_function(cb);
        s.uleb(cb.b.size());
        s.append(cb);
        section(10, s);
    }

    int base = jitwasm_install(m.b.data(), static_cast<int>(m.b.size()), static_cast<int>(bodies.size()));
    ++n_wasm_modules;
    if (base < 0) {
        wasm_on = false;   // something in the generator is wrong; stay with the threaded tier
        return;
    }
    wasm_chain_fn = static_cast<uint32_t>(base) + static_cast<uint32_t>(used.size());
    for (size_t i = 0; i < used.size(); ++i) used[i]->wasm_fn = static_cast<uint32_t>(base) + static_cast<uint32_t>(i);
    n_wasm_blocks += used.size();
    if (stats_every_ && n_wasm_modules % 20 == 0) print_stats();
}

}  // namespace jit

#else   // not the browser build: there is no wasm tier

namespace jit {
void Engine::wasm_queue(Block*) {}
void Engine::wasm_compile_pending() {}
}  // namespace jit

#endif
