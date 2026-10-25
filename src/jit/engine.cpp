#include "engine.h"
#include "native_host.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace jit {

using Cpu = GCpu;
using Memory = GMemory;

namespace {
Engine* g_stats_engine = nullptr;
}

Engine::Engine(Cpu& c, Memory& m) : cpu(c), mem(m) {
    Glue::fill_slots(slots, cpu);
    mem.set_code_observer(this);
    if (const char* sv = std::getenv(JIT_ENV("JIT_STATS"))) {
        stats_every_ = std::strtoull(sv, nullptr, 10);
        // Report at exit for an engine that is still alive then (the emulator is a
        // static in some hosts); one that was destroyed has already reported.
        if (!g_stats_engine) {
            g_stats_engine = this;
            std::atexit([] { if (g_stats_engine) g_stats_engine->print_stats(); });
        }
    }
    if (const char* v = std::getenv(JIT_ENV("JIT_VERIFY"))) verify = v[0] == '1';
    if (const char* v = std::getenv(JIT_ENV("JIT_PROFILE"))) profile = v[0] == '1';
#ifdef __EMSCRIPTEN__
    wasm_on = true;
#endif
#if defined(JIT_NATIVE_X64) || defined(JIT_NATIVE_A64)
    native_on = true;
#endif
    if (const char* v = std::getenv(JIT_ENV("JIT_NATIVE"))) native_on = native_on && v[0] != '0';
    if (const char* v = std::getenv(JIT_ENV("JIT_NATIVE_HOT"))) {
        native_hot = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
        if (native_hot < 1) native_hot = 1;
    }
    if (const char* v = std::getenv(JIT_ENV("JIT_WASM"))) wasm_on = v[0] != '0';
    if (const char* v = std::getenv(JIT_ENV("JIT_WASM_HOT"))) {
        wasm_hot = static_cast<uint32_t>(std::strtoul(v, nullptr, 10));
        if (wasm_hot < 1) wasm_hot = 1;
        wasm_batch = wasm_hot <= 1 ? 1 : wasm_batch;
    }
}

Engine::~Engine() {
    mem.set_code_observer(nullptr);
    native_shutdown();
    if (std::getenv(JIT_ENV("JIT_STATS"))) print_stats();
    if (g_stats_engine == this) g_stats_engine = nullptr;
}

// Where the time goes, from the blocks' run counts: the ops executed by kind, and
// the hottest blocks with the ops they are made of.
void Engine::print_profile() {
    std::vector<uint64_t> by_kind(256, 0);
    uint64_t total_ops = 0, total_hits = 0;
    std::vector<Block*> blocks;
    for (auto& b : all_) {
        if (!b->hits) continue;
        blocks.push_back(b.get());
        total_hits += b->hits;
        for (const Uop& u : b->code) { by_kind[u.kind] += b->hits; total_ops += b->hits; }
    }
    std::fprintf(stderr, "[prof] %llu block runs, %llu ops (%.2f per block)\n", (unsigned long long)total_hits,
                 (unsigned long long)total_ops, total_hits ? double(total_ops) / double(total_hits) : 0.0);
    std::vector<int> order;
    for (int k = 0; k < 256; ++k) if (by_kind[k]) order.push_back(k);
    std::sort(order.begin(), order.end(), [&](int a, int b) { return by_kind[a] > by_kind[b]; });
    for (size_t i = 0; i < order.size() && i < 24; ++i)
        std::fprintf(stderr, "[prof]   %-10s %5.1f%%\n", op_name(static_cast<OpKind>(order[i])),
                     100.0 * double(by_kind[order[i]]) / double(total_ops));
    std::sort(blocks.begin(), blocks.end(), [](Block* a, Block* b) {
        return a->hits * a->code.size() > b->hits * b->code.size();
    });
    for (size_t i = 0; i < blocks.size() && i < 12; ++i) {
        Block* b = blocks[i];
        std::fprintf(stderr, "[prof] block %llX  runs %llu  insns %u  ops:", (unsigned long long)b->start,
                     (unsigned long long)b->hits, b->insns);
        for (const Uop& u : b->code)
            std::fprintf(stderr, " %s", op_name(static_cast<OpKind>(u.kind)));
        std::fprintf(stderr, "\n");
    }
}

void Engine::print_stats() {
    if (profile) print_profile();
    if (wasm_on || n_wasm_blocks || native_on)
    {
        std::fprintf(stderr, "[jit] wasm tier: %llu blocks in %llu modules; ops left to the threaded handlers:",
                     (unsigned long long)n_wasm_blocks, (unsigned long long)n_wasm_modules);
        for (size_t k = 0; k < 128; ++k)
            if (wasm_fallbacks[k]) std::fprintf(stderr, " #%zu x%llu", k, (unsigned long long)wasm_fallbacks[k]);
        std::fprintf(stderr, "\n[jit] fallback runs:");
        for (size_t k = 0; k < 128; ++k)
            if (generic_calls[k]) std::fprintf(stderr, " #%zu x%llu", k, (unsigned long long)generic_calls[k]);
        std::fprintf(stderr, "\n");
    }
    if (native_on || n_native_blocks)
        std::fprintf(stderr, "[jit] native tier: %llu blocks of machine code\n", (unsigned long long)n_native_blocks);
    std::fprintf(stderr,
                 "[jit] translated %llu blocks, ran %llu (%llu native insns, %llu interpreted), invalidated %llu, stub hits %llu\n",
                 (unsigned long long)n_translated, (unsigned long long)n_blocks_run,
                 (unsigned long long)n_insns_native, (unsigned long long)n_interp,
                 (unsigned long long)n_invalidated, (unsigned long long)n_stub_hits);
    for (int k = 0; k < 14; ++k) {
        int best = -1;
        for (int i = 0; i < 512; ++i)
            if (interp_ops[i] && (best < 0 || interp_ops[i] > interp_ops[best])) best = i;
        if (best < 0) break;
        std::fprintf(stderr, "[jit]   interp %s%02X  %llu\n", best >= 256 ? "0F " : "", best & 255,
                     (unsigned long long)interp_ops[best]);
        interp_ops[best] = 0;
    }
}

Block* Engine::lookup(uint64_t pc) {
    Block*& slot = table_[(pc ^ (pc >> kTableBits)) & ((1u << kTableBits) - 1)];
    Block* b = slot;
    if (b && b->start == pc && b->valid) return b;
    auto it = map_.find(pc);
    if (it == map_.end()) return nullptr;
    slot = it->second;
    return it->second;
}

Block* Engine::translate(uint64_t pc) {
    const uint64_t page = pc >> kCodeBits;
    auto blk = std::make_unique<Block>();
    blk->start = pc;
    blk->page = page;
    bool watch = true;

    if (banned_.count(page)) {
        blk->stub = true;
        watch = false;   // never translated, so nothing to invalidate
    } else {
        IrBlock ir;
        if (translate_block(cpu, slots, pc, ir)) {
            compile_threaded(*this, ir, *blk);
            if (wasm_on || native_on) {
                // An op that jumps forward inside the block (A32Skip) only exists as a threaded
                // handler; such a block is never compiled to WebAssembly or machine code.
                bool ok = true;
                for (const Op& o : ir.ops) ok = ok && o.kind != OpKind::A32Skip;
                if (ok) blk->ir_ops = ir.ops;
            }
            blk->insns = ir.insns;
            blk->effects = ir.effects;
            blk->guest_bytes = ir.guest_bytes;
            ++n_translated;
        } else {
            blk->stub = true;
        }
        if (!mem.mark_code_page(page)) {
            blk->stub = true;
            blk->code.clear();
            watch = false;
        }
    }

    Block* raw = blk.get();
    all_.push_back(std::move(blk));
    map_[pc] = raw;
    if (watch) by_page_[page].push_back(raw);
    else if (raw->stub) {
        // Stubs on unwatched pages stay valid; nothing changes under them
        // without a map/unmap, which flushes everything.
    }
    table_[(pc ^ (pc >> kTableBits)) & ((1u << kTableBits) - 1)] = raw;
    return raw;
}

void Engine::reclaim() {
    if (dead_ < 8192 || depth_ > 0) return;
    for (auto& s : table_)
        if (s && !s->valid) s = nullptr;
    size_t w = 0;
    for (size_t r = 0; r < all_.size(); ++r) {
        if (all_[r]->valid) {
            if (w != r) all_[w] = std::move(all_[r]);
            ++w;
        }
    }
    all_.resize(w);
    dead_ = 0;
}

bool Engine::run_block() {
    const uint64_t pc = Glue::pc(cpu);
    Block* b = lookup(pc);
    if (!b) {
        reclaim();
        b = translate(pc);
    }
    if (b->stub) {
        ++n_stub_hits;
        return false;
    }
    return verify ? run_verified(b) : run_plain(b);
}

// Runs translated blocks one after another for as long as there are any to run:
// until the instruction counter reaches `deadline`, rip reaches `stop_pc`, the
// guest halts, `*yield` is set, or rip is somewhere that is not translated code
// (a host hook, a stub).  Returns whether at least one block ran.
//
// Staying in here between blocks is most of the point.  Blocks average four or
// five guest instructions, so the work of getting into and out of the engine
// was as large as the blocks themselves.
bool Engine::run(uint64_t deadline, uint64_t stop_pc, const bool* yield) {
    if (verify) {
        // One block at a time, each checked against the interpreter.
        const uint64_t pc = Glue::pc(cpu);
        if (Glue::is_stop(pc, stop_pc) || Glue::in_hook(cpu, pc)) return false;
        return run_block();
    }
    reclaim();
    Ctx ctx{Glue::env(cpu), &cpu, &mem, this, 0, -1, false, nullptr, false, -1, nullptr, 0};
    const Uop* u = nullptr;
    Block* b = nullptr;
    bool any = false;
    ++depth_;
    try {
        for (;;) {
            const uint64_t pc = Glue::pc(cpu);
            if (Glue::is_stop(pc, stop_pc) || Glue::in_hook(cpu, pc)) break;
            b = lookup(pc);
            if (!b) b = translate(pc);
            if (b->stub) {
                ++n_stub_hits;
                break;
            }
            ctx.epoch0 = epoch;
            ctx.partial = -1;
            ctx.cur = nullptr;
            if (profile) ++b->hits;
            uint32_t done;
            // The exit that left machine code last time (if one did) was heading here: when this
            // block has machine code too, it can jump straight to it from now on.
            uintptr_t* const npend = ctx.npending;
            ctx.npending = nullptr;
            if (native_on && !b->nat && !b->nat_failed && ++b->heat >= native_hot) native_compile(b);
            if (b->nat) {
                // Machine code: runs this block and then whichever ones its exits lead to.
                if (npend) {
                    *npend = reinterpret_cast<uintptr_t>(b->nat);
                    nlinked_cells_.push_back(npend);
                }
                ctx.fault_rip = 0;
                const uint64_t left = deadline > Glue::icount(cpu) ? deadline - Glue::icount(cpu) : 1;
                const bool ok = native_run(b, ctx, left, &done);
                Glue::add_icount(cpu, done);
                n_insns_native += done;
                any = true;
                if (!ok) {
                    std::exception_ptr e = nexc_;
                    nexc_ = nullptr;
                    std::rethrow_exception(e);
                }
                if (Glue::halted(cpu) || (yield && *yield) || Glue::icount(cpu) >= deadline) break;
                continue;
            }
            if (b->wasm_fn) {
                // The block a static exit was heading for has now been found: next time
                // that exit goes straight there.
                if (ctx.pending_cell) {
                    *ctx.pending_cell = b->wasm_fn;
                    linked_cells_.push_back(ctx.pending_cell);
                    ctx.pending_cell = nullptr;
                }
                ctx.fault_rip = 0;
                const uint64_t left = deadline > Glue::icount(cpu) ? deadline - Glue::icount(cpu) : 1;
                done = static_cast<uint32_t>(reinterpret_cast<ChainFn>(static_cast<uintptr_t>(wasm_chain_fn))(
                    ctx.env, &ctx, b->wasm_fn, static_cast<uint32_t>(left > 0x7FFFFFFF ? 0x7FFFFFFF : left)));
                Glue::add_icount(cpu, done);
                n_insns_native += done;
                any = true;
                if (Glue::halted(cpu) || (yield && *yield) || Glue::icount(cpu) >= deadline) break;
                continue;
            } else {
                ctx.pending_cell = nullptr;
                if (wasm_on && ++b->heat == wasm_hot && !b->wasm_queued) wasm_queue(b);
                u = b->code.data();
                while (u) u = u->fn(&ctx, u);
                done = ctx.partial >= 0 ? static_cast<uint32_t>(ctx.partial) : b->insns;
            }
            Glue::add_icount(cpu, done);
            ++n_blocks_run;
            n_insns_native += done;
            any = true;
            if (stats_every_ && n_blocks_run % stats_every_ == 0) print_stats();
            if (Glue::halted(cpu) || (yield && *yield) || Glue::icount(cpu) >= deadline) break;
        }
    } catch (const GFault&) {
        Glue::settle(cpu);
        --depth_;
        // Report the fault at the start of the instruction that made it, which
        // is where an exception handler would restart it - unless it came out
        // of an interpreted instruction, which has already said where it was.
        if (ctx.fault_rip) Glue::set_pc(cpu, ctx.fault_rip);
        else if (ctx.cur && !ctx.in_interp) Glue::set_pc(cpu, b->start + ctx.cur->pc);
        throw;
    } catch (...) {
        Glue::settle(cpu);
        --depth_;
        throw;
    }
    Glue::settle(cpu);
    --depth_;
    // Blocks that got hot during this stretch are compiled before the next one.
    if (!wasm_pending_.empty() && depth_ == 0) wasm_compile_pending();
    return any;
}

bool Engine::run_plain(Block* b) {
    Ctx ctx{Glue::env(cpu), &cpu, &mem, this, epoch, -1, false, nullptr, false, -1, nullptr, 0};
    ++depth_;
    if (!b->wasm_fn && wasm_on && ++b->heat == wasm_hot && !b->wasm_queued) wasm_queue(b);
    if (native_on && !b->nat && !b->nat_failed && !b->wasm_fn && ++b->heat >= native_hot) native_compile(b);
    const Uop* u = b->code.data();
    try {
        if (b->nat) {
            // limit 1: run this block, and not whatever it would chain to.
            uint32_t d;
            if (!native_run(b, ctx, 1, &d)) {
                std::exception_ptr e = nexc_;
                nexc_ = nullptr;
                std::rethrow_exception(e);
            }
            ctx.partial = static_cast<int>(d);
        } else if (b->wasm_fn) {
            // limit 1: run this block, and not whatever it would chain to.
            ctx.partial = reinterpret_cast<ChainFn>(static_cast<uintptr_t>(wasm_chain_fn))(ctx.env, &ctx, b->wasm_fn, 1);
        } else {
            while (u) u = u->fn(&ctx, u);
        }
    } catch (const GFault&) {
        --depth_;
        // Report the fault at the start of the instruction that made it, which
        // is where an exception handler would restart it.
        if (ctx.fault_rip) Glue::set_pc(cpu, ctx.fault_rip);
        else if (ctx.cur) Glue::set_pc(cpu, b->start + ctx.cur->pc);
        throw;
    } catch (...) {
        --depth_;
        throw;
    }
    Glue::settle(cpu);
    --depth_;
    const uint32_t done = ctx.partial >= 0 ? static_cast<uint32_t>(ctx.partial) : b->insns;
    Glue::add_icount(cpu, done);
    ++n_blocks_run;
    if (stats_every_ && n_blocks_run % stats_every_ == 0) print_stats();
    n_insns_native += done;
    return true;
}

void Engine::on_code_write(uint64_t page) {
    ++n_invalidated;
    unlink_all();   // a block that was invalidated may be the successor some exit points at
    auto it = by_page_.find(page);
    if (it != by_page_.end()) {
        for (Block* b : it->second) {
            if (!b->valid) continue;
            b->valid = false;
            auto m = map_.find(b->start);
            if (m != map_.end() && m->second == b) map_.erase(m);
            ++dead_;
        }
        by_page_.erase(it);
    }
    ++epoch;
    // A page that keeps being written to is data that happens to be executed
    // from, or code that rewrites itself in a loop; translating it again each
    // time costs more than interpreting it.
    if (++inval_count_[page] > 24) banned_.insert(page);
}

void Engine::on_code_unmap(uint64_t page) { on_code_write(page); }

void Engine::on_code_flush_all() {
    unlink_all();
    for (auto& kv : by_page_)
        for (Block* b : kv.second)
            if (b->valid) { b->valid = false; ++dead_; }
    by_page_.clear();
    // Stubs on unwatched pages are not in by_page_; drop them too.
    for (auto& b : all_)
        if (b->valid) { b->valid = false; ++dead_; }
    map_.clear();
    banned_.clear();
    inval_count_.clear();
    ++epoch;
}

}  // namespace jit

