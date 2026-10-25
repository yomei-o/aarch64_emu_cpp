// The translation cache and the loop that runs it.
//
// run_block() looks up (or translates) the block at the CPU's rip and runs it.
// It returns false when there is nothing to run there - the address is a host
// hook, the page is not allowed to be translated, or the first instruction is
// one the frontend will not touch - and the caller then steps the interpreter
// once, exactly as it would have without a JIT.
#pragma once

#include <cstdint>
#include <exception>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "glue.h"
#include "ir.h"

namespace jit {

class Engine;
struct Uop;
struct Ctx;
using WasmFn = int64_t (*)(uint8_t* env, Ctx* ctx);
using ChainFn = int (*)(uint8_t* env, Ctx* ctx, uint32_t fn, uint32_t limit);

struct Ctx {
    uint8_t* env;
    GCpu* cpu;
    GMemory* mem;
    Engine* eng;
    uint64_t epoch0;   // Engine::epoch when this block started
    int partial;       // set by an op that leaves early: native insns finished
    bool in_interp;    // an interpreted instruction is running
    const Uop* cur;    // the last op that could fault (memory access): where a fault happened
    bool cont;         // set by the "stop" op: a single op run by the wasm tier did not end the block
    int32_t cur_pc;    // (unused)
    uint32_t* pending_cell;   // wasm tier: a static exit that found no successor ready; C++ fills it in
    uint64_t fault_rip;       // wasm tier: guest address of the instruction in a slow memory access, or 0
    int nfault;               // native tier: a helper called from generated code caught an exception (Engine::nexc_)
    uintptr_t* npending;      // native tier: like pending_cell
};

struct Uop {
    const Uop* (*fn)(Ctx*, const Uop*);
    int32_t d, a, b, c;
    int64_t imm, imm2;
    uint32_t pc;
    uint16_t ni;
    uint8_t sz, cc, flags;
    uint8_t kind;   // OpKind, for the profile
};

struct Block {
    uint64_t start = 0;
    uint32_t insns = 0;
    bool valid = true;
    bool stub = false;       // nothing translated here: step the interpreter
    bool effects = false;    // see IrBlock::effects: cannot be run twice for verification
    uint32_t guest_bytes = 0;
    uint64_t page = 0;
    std::vector<Uop> code;
    uint64_t hits = 0;       // X86EMU_JIT_PROFILE: times this block ran
    uint32_t heat = 0;       // runs so far, for deciding when to compile it for the wasm tier
    // The wasm tier (backend_wasm.cpp): the IR, kept to compile from later; the
    // one-op programs that run the ops it does not translate itself; and the
    // function once it exists (a table index, 0 = none).
    std::vector<Op> ir_ops;
    std::vector<std::unique_ptr<Uop[]>> single;
    uint32_t wasm_fn = 0;
    bool wasm_queued = false;
    std::unique_ptr<uint32_t[]> cells;   // wasm tier: one word per static exit, see backend_wasm.cpp
    // The native tier (backend_native.cpp): the machine code, once there is some, and the
    // words its static exits jump through.
    const uint8_t* nat = nullptr;
    bool nat_failed = false;
    std::unique_ptr<uintptr_t[]> ncells;
};

class Engine : public GObserver {
public:
    Engine(GCpu& cpu, GMemory& mem);
    ~Engine() override;

    bool run_block();
    bool run(uint64_t deadline, uint64_t stop_pc, const bool* yield);

    // X86EMU_JIT_VERIFY=1: run every block twice - translated, then through the
    // interpreter from the same starting state - and stop at the first
    // difference (verify.cpp).
    bool verify = false;

    // CodeObserver
    void on_code_write(uint64_t page) override;
    void on_code_flush_all() override;
    void on_code_unmap(uint64_t page) override;

    // Where the cells translated code uses are (see glue.h).
    GuestSlots slots;

    // Counts invalidations.  A running block compares it with the value it
    // started with, which stays right when blocks nest (a hook that calls back
    // into the guest runs blocks of its own inside an interpreted instruction).
    uint64_t epoch = 0;

    // Statistics (X86EMU_JIT_STATS=1)
    uint64_t n_translated = 0, n_blocks_run = 0, n_insns_native = 0, n_invalidated = 0;
    uint64_t n_stub_hits = 0;
    uint64_t stats_every_ = 0;   // X86EMU_JIT_STATS=N prints every N blocks
    bool profile = false;        // X86EMU_JIT_PROFILE=1: count block runs, report the hot ones
    void print_profile();
    uint64_t n_interp = 0;
    uint64_t interp_ops[512] = {};   // which interpreted opcodes ran (0F xx at 256+xx)
    void print_stats();

    GCpu& cpu;
    GMemory& mem;

private:
    static constexpr uint32_t kTableBits = 13;
public:
    // The wasm tier.  Blocks that have run `wasm_hot` times are compiled, in
    uint32_t wasm_chain_fn = 0;              // table index of the function that runs a chain of blocks
    std::vector<uint32_t*> linked_cells_;    // exits that have been pointed at a successor
    void unlink_all() {
        for (uint32_t* c : linked_cells_) *c = 0;
        linked_cells_.clear();
        for (uintptr_t* c : nlinked_cells_) *c = 0;
        nlinked_cells_.clear();
        for (size_t i = 0; i < ind_.size(); i += 2) ind_[i] = ~uintptr_t(0);
    }
    // batches, into WebAssembly modules built at run time.
    void wasm_queue(Block* b);
    void wasm_compile_pending();
    bool wasm_on = false;
    uint32_t wasm_hot = 20000;   // below this, V8 runs the new code in its baseline tier, which loses to the threaded handlers
    uint32_t wasm_batch = 32;
    // The native tier: blocks that have run `native_hot` times get machine code, where the
    // host has a backend for it (x86-64 so far).
    bool native_on = false;
    uint32_t native_hot = 30;
    uint64_t n_native_blocks = 0;
    // Indirect branches (returns, computed jumps) from machine code look the target up here:
    // 4096 direct mapped entries of {guest address, code}; the engine fills them in.
    std::vector<uintptr_t> ind_ = std::vector<uintptr_t>(8192, ~uintptr_t(0));
    uint64_t native_gen = 0;      // counts the times all machine code was thrown away
    std::vector<uintptr_t*> nlinked_cells_;
    std::exception_ptr nexc_;     // what a helper called from generated code caught
    bool native_init();
    void native_compile(Block* b);
    void native_reset();          // forget all machine code (the arena is full)
    void native_shutdown();
    bool native_run(Block* b, Ctx& ctx, uint64_t limit, uint32_t* done);
    struct NativeState;
    NativeState* nat_ = nullptr;
    std::vector<Block*> wasm_pending_;
    uint64_t n_wasm_blocks = 0, n_wasm_modules = 0;
    uint64_t wasm_fallbacks[128] = {};   // ops the wasm tier runs through their threaded handler, by kind
    uint64_t generic_calls[128] = {};    // ...and how many times each was actually run that way

private:
    bool run_plain(Block* b);
    bool run_verified(Block* b);
    Block* lookup(uint64_t pc);
    Block* translate(uint64_t pc);
    void reclaim();

    Block* table_[1u << kTableBits] = {};
    std::unordered_map<uint64_t, Block*> map_;
    std::unordered_map<uint64_t, std::vector<Block*>> by_page_;
    std::unordered_map<uint64_t, uint32_t> inval_count_;
    std::unordered_set<uint64_t> banned_;
    std::vector<std::unique_ptr<Block>> all_;
    size_t dead_ = 0;
    int depth_ = 0;           // blocks running now; nothing is freed while > 0
};

// Per-guest-ISA translation.  The x86 one is the only implementation so far.
bool translate_block(GCpu& cpu, const GuestSlots& slots, uint64_t pc, IrBlock& out);
int32_t jit_generic(Ctx* c, const Uop* u);
void make_stop_op(Uop& u);
// Lowers IR to something runnable.
void compile_threaded(Engine& eng, const IrBlock& ir, Block& out);

}  // namespace jit
