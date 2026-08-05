// What the host has to do around a guest, shared by the two front ends.
//
// This exists because they drifted. `main.cpp` grew every piece of Darwin
// start-up as it was discovered -- the commpage, the thread pointer, dyld's API
// object, the ObjC image list, thread-local storage, the bootstrap port, the
// `ProgramVars` struct, the order initializers run in, the `exit` that flushes
// stdio -- and `web/wasm_api.cpp` grew none of it. The WebAssembly build could
// therefore run a freestanding Mach-O and not a real macOS one, and nothing said
// so: it simply stopped somewhere odd.
//
// Two functions, in the order they are used:
//
//   darwin_prepare()  everything that must be true before the first instruction
//   run_image()       initializers, +load, main, and the guest's own exit
#include "start.h"
#include <cstdio>

namespace a64 {

// Everything the host puts in place before a Darwin guest runs. Nothing here is
// optional: each line is a thing a real kernel or dyld does, and the comment on
// each says which failure it was found by.
void darwin_prepare(Cpu& cpu, Memory& mem, Syscalls& sys, const LoadedImage& img) {
    // A thread pointer for the main thread, before it runs its first instruction.
    //
    // On Darwin, xnu sets TPIDRRO_EL0 when it starts the thread, so `_pthread_self()`
    // works from the very beginning — and libsystem_kernel depends on it earlier than
    // anything else does: `cerror`, the error path every failing syscall goes through,
    // stores errno in the thread structure. The third syscall this guest makes is an
    // `access()` on a file that legitimately does not exist, so `cerror` runs 315
    // instructions in, long before libpthread has installed a real `pthread_t`.
    //
    // With permissive memory that wrote errno to address 8 and nothing said anything.
    // `--strict` reported it as the first thing it found. libpthread replaces this with
    // its own structure later; until then it only has to be real memory, 16-byte
    // aligned because the low bits of TPIDRRO_EL0 are the CPU number and get masked off.
    // The pointer lands in the *middle* of the region, because Darwin's thread pointer
    // points into the middle of `struct _pthread` — at the TSD array — and the header
    // fields are at negative offsets from it. Pointing at the base of a region made the
    // first write land 0xE0 bytes below it, which is how that came to be known.
    constexpr uint64_t kTsdBase = 0x0000'0003'0400'0000ull, kTsdSize = 128u * 1024;
    mem.map(kTsdBase, kTsdSize);
    cpu.tpidr_el0 = kTsdBase + kTsdSize / 2;
    sys.setup_commpage();
    sys.setup_dyld_apis(img.dyld_gapis);
    sys.set_objc_images(img.image_paths, img.image_headers);
    sys.set_image_segs(img.image_segs);
    sys.set_objc_opt_ro(img.objc_opt_ro);
    sys.set_prog_header(img.phdr_addr);
    sys.set_cache_range(img.cache_lo, img.cache_hi);
    sys.setup_tlv(img.tlv_images);
    // The bootstrap port, before the first instruction, because that is when a
    // real kernel provides it. Measured on a Mac: a plain `__attribute__((
    // constructor))` already sees `bootstrap_port = 0x807`, so it is there before
    // any initializer runs -- and several libraries read it long before libxpc's
    // initializer, which is the only thing in the guest that ever writes it.
    //
    // Leaving it zero is not inert. libsystem_info asks libnotify to register for
    // "com.apple.system.DirectoryService.InvalidateCache", libnotify reads this
    // global, and `bootstrap_look_up3(0, ...)` sends libxpc down its "we have a
    // bootstrap" branch and into a pipe it has not created -- a read of address
    // 0x1C, four million instructions into the stock macOS CPython.
    if (img.bootstrap_port_addr)
        mem.write<uint32_t>(img.bootstrap_port_addr, Syscalls::kBootstrapPort);

}

// The initializers, `+load`, `main`, and the guest's own `exit`. Returns the exit
// code. `trace` only controls the running commentary.
int run_image(Cpu& cpu, Memory& mem, Syscalls& sys, const LoadedImage& img,
              bool darwin, uint64_t start_pc, bool trace) {
    if (!img.initializers.empty()) {
        constexpr uint64_t kInitReturn = 0x0000'0000'DEAD'1000ull;
        const uint64_t sp0 = cpu.sp;
        const uint64_t argc_g = mem.read<uint64_t>(sp0);
        const uint64_t argv_g = sp0 + 8;
        const uint64_t envp_g = argv_g + (argc_g + 1) * 8;
        uint64_t apple_g = envp_g;
        while (mem.read<uint64_t>(apple_g)) apple_g += 8;
        apple_g += 8;

        // The fifth argument: `const ProgramVars* vars`. dyld passes it and libsystem_c
        // dereferences it immediately — `__libc_initializer` calls `__program_vars_init`,
        // which copies the five members into NXArgc, NXArgv, environ and __progname.
        // Passing four arguments left x4 holding whatever the last call had, and with
        // permissive memory a null read zeros: `environ` came out NULL, so every
        // `getenv` in the process answered "unset" and nothing said why. `--strict`
        // reported it as a read of address 8, five thousand instructions in.
        //
        //     struct ProgramVars { void* mh; int* NXArgcPtr; char*** NXArgvPtr;
        //                          char*** environPtr; const char** __prognamePtr; };
        //
        // The pointed-at words live next to the struct rather than on the stack,
        // because libsystem_c keeps the *pointers*, not copies, and the stack frame this
        // is built from is gone by the time anything reads them.
        constexpr uint64_t kVars = 0x0000'0003'0500'0000ull;
        uint64_t vars_g = 0;
        if (darwin) {
            mem.map(kVars, 4096);
            const uint64_t argv0 = mem.read<uint64_t>(argv_g);
            uint64_t progname = argv0;                  // dyld uses the last component
            for (uint64_t s = argv0; ; ++s) {
                const uint8_t c = mem.read<uint8_t>(s);
                if (!c) break;
                if (c == '/') progname = s + 1;
            }
            // The words the struct points at. When libdyld is loaded these are *its*
            // globals, because that is where they live on a Mac and every consumer --
            // libsystem_c's `environ`, libswiftCore's environment reader -- is bound
            // against that storage rather than handed a copy. The scratch words next
            // to the struct are only the fallback for a guest without libdyld.
            const uint64_t p_argc = img.prog_vars.argc     ? img.prog_vars.argc     : kVars + 0x30;
            const uint64_t p_argv = img.prog_vars.argv     ? img.prog_vars.argv     : kVars + 0x38;
            const uint64_t p_env  = img.prog_vars.env  ? img.prog_vars.env  : kVars + 0x40;
            const uint64_t p_prog = img.prog_vars.progname ? img.prog_vars.progname : kVars + 0x48;
            mem.write<uint32_t>(p_argc, static_cast<uint32_t>(argc_g));
            mem.write<uint64_t>(p_argv, argv_g);
            mem.write<uint64_t>(p_env, envp_g);
            mem.write<uint64_t>(p_prog, progname);
            mem.write<uint64_t>(kVars + 0x00, img.phdr_addr);   // the mach_header
            mem.write<uint64_t>(kVars + 0x08, p_argc);
            mem.write<uint64_t>(kVars + 0x10, p_argv);
            mem.write<uint64_t>(kVars + 0x18, p_env);
            mem.write<uint64_t>(kVars + 0x20, p_prog);
            if (trace)
                std::fprintf(stderr, "[mac] crt globals: NXArgc %llX NXArgv %llX "
                                     "environ %llX __progname %llX\n",
                             static_cast<unsigned long long>(p_argc),
                             static_cast<unsigned long long>(p_argv),
                             static_cast<unsigned long long>(p_env),
                             static_cast<unsigned long long>(p_prog));
            vars_g = kVars;
        }
        for (size_t k = 0; k < img.initializers.size(); ++k) {
            // Which initializer is running, when asked. Order matters here and is not
            // derivable from the dependency graph alone -- dyld runs libSystem's
            // first, and an initializer that calls atexit before malloc is up gets a
            // null and asserts inside libsystem_c, naming neither itself nor the
            // ordering.
            if (trace)
                std::fprintf(stderr, "[init] %zu/%zu at %012llX\n", k + 1,
                             img.initializers.size(),
                             static_cast<unsigned long long>(img.initializers[k]));
            cpu.sp = sp0;
            cpu.pc = img.initializers[k];
            cpu.setx(0, argc_g);
            cpu.setx(1, argv_g);
            cpu.setx(2, envp_g);
            cpu.setx(3, apple_g);
            cpu.setx(4, vars_g);
            cpu.setx(30, kInitReturn);
            cpu.run_until(kInitReturn);
            if (cpu.halted) break;

        }
        // Every image's `+load`, now that the libraries are up. libobjc handed the
        // callback over during its own initializer and this is where dyld runs it;
        // running it there instead put Foundation's `+load` on top of a libSystem
        // initializer that was still part-way through. See darwin.cpp, `case 107`.
        if (!cpu.halted) sys.run_objc_load_images();
        cpu.sp = sp0;
        cpu.pc = start_pc ? start_pc : img.entry;
    }
    // An LC_MAIN entry point is `main`, and dyld's start calls `exit(main(...))`. The
    // host is standing in for that start, so it has to do the same: give `main` a
    // return address it can be recognised by, and when it comes back, call the guest's
    // own `exit` with the result.
    //
    // Skipping it is not just a wrong status code. `exit` is what flushes stdio, so a
    // guest that printed and returned normally produced **no output at all** — and the
    // symptom was the emulator stopping at the *initializer* sentinel, because x30 still
    // held whatever the last initializer ran with. That looked like a control-flow bug in
    // the host and was really "main returned and nobody was there to catch it".
    constexpr uint64_t kMainReturn = 0x0000'0000'DEAD'3000ull;
    if (darwin) cpu.setx(30, kMainReturn);
    cpu.run_until(kMainReturn);
    if (!cpu.halted && cpu.pc == kMainReturn && img.exit_fn) {
        if (trace)
            std::fprintf(stderr, "[main] returned %d; calling exit at %012llX\n",
                         static_cast<int>(cpu.xr(0)),
                         static_cast<unsigned long long>(img.exit_fn));
        cpu.pc = img.exit_fn;
        cpu.setx(30, kMainReturn);          // exit does not return; if it does, stop
        cpu.run_until(kMainReturn);
    }

    return cpu.exit_code;
}

}  // namespace a64
