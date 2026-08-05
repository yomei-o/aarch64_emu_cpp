# Where this is, and what to do next

Working notes for picking the project back up. The README says what the emulator
*is*; this says what is unfinished and what is known about it.

## Handoff — start here

**Everything needed is in the repository. No Mac is required to continue.**

    git pull
    sh build.sh
    sh prebuilt/unpack.sh                # both macOS guest trees, 88 MB packed
    ./aarch64emu --root guests/macos guests/macos/hello

**That prints `hello from real macOS`.** 199,279 instructions of Apple's own arm64 code, from
a real Mac's shared cache, on an x86 host. The libraries load and link, the emulator does
dyld's job, initializers run in dyld's order, libSystem comes up over Mach IPC and the
commpage, libobjc realizes its classes out of the cache's preoptimized tables, libxpc
initialises over a bootstrap port, libcorecrypto runs AES on the emulated crypto
instructions, and `main` returns to the host, which calls the guest's `exit` — the thing
that flushes stdio, and without which the program printed nothing at all.

The macOS milestone is **met**. What is left on that side is breadth rather than a wall.

**Where this is (2026-08-05, third pass).** The goal it was aimed at is met:

    sh prebuilt/unpack.sh
    ./aarch64emu --root guests/macos guests/macos/hello
    hello from real macOS

    ./aarch64emu --dyld-sections --root guests/macos_py \
        guests/macos_py/install/bin/python3.13 -c \
        "import sys, platform, hashlib
         print(sys.version.split()[0], platform.machine(), sys.platform)
         print(hashlib.sha256(b'aarch64_emu_cpp').hexdigest())"
    3.13.14 arm64 darwin
    bffb6fd92e8571ee9842b4be91c59556fa99d85a203350610620d876755b4110

Apple's own CPython, on Apple's own libraries, on an x86 host — and in a browser tab,
at <https://yomei-o.github.io/aarch64_emu_cpp/>. The digest is the host's digest of
the same bytes, which is what `tests/run_macos.sh` now checks.

`--dyld-sections` is **not optional for anything but `hello`**. Without it libobjc
never reads the shared cache's preoptimized class tables, and libxpc fails its own
type check ("API Misuse: Messages must be dictionaries") long before Python starts.
It is still off by default on the command line because the load-command fallback is
what the recorded `hello` instruction count is measured against; the wasm build turns
it on unconditionally.

**The last wall was one decoder bug, and it is the one to remember.** `STLUR`
(ARMv8.4 store-release, unscaled offset) shares bits 29..27 with `LDR (literal)` and
differs only in **bit 24**, which the literal case did not test. So

    stlur wzr, [x19, #0x10]

decoded as a load into the zero register: an instruction that read an unrelated
address and threw the result away, silently. CPython's `create_gil` ends with

    gil->last_holder = NULL;   // str   -- happened
    gil->locked = 0;           // stlur -- did not

and `locked` starts at -1 meaning "no GIL yet". So the GIL was created and still
looked uncreated; `take_gil` waited for a holder that could not exist, timed out
forever, and eventually dereferenced a null `last_holder`. **Five million
instructions of ObjC, XPC and CoreFoundation start-up were debugged before this, all
of them working correctly.** Everything in this file's design — refuse the unknown,
never no-op — exists because of failures shaped like that one.

Three more from the same stretch, each found by the guest saying so:

- **`main` was called without its arguments.** An LC_MAIN entry point *is* `main`,
  and dyld's start loads argc/argv/envp/apple into registers. Leaving them alone
  worked for `hello`, which ignores them, and made CPython see no `-c`, fall through
  to the REPL, read EOF and exit 0 having printed nothing.
- **The bootstrap port is handed over at exec.** Measured on a Mac with a five-line
  probe: a plain `__attribute__((constructor))` already sees `bootstrap_port = 0x807`.
  Nothing in the guest sets it that early, so the host writes it into
  libsystem_kernel's global before the first instruction. Leaving it zero sent
  libnotify into libxpc's "we have a bootstrap" branch and a null pipe.
- **`load_images` was being called far too early.** `map_images` must run
  re-entrantly inside libobjc's registration; `+load` must not. Running it there ran
  Foundation's `+load` on top of a libSystem initializer that was still part-way
  through, which is how the null pipe was reached at all. dyld runs `+load` once the
  libraries are up, and so does `run_image()` now.

**Threads and child processes (2026-08-05, fourth pass).** Both were asked for as the
step before running gcc, and both work on both personalities now.

    # four threads and a mutex, in Apple's CPython
    ./aarch64emu --dyld-sections --root guests/macos_py \
        guests/macos_py/install/bin/python3.13 -c \
        "import threading; ..."          # -> 15005000

    # Apple's CPython spawning Apple's CPython
    ./aarch64emu --dyld-sections --root guests/macos_py \
        guests/macos_py/install/bin/python3.13 -c \
        "import subprocess
         print(subprocess.run(['/install/bin/python3.13','-c','print(6*7)'],
                              capture_output=True).stdout)"   # -> b'42\n'

Both are in `tests/run_macos.sh` (12 cases) and the Linux equivalents are in
`tests/run_python.sh` (8).

### fork, and why it needs no host fork and no copied address space

This was asked directly and the answer is worth keeping. `fork` is entirely internal:
nothing here calls the host's. What a parent requires is only that the child cannot
affect its memory -- and the pages a child touches between fork and exec are a
handful. So `Memory::begin_journal()` records each page's previous contents on its
first write and `rollback_journal()` puts them back. The cost is the pages written,
not the hundreds of megabytes a CPython address space occupies.

`src/process.cpp` has the model in full. The shape:

    fork      save the registers, the descriptor table (copied) and open a journal;
              the child continues in place seeing 0 in x0
    execve    load and run the new program to completion in a *fresh* Memory, then
              stop the run loop
    resume    restore the registers, the descriptor table and the journal; the
              parent's fork() returns the child's pid
    wait4     the status is already on hand

**What is still not supported**, and is reported rather than faked: a child that runs
*concurrently* with its parent. A pipeline where the writer must be scheduled while
the reader blocks cannot work. The pipe buffer is unbounded so the common shape --
child writes, exits, parent reads -- does, and `Files::Pipe` says why. Making the two
concurrent means a process table and a scheduler over it, which is the next real
piece of work if something needs it.

### Bugs from this stretch worth not rediscovering

Every one of these failed *silently*:

- **The psynch syscall numbers.** 301 mutexwait, 302 mutexdrop, 303 cvbroad,
  **304 cvsignal**, 305 cvwait. cvsignal was answered at 303, so a signal woke nobody
  and `Thread.join()` hung with no diagnostic.
- **execve is Darwin syscall 59**, not 147 (that is `setsid`). A scan of `_execve`
  returned 147 because the stub begins with a branch through an interposable slot
  rather than `movz x16`, so the scan over-ran into the next symbol. **The number the
  guest issues is the one to trust** -- `--trace-sys` prints it.
- **Darwin's `fork` returns a flag in x1** as well as the pid in x0, and the **carry
  flag** is how Darwin reports failure. The parent's context is saved inside the fork
  syscall, before the tail clears the carry, so a carry left set by the child made
  libsyscall read the child's pid as an errno: "[Errno 2000] Unknown error: 2000".
- **The descriptor table is copied at fork; the pipes are shared.** Sharing the table
  left the *parent* with fd 1 pointing at a pipe after the child was gone.
- **fd 0..2 are the console only until something redirects them.** `sys_write` sent
  fd 1 to the terminal regardless, so a child's output appeared on screen while its
  parent read an empty pipe.
- **`prlimit64` answering EINVAL** made `_posixsubprocess` close every descriptor from
  3 to twenty million before each exec. `close_range` is implemented too.
- **A thread is CLONE_VM *and* CLONE_THREAD.** musl's `posix_spawn` passes
  CLONE_VM|CLONE_VFORK, which is not a thread.

### gcc: works, end to end (2026-08-05, fifth pass)

Alpine's aarch64 packages give a real toolchain with no Mac and no cross-compiler:

    for p in binutils-2.42-r1 gcc-13.2.1_git20240309-r1 musl-dev-1.2.5-r3 \
             musl-1.2.5-r3 libgcc-13.2.1_git20240309-r1 gmp-6.3.0-r1 mpc1-1.3.1-r1 \
             mpfr4-4.2.1-r0 zlib-1.3.1-r1 isl26-0.26-r1 zstd-libs-1.5.6-r0 \
             jansson-2.14-r4; do
      curl -sLO "https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/$p.apk"
      tar xzf "$p.apk" -C guests/gccroot
    done
    # Windows tar writes apk symlinks as nothing at all, so the sonames the
    # loader asks for (libgmp.so.10, libzstd.so.1, ...) have to be *copies* of
    # the real files. `ls guests/gccroot/usr/lib` and copy whatever lacks its
    # unversioned soname.

    ./aarch64emu --root guests/gccroot guests/gccroot/usr/bin/gcc /hello.c -o /hello
    ./aarch64emu --root guests/gccroot guests/gccroot/hello
    hello from emulated gcc

**The whole pipeline runs**: the driver forks and execs cc1, as, collect2 and ld --
four child processes, pipes, temp files -- and the binary it links *runs under the
same emulator that built it*. `tests/run_gcc.sh` (3 cases) closes that loop and
skips itself when the ~120 MB toolchain tree is absent.

Three bugs stood between "spawns cc1" and this, all worth remembering:

- **musl's ld.so tells libraries apart by st_dev/st_ino.** fill_stat answered
  (1,1) for every file, so the first library loaded stood in for all five and
  relocation failed with `__gmpz_get_si: symbol not found` against a libgmp that
  was present and correct. The inode is now an FNV hash of the host path.
- **cc1 installs a SIGILL handler**, so an unimplemented instruction no longer
  stops the machine -- it becomes "internal compiler error: Illegal instruction"
  with no PC. `--trace-sys` prints the `[sig]` delivery line; the faulting PC in
  it is the instruction to go implement. That is how the three below were found.
- **The instructions cc1 actually needed**: `uaddlp` (vector pairwise widening
  add), scalar `cmge/cmgt/cmle/cmeq #0`, scalar `add d0, d0, d1` (three-same,
  size==11), vector `abs/neg`. All popcount/hash-loop shapes. And the vector
  zero-compare opcode table was wrong -- opcode 8 is CMGT/CMGE, 9 is CMEQ/CMLE,
  A is CMLT; the old table answered different questions than were asked.

### Also still open

- **`sysctl {1,14,1,pid}`** (KERN_PROC_PID, a `kinfo_proc`). Nothing has needed it.
- **`posix_spawn`** on Darwin (syscall 244) is unimplemented. It is no longer *needed*
  now that fork works, but it is the path a guest that avoids fork would take.
- **Speed.** ~15M instructions/sec on the macOS guest against ~41M on Linux ones; the
  difference is the ObjC-heavy start-up, not the core. A decode cache keyed on the PC
  is the standing idea -- measure first.
- The dyld API slots still answered with zero on the CPython guest: 1, 8, 10, 12, 13,
  44, 49, 51, 52, 54, 59, 60, 82, 90, 97, 121. None has been shown to matter.

Builds with **g++, clang or MSVC** (`CXX=cl sh build.sh`); the two compilers agree byte for
byte over the whole macOS run, which is the best differential oracle here for anyone
without a cross-compiler.

Run the six suites before touching anything — they should be 9 / 11 / 9 / 8 / 11 / 3, plus 8
for `node web/test_node.mjs` if emscripten is around:

    sh tests/run_tests.sh    sh tests/run_macho.sh
    sh tests/run_busybox.sh  sh tests/run_python.sh
    sh tests/run_macos.sh    sh tests/run_gcc.sh

`EMU` is overridable, which is how the strict sweep is run and how a second build is
compared:

    EMU="./aarch64emu --strict" sh tests/run_busybox.sh

**Two of the five need only a download, not a cross-compiler**, which matters on a host
without one — `run_tests.sh` and `run_macho.sh` build their guests with
`clang --target=aarch64…`, but busybox and CPython are prebuilt binaries:

    cd guests
    curl -Lo bb.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-1.36.1-r31.apk
    tar xzf bb.apk && mv bin/busybox.static busybox
    curl -Lo py.tgz https://github.com/astral-sh/python-build-standalone/releases/download/20260728/cpython-3.13.14%2B20260728-aarch64-unknown-linux-musl-install_only_stripped.tar.gz
    mkdir -p sysroot/opt && tar xzf py.tgz -C sysroot/opt
    curl -Lo musl.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/musl-1.2.5-r3.apk
    tar xzf musl.apk -C sysroot

Those 20 tests are enough to work on any of this: they are
differential against the host's own tools, and between them they cover the integer core, the
SIMD groups, threads, dynamic linking and both personalities. They are also how a
compiler-portability change gets checked, since cl.exe and clang must agree.

The tools built for this, all of which take addresses straight out of a trace:

    --trace-sys              syscalls, Mach traps, MIG routines, dyld slots,
                             [init]/[objc]/[call]/[thr]
    --sample N               print the PC every N instructions
    --watch LO:HI            log every guest access in a range, with the PC
    --pcwatch ADDR           at a guest function's entry: x0..x5 with any strings they
                             point at, then x19..x28 and sp on a second line
    --dyld-sections          answer dyld's section-location API (see item 1; off by default)
    --setenv NAME=VALUE      extra guest environment, repeatable (for OBJC_PRINT_*)
    --macho-info FILE [sym…] what a Mach-O contains; look symbols up in its export trie
    tools/whichlib.py        address -> library and nearest symbol
    tools/dis_macho.py       disassemble at a virtual address in a cache-extracted library
    tools/dyld_slots.py      names 98 of dyld's API vtable slots
    tools/profile_pcs.py     a --sample trace -> a per-function profile
    --list-unresolved        every unresolved symbol, not the first forty
    --list-images            every image the loader actually mapped, and stop
    tools/dsc_extract.c      re-extract from a Mac's shared cache (only if the OS changes)
    guests/macos/build.sh    build a new macOS guest with clang+lld, no Mac and no SDK
    guests/macos/stub_libs.sh  stand-in dylibs for libraries not yet extracted

Two habits this project runs on, both earned the hard way and both worth keeping:

- **The guest usually names its own problem.** Every wall since the loader was diagnosed
  by a message libSystem, libpthread or libobjc printed itself, once `write` worked. When
  something fails silently, the first move is to find the string the code stashes before
  it aborts (`--watch` a wide range, filter to accesses where the address is not the PC).
- **Measure instead of reasoning about which structure "should" hold the value.** Three
  separate rounds were lost to plausible explanations of a zero. `--watch`, `--dump` in
  dsc_extract, and `profile_pcs.py` all exist because of that.

The Linux side (CPython 3.13, threads, WebAssembly) is finished and green; nothing below
touches it.

## The goal

Run a **stock CPython for ARM Linux, and then for Apple Silicon, on an x86 host and
in a browser** — the mirror image of x86_emu_cpp, which runs x86 guests on ARM.
Everything below is ordered by what that needs.

## State (verified against the host, not against expectations)

Five suites. Four are differential — the oracle is the host, never a recorded file. The
fifth cannot be: no x86 host can run Apple's arm64 libraries, so it checks the macOS guest
against *itself* under two memory modes, which turns out to be a sharp test (see below):

    sh tests/run_tests.sh      9 passed   freestanding C, built twice and diffed
    sh tests/run_macho.sh     11 passed   the same sources as arm64 Mach-O, plus a dylib
                                          linked both ways: chained fixups and the older
                                          LC_DYLD_INFO opcode programs
    sh tests/run_busybox.sh    9 passed   Alpine's static aarch64-musl busybox
    sh tests/run_python.sh     8 passed   CPython 3.13, dynamically linked, and a
                                          child process through fork/exec/pipe/wait
    sh tests/run_macos.sh     11 passed   the macOS guests: hello, threads, tls, files,
                                          and Apple's CPython -- its digest against the
                                          host's, its threads, and a child process
    sh tests/run_gcc.sh        3 passed   Alpine gcc compiles and links a program and
                                          the emulator runs the result (skips without
                                          the ~120 MB toolchain tree)
    node web/test_node.mjs     8 passed   the same guests under WebAssembly

What works:

- The A64 integer core, branches, every load/store addressing mode, and the system
  registers a userland guest reads.
- FP and Advanced SIMD: scalar arithmetic/compare/convert/round/FMADD; the vector
  three-same, three-different, two-misc, across-lanes, permute and shift groups;
  DUP/INS/UMOV/SMOV, EXT, TBL/TBX, MOVI, XTN, REV, PMULL; LD1-LD4 including
  de-interleaving, LD1R and the single-lane forms; the narrowing right shifts and the
  accumulate/round/insert shifts; MUL/PMUL, MLA/MLS, SABA, and the saturating and halving
  add/subtract. **SHA1, SHA256 and AES** are implemented exactly, in `crypto.cpp`, because
  hashlib and libcorecrypto use them for real — the AES S-box is *generated* from its
  definition rather than transcribed, and the primitives are checked by composing them into
  AES-128 and comparing against the FIPS-197 vector.
- **Dynamic linking** by running the guest's own `ld.so`: map the program, map the
  interpreter, start at the interpreter's entry with AT_BASE/AT_ENTRY set. This
  needed a real mmap — MAP_FIXED honoured, file mappings at their offset, zero-fill
  past EOF.
- **Signal delivery**: an AArch64 signal frame, SIGILL for an unimplemented
  instruction or system register, and `rt_sigreturn`.
- A file layer with directory descriptors and `getdents64`, and the syscalls
  busybox and CPython need.
- **Mach-O and Darwin.** `macho_loader.cpp` handles `LC_SEGMENT_64` / `LC_MAIN` /
  `LC_UNIXTHREAD` and skips `__PAGEZERO`; `darwin.cpp` is the BSD syscall table
  plus the cheap Mach traps, reached through `svc #0x80`.
- **Dynamic linking on Darwin, with the emulator playing dyld** (`macho_dyld.cpp`):
  dependency loading, `LC_DYLD_CHAINED_FIXUPS` (rebases and binds), and export-trie
  symbol resolution. Apple's dyld cannot be shipped, so unlike the Linux side there
  is no real loader to run. Both run under WebAssembly too.
- **Threads.** `clone`, `futex`, a round-robin scheduler with preemption, and a
  real exclusive monitor. CPython's `threading`, `queue`, `Event` and
  `ThreadPoolExecutor` all work — including inside WebAssembly, on one wasm
  instance, with no `SharedArrayBuffer` and no COOP/COEP.
- **Threads and child processes on both personalities.** `bsdthread_create`,
  `__ulock_wait`/`wake` and the psynch condition variables on Darwin; `clone`, `futex`
  and a real exclusive monitor on Linux. `fork`/`execve`/`wait4` and pipes on both,
  with the parent's memory protected by an undo journal rather than a copy -- see
  `src/process.cpp`.
- **WebAssembly** (`web/`), running all of the above, and a browser demo with five
  guests at <https://yomei-o.github.io/aarch64_emu_cpp/>.

## ⏭ Next, in order

1. ✅ **A real macOS binary runs.** `hello from real macOS`, 199,279 instructions, exit 0 — the
   same count with `--strict`.
   The account of how the last walls fell is in "How the macOS milestone was reached" below,
   because every one of them was a case of the host telling the guest something almost true.

   What is left on that side is breadth, not a wall:

   - ✅ **A guest that does more than print, built with no Mac.**
     `sh guests/macos/build.sh threads` compiles `threads.c` with clang and links it
     with `lld -flavor darwin` against the extracted libraries in this tree — no Apple
     SDK, no headers, because the guest declares its own prototypes. Both halves are
     verified now: an ordinary LLVM release has the AArch64 target (only the
     emscripten clang does not), and the link names **every** `usr/lib/system/*.dylib`
     rather than libSystem alone, because lld does not follow libSystem's re-exports
     out of an extracted tree — `printf` happens to live in libsystem_c and linked,
     `pthread_mutex_lock` did not. Output is arm64 and not arm64e on purpose: the
     libraries are arm64e and linking against them is fine, but an arm64e *output*
     carries `DYLD_CHAINED_PTR_ARM64E` fixups, which are item 2 below.

     The next interesting guest is one that uses Foundation, which needs
     CoreFoundation and Foundation extracted.
   - ✅ **`--strict` is clean on this guest.** Permissive and strict now run the *same*
     199,279 instructions, which is the result worth stating: no path through this guest
     depends on reading unmapped memory. Getting there from the one remaining finding — an
     unmapped read at address 0x10, 138,000 instructions in — went through three separate
     gaps, each hidden behind the last, and the middle one was the interesting one:

     1. **dyld API slot 12 answers through an out-parameter, not just x0.** libsystem_c's
        `_os_assumes_log` does `add x1, sp, #0x30`, then hands `[sp, #0x38]` to
        `_os_get_image_uuid` as a mach_header and `[sp, #0x30]` to `strrchr(…, '/')`. So x0
        is a success flag and the buffer at x2 is `{path, header}`. The shape was read off
        the caller rather than guessed: each version moved the fault a measurable distance
        further along, which is what said the previous guess was only half right.
     2. **`environ` was null.** `NXArgc`, `NXArgv`, `environ` and `__progname` live in
        *libdyld.dylib* on a Mac, and dyld writes them before any initializer runs.
        libsystem_c's `environ` and libswiftCore's environment reader are binds against
        that same storage, not copies of it — so filling in a private `ProgramVars` struct,
        which is what this did, satisfies libsystem_c's copy and nothing else. Every
        `getenv` in the process answered "unset", and libswiftCore's
        `runtime::environment::initialize` read `environ[0]` through a null pointer. The
        loader now reports where libdyld's four globals are and `ProgramVars` points at
        them. This one had been mis-diagnosed as fixed once already: an earlier pass added
        `ProgramVars` and stopped there, because the guest printed.
     3. Paths handed to the guest are `const char*` into guest memory, so
        `image_path_addr` copies the host's `std::string`s in on demand.

     Worth recording what was *not* the fix: closing every remaining syscall the trace
     named on this guest — `csops`, `csops_audittoken`, `csrctl`, `shm_open`,
     `getattrlist`, `socket`, and sysctl's `name2oid` form with the five names it asks for
     — changed the fault by 15 instructions. They are all implemented now and the trace is
     silent, but the temptation to claim them as the cause was real and the instruction
     count is what refused it.
   - **The dyld API slots still answered with zero** are down to two on this guest, and
     both are deliberate:

     ✅ **`_dyld_lookup_section_info` (111), 186 calls — implemented, behind
     `--dyld-sections`, and this is where to pick the project up.** The frontier moved: with
     it on the guest gets 86,000 instructions past where the whole run used to end, into
     libobjc using the cache's preoptimized class layout for real, and stops at a null
     function pointer nobody has looked at yet.

     The blocker was the `_dyld_section_location_kind` enum: kind is a number, a wrong
     mapping returns some *other* section's contents, and nothing about that looks like a
     failure. It is now measured, not recalled, and the trick was that **the caller names
     the kind**: libobjc has a separate method per section, and x30 plus
     `tools/whichlib.py` reads them straight out of a trace. Reproduce with

         ./aarch64emu --trace-sys --root guests/macos guests/macos/hello 2>&1 \
           | grep "slot 111" | sed 's/.*called from \([0-9A-F]*\) .*x3=\([0-9A-F]*\).*/\1 kind=\2/' \
           | sort | uniq -c

     and put each address through `tools/whichlib.py guests/macos ADDR`:

         kind  section              proved by
          3    __swift5_replace     libswiftCore addImageCallback2Sections<…,Li3E,Li4E>
          6    __objc_imageinfo     _map_images_nolock, for every image
          7    __objc_selrefs       header_info::selrefs
         12    __objc_classlist     header_info::classlist
         13    __objc_nlclslist     header_info::nlclslist *and* _load_images+76
         17    __objc_nlcatlist     _load_images+104, right after the non-lazy classes
         18    __objc_protolist     header_info::protocollist

     Seven values, and they cross-check: 13 arrives from two unrelated callers, the Swift
     one appears as a *template argument* (`Li3E`) in the mangled name, and all seven fall
     exactly where dyld's enum puts them (0–5 the swift5 sections, 6 objc_imageinfo, then
     the __DATA ones from 7). Those seven cover all 186 calls on this guest, so answering
     only the measured kinds and returning false for the rest gives up nothing — and
     returning false stays correct, because libobjc then walks the load commands itself.

     **The argument layout took two readings.** The first was wrong in the usual way: x4
     and x5 look exactly like `uint64_t* offset, uint64_t* size`, and they are not
     out-parameters at all. They hold `stubs + 111*16` and `vtable + 111*8` — this slot's
     own stub and its own vtable entry, left behind by the caller's dispatch on the way in.
     Which settles the signature by elimination: the caller clobbered x4 and x5 getting
     here, so **nothing can be passed in them**, and the only arguments are x1 (the
     mach_header), x2 (a per-image handle dyld precomputes, often 0) and x3 (the kind). The
     answer therefore comes back as a **16-byte return in x0:x1** — the section's address
     and its size — and x0 has to be an *address*, because a zero x0 is what has been making
     libobjc fall back all along. An offset from the header would make zero mean "the
     header", and no section is there.

     **It is implemented, and it is behind `--dyld-sections`, off by default.** Run

         ./aarch64emu --dyld-sections --root guests/macos guests/macos/hello

     and this is where to pick the project up. With it on, libobjc stops walking load
     commands and starts *using* the shared cache's preoptimized class layout for real: the
     run gets 86,000 instructions further and then branches through a null function pointer
     — PC 0 at 285,669 instructions, against 199,279 for the whole run with the fallback.
     That is new territory rather than a regression in this slot, and both compilers agree
     on the number to the instruction, which is the usual sign the emulator is being
     deterministic about it. It is a run that does not finish, so it cannot be the default.

     Two things to know before starting. The section addresses it hands back are checkable
     and were checked — `--trace-sys` prints every one (`[mac] section info: …`), and they
     land inside the right images with sizes that are multiples of 8. And turning it on
     immediately uncovered a *missing instruction*: **PACGA**, the generic
     pointer-authentication MAC, which libobjc uses on its method caches. That is now
     implemented (see the note in `cpu.cpp`: it is the one PAC instruction the identity
     treatment does not fit, because there is no pointer to leave alone — what it needs is a
     deterministic non-zero mix, since a generic MAC is only ever checked by the code that
     made it).

     It costs 16% of the run, which is the only reason to want it, and item 4 is a better
     lever on the same problem.

     Slot 97, 18 calls from libobjc. Answering zero is not visibly wrong; it has not been
     identified because nothing has gone looking.

2. **arm64e chained pointers.** Only `DYLD_CHAINED_PTR_64` and `_64_OFFSET` are
   implemented. Cache libraries do not use them (they are pre-linked), so this has
   not yet bitten; a third-party arm64e dylib would. The emulator can ignore the
   signature — PAC is the identity here — but must read the different bit layout.
   Currently refused loudly.
3. **A trimmed Python for the browser demo.** The page can run CPython today, but the
   guest tree is 45 MB into MEMFS. Dropping the stdlib to what a script actually
   imports would make a shippable Pages demo.
4. **Speed.** ~48M instructions/sec interpreted where that was measured; **41.4M/s** on the
   host this was last checked on (clang -O2, 393,385,201 instructions in 9.5 s — CPython
   summing `i*i` over 200,000 iterations, which is a useful benchmark because the answer is
   checkable: 2666646666700000, the same as the host's own Python). A decode cache keyed on
   the PC (the instruction word is fixed-width, so a table of decoded handlers is cheap) is
   the obvious next step if it ever matters, and it is a real refactor of `step()` rather
   than a local change — worth measuring where the time actually goes first.
5. ✅ **`--strict` memory** is in. Unmapped guest reads and writes stop the run and name the
   address instead of reading zero and allocating. It found two bugs in the first 5,000
   instructions of the macOS guest the day it was written (the missing thread pointer and the
   missing `ProgramVars`), and both Linux suites pass under it, which says the Linux side
   makes no wild accesses at all. Only *guest* accesses are checked; `Memory::map()` is how
   the host declares the regions it synthesises.

## How the macOS milestone was reached, in the order it was needed

Kept because every one of these was invisible until the guest was several hundred
instructions past it, and each looked like a different problem than it was.

- **`dsc_extract`, a shared-cache extractor.** Cache dylibs are pre-linked at fixed
  addresses, so pulling out a library's segments and keeping their addresses is
  enough to run it. Only the *file* layout has to be repaired.
- **The symbol table is shared.** Each dylib's LC_SYMTAB has its own symoff/nsyms but
  a stroff into one common pool, with strsize covering the whole thing — so copying
  strsize copied the names of every symbol in macOS, once per library, producing
  434 MB dylibs. Rebuilt per library instead.
- **Never hold a pointer into a growing buffer.** `dst->symoff = ob_put(...);
  dst->stroff = ob_put(...);` loses the second write when the realloc moves the
  buffer, leaving the cache's offset in the field. libSystem survived it; libxpc came
  out claiming a 445 MB string table at offset 2.2 GB.
- **Data pointers in the cache are not pointers.** They are packed
  `dyld_cache_slide_pointer` values in per-page chains, rewritten by the kernel at map
  time. Sequoia's arm64e cache uses **slide info version 5** (v3 was implemented
  first, and the version check skipped the rest): a 34-bit offset relative to
  `value_add`, with the chain step at bits 52..62 rather than 51..61.
- **A heuristic cannot check that.** An authenticated packed slot hides behind a
  16-bit diversity field and a plain one reads as an ordinary small integer. The
  residual-scan check found 9 of 9334. Count what the slide walk *rewrote* instead.
- **libSystem exports libc by re-exporting**, and contains almost no code — so a
  symbol lookup that stops at the named library finds nothing. Also: a chained
  import's `lib_ordinal` indexes *every* dylib-referencing load command in order, and
  omitting LC_REEXPORT_DYLIB/LC_LOAD_UPWARD_DYLIB renumbers the rest.
- **The closure needs bounding.** Following every edge from libSystem gives 477
  libraries and 784 MB, through one chain: libxpc → libobjc (upward), XPCSupport
  (weak), CoreFoundation (plain) → everything. Not following weak or upward, and
  filtering to `/usr/lib/`, gives 39 libraries and 8.4 MB.
- **GOT islands.** The cache coalesces GOT entries into pages belonging to no dylib.
  Collecting "every rebased page no extracted library owns" gives 301 MB of other
  libraries' data; collecting the pages the extracted *code* names — found by scanning
  for ADRP, per instruction-flagged **section**, because `__cstring` decodes as
  plausible ADRPs — gives a few hundred KB.
- **The commpage**, at `0xF_FFFF_C000` *and* a read-only copy 32 KiB below since macOS
  13. libsyscall builds `vm_page_size` from the page shift in it, so an absent
  commpage means a page size of zero and every allocation rounding to nothing.
- **ARMv8.1 LSE atomics**, all of them — Apple's libraries use CAS/SWP/LD<op> rather
  than LDXR/STXR loops.
- **PAC**, as the identity.
- **Mach VM traps**, because libmalloc builds its zones through them. They return a
  `kern_return_t` in x0 and do *not* use the carry flag, unlike the BSD calls.
- **Image initializers**, in post-order, before the entry point. Without them the
  guest reaches printf and branches through a null 57 instructions in.
- **The cache's patch table**, for the GOT slots it deliberately leaves null. Worth
  three notes: the walk was correct on the first attempt (the table carries symbol
  names, so a run that prints a few of them proves it); a fixed cap of 65536 collected
  locations against 3.65 *million* in the table stopped inside libobjc and never
  reached the library it was being read for; and it has to run *after* the dependency
  closure so it can be filtered to the libraries being written out.
- **A page can be part-owned.** The cache packs several libraries' small
  `__DATA_CONST` segments into one 16 KiB page, so "skip any page overlapping an
  extracted library" discards the rest of that page. `&mach_task_self_` was in the
  cache, correctly encoded, the entire time. Correspondingly the emulator maps
  `dsc_extras` **last**, because a library whose `vmsize` exceeds its `filesize`
  zero-fills the difference and would wipe an island mapped before it.
- **"No unresolved symbols" does not mean "no missing libraries"** when the libraries
  are pre-linked. The cache has already written the addresses, so a library left out of
  the extraction is not a link error — it is a pointer into unmapped memory, found by
  branching there twenty thousand instructions later. libobjc was excluded on exactly
  that reasoning and libdispatch's initializer calls it anyway. `dsc_extract` now
  attributes every pointer in the extracted data and names the libraries it points into.
- **`gAPIs` is a pointer to dyld's API object, not the object.** Three levels:
  `gAPIs -> object -> vtable -> method`. Collapsing two of them made the guest read
  `vtable[0]` as the object's vtable pointer and land in the stub area, where it read
  three instructions as a function pointer.
- **dyld runs libSystem's initializer before its own dependencies', and that ordering
  is not in the graph.** A post-order walk descends from libSystem into libdispatch,
  libobjc and libc++abi, whose initializers call `atexit`, which calls malloc, which
  libSystem's initializer has not yet brought up. The guest says so itself —
  `Assertion failed: (p), function atexit_register` — which only became visible once
  stdio worked well enough to print it.
- **Some of what dyld does is re-entrant.** libobjc registers its callbacks from inside
  its own initializer and dyld calls `map_images` *before the registration returns* --
  `_objc_init` goes on to use classes, so deferring the call until the initializer
  finishes means the initializer never finishes. `Syscalls::call_guest` saves the whole
  context, runs the guest function, and restores it, so the interrupted instruction can
  complete afterwards.
- **The image list `map_images` receives has to be in dependency order.** libobjc
  registers each image's classes as it walks the list, so an image processed before
  libobjc that references NSObject finds it unknown and aborts *inside* `map_images`.
  Breadth-first from the executable puts libobjc late; the post-order used for
  initializers puts it early, which is what dyld passes.
- **"Emitted" and "visited" are different marks.** Emitting libSystem's initializers
  ahead of the walk and then marking it *done* stops the walk at libSystem, so nothing
  else's initializers ever run -- visible only as `[init] 1/1` in the trace.
- **A callbacks struct at version 4 means the modern `mapped` shape**: `(count, infos[])`
  with 32-byte entries, not `(count, paths[], mach_headers[])`. Passing the two-array form
  makes libobjc read a *path pointer* where a mach_header belongs, fail its magic check,
  and skip every image -- which looks exactly like success: the call runs, returns, and
  registers nothing. Getting it right took `map_images` from 11,271 instructions to 35,793.
- **A cache dylib's `__objc_imageinfo` has `OPTIMIZED_BY_DYLD` set**, which tells libobjc
  its classes are already in the shared cache's tables and its classlist need not be read.
  True on a Mac, a dead end here, so the bit is cleared at load time.
- **`tools/dyld_slots.py` names 98 of the dyld API vtable slots** by scanning libdyld for
  the dispatch shape. The destination register of the vtable load varies -- x1 as often as
  x8 -- and requiring x8 found five slots out of a hundred and thirty.
- **The syscall number is a 32-bit value.** Reading all of x16 turns `mov w16, #-3`,
  which selects Mach trap 3, into 4294967293 — a positive number that goes down the BSD
  path and reports an absurd syscall.
- **`--dump ADDR` in dsc_extract settled that in one run**, after three readings of
  "the slot is zero" with three different explanations. From outside, "zero in the
  file" is indistinguishable from "never copied", and "no slide information" from "a
  chain that skips this slot". A tool that answers the question directly is worth more
  than another round of reasoning about which of them it is.

## Notes and gotchas

- **`DecodeBitMasks` returns two masks, and both matter.** The logical-immediate
  instructions only need `wmask`; the bitfield ones need `tmask` as well. The first
  version approximated the pair with a single hand-rolled mask, which is correct
  exactly when `imms >= immr` — so `lsl x0, x0, #7` (which encodes as UBFM with
  `imms < immr`) came out as a *rotate*. The value looked completely plausible; the
  differential test caught it on the first run. This is the argument for building
  the test harness before the instruction set.
- **`len = HighestSetBit(immN:NOT(imms))` is over a seven-bit value** — N is bit 6.
  Putting it anywhere else makes every mask the wrong size, and `and x11, x0, #0xf`
  gets rejected as reserved.
- **Reverse loops.** `for (unsigned b = 6; b-- > 0;)` never examines bit 6; it needs
  to start at 7. Cost one debugging cycle.
- **An unimplemented FP instruction must stop the machine**, not no-op. The sibling
  x86 project lost days to a no-op x87: the guest computes with whatever was in the
  register and fails somewhere unrelated. `exec_fp_simd` fails loudly by design.
- **Memory is permissive**: unmapped reads return zero, unmapped writes allocate.
  That gets a guest further, but it means a wild pointer is invisible. A `--strict`
  mode that faults instead is worth having before chasing a hard bug.
- **`long` is 64-bit on the guest and 32-bit on a Windows host**, so tests use
  fixed-width types only — otherwise a diff means nothing.
- **The exclusive monitor is real now, and it had to be.** With `STXR` always
  succeeding, four threads racing on one counter produced 67,000 of 100,000
  increments — a plausible-looking number. `LDXR` arms, `STXR` fails unless still
  armed for the same address, and `load_context` disarms. Watch bit 23: `LDAR`/`STLR`
  live in the same encoding group, are *not* exclusive, and must never fail.
- **A bug in the test harness is invisible to differential testing.** `dec()` wrote
  its newline over the last digit, so `100000` printed as `10000` — and because the
  host build ran the same formatter, the diff agreed and said nothing. Found only by
  reading the output during an unrelated experiment. Shared helpers deserve reading,
  not just diffing.
- **Preemption is what makes a lock test mean anything.** Switching only at syscalls
  would let each thread run its whole loop uninterrupted, and the counter would come
  out right no matter how broken the monitor was. `kPreemptEvery` in threads.cpp;
  temporarily dropping it to ~100 is a good stress test.
- **aarch64's `clone` argument order is flags, stack, parent_tid, tls, child_tid** —
  tls and child_tid are swapped relative to x86-64.
- **Darwin reports errors in the carry flag**, not as a negative return. Forgetting
  it is not a failed syscall, it is a *wrong answer*: `open` of a missing file comes
  back as 2, which is a valid file descriptor. `tests/file.c` exists to catch this,
  and the guest wrapper in `harness.h` reads the flag with `cset` rather than
  trusting the sign.
- **`LC_LOAD_DYLINKER` is on every Mach-O executable**, even `-nostdlib` ones with
  no imports at all, so it cannot mean "needs dyld". The loader tests for actual
  work instead: an `LC_LOAD_DYLIB`, a non-zero bind size in `LC_DYLD_INFO_ONLY`, or
  a non-empty `LC_DYLD_CHAINED_FIXUPS`.
- **Darwin's `struct stat64` is 144 bytes and shares no offsets with Linux's**, so
  `darwin.cpp` translates the buffer `Files` fills rather than copying it. Only
  mode, nlink, size, blocks and blksize are carried across; if a guest ever branches
  on a timestamp, that is where to add it.
- **Darwin's open flags are not Linux's** above `O_ACCMODE`: `O_CREAT` is 0x0200,
  not 0x40. Passing them through unchanged silently asks for something else.
- The Mach-O test build needs `-fno-stack-protector` — the Darwin target turns it
  on by default and there is no libc here to supply `__stack_chk_guard`.
- **`segment_offset` in `dyld_chained_starts_in_segment` is measured from the
  mach_header, not from the slide.** For a dylib preferring address 0 the two are
  identical, so the bug only appears in an executable — where it puts the entire
  chain walk 4 GiB low, in unmapped memory, and every fixup silently does nothing.
- **An image with no chained fixups is not necessarily an image with no fixups.**
  A dylib linked without `-fixup_chains` expresses the same work as `LC_DYLD_INFO`
  opcode programs, which are not implemented. Skipping them looked like a clean
  load and produced a rebased pointer that had never been rebased — pointing at a
  zero byte, so the test printed an empty string instead of crashing. It is refused
  loudly now.
- **PAC is the identity here, and that is a decision, not a stub.** An ARMv8.3 CPU
  with pointer authentication *disabled* does nothing for `pacia`/`autia` either, so
  the round-trip in `tests/pac.c` — sign then authenticate, sign then strip — holds
  on both real hardware and here, and is checkable. What does not hold: a guest that
  corrupts a signed pointer will not fault, because there is no signature to fail.
  Two encoding traps behind it:
  - In the 1-source data-processing group the **Rm field is `opcode2`**, and nothing
    looked at it, so `pacia x0, x1` decoded as **RBIT** and reversed the bits of a
    return address. Anything with `opcode2 != 0` now fails loudly.
  - `PACIA Xd, Xn` reads *and writes* **Xd** — the pointer — and takes the modifier
    in Xn. Writing `Xd = Xn` (the obvious-looking version) replaces the pointer with
    the salt; the identity means writing nothing at all.
  - `RETAA`/`RETAB` encode Rn as `11111` but use **X30**. Reading Rn there gives XZR
    and branches to zero.
- MSYS rewrites a command-line argument that starts with `/` into a Windows path
  before clang sees it, so `-install_name,/libfoo.dylib` becomes
  `C:/Program Files/Git/libfoo.dylib`. The tests use `@executable_path/…`.
