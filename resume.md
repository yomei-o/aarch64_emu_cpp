# Where this is, and what to do next

Working notes for picking the project back up. The README says what the emulator
*is*; this says what is unfinished and what is known about it.

## The goal

Run a **stock CPython for ARM Linux, and then for Apple Silicon, on an x86 host and
in a browser** — the mirror image of x86_emu_cpp, which runs x86 guests on ARM.
Everything below is ordered by what that needs.

## State (verified against the host, not against expectations)

Four suites, all differential — the oracle is always the host, never a recorded
file:

    sh tests/run_tests.sh      5 passed   freestanding C, built twice and diffed
    sh tests/run_macho.sh      5 passed   the same sources as arm64 Mach-O
    sh tests/run_busybox.sh    9 passed   Alpine's static aarch64-musl busybox
    sh tests/run_python.sh     5 passed   CPython 3.13, dynamically linked
    node web/test_node.mjs     6 passed   the same guests under WebAssembly

What works:

- The A64 integer core, branches, every load/store addressing mode, and the system
  registers a userland guest reads.
- FP and Advanced SIMD: scalar arithmetic/compare/convert/round/FMADD; the vector
  three-same, three-different, two-misc, across-lanes, permute and shift groups;
  DUP/INS/UMOV/SMOV, EXT, TBL/TBX, MOVI, XTN, REV, PMULL; LD1-LD4 including
  de-interleaving, LD1R and the single-lane forms. SHA1 and SHA256 are implemented
  exactly, in `crypto.cpp`, because hashlib uses them for real.
- **Dynamic linking** by running the guest's own `ld.so`: map the program, map the
  interpreter, start at the interpreter's entry with AT_BASE/AT_ENTRY set. This
  needed a real mmap — MAP_FIXED honoured, file mappings at their offset, zero-fill
  past EOF.
- **Signal delivery**: an AArch64 signal frame, SIGILL for an unimplemented
  instruction or system register, and `rt_sigreturn`.
- A file layer with directory descriptors and `getdents64`, and the syscalls
  busybox and CPython need.
- **Mach-O and Darwin, for static binaries.** `macho_loader.cpp` handles
  `LC_SEGMENT_64` / `LC_MAIN` / `LC_UNIXTHREAD` and skips `__PAGEZERO`;
  `darwin.cpp` is the BSD syscall table plus the cheap Mach traps, reached through
  `svc #0x80`. Both run under WebAssembly too.
- **WebAssembly** (`web/`), running all of the above.

## ⏭ Next, in order

1. **Dynamically linked Mach-O.** The hard half of the Darwin milestone is still
   open, and it is hard for a reason that is not technical: a real macOS binary
   links against `/usr/lib/dyld` and the dylibs in the shared cache, and neither is
   a file you can obtain without a Mac. Two ways forward, and the second is
   probably right:
   - map the real dyld and the real dyld shared cache from a Mac (needs
     `LC_DYLD_CHAINED_FIXUPS`, `shared_region_check_np`, and a lot of Mach);
   - or *be* the loader for chained fixups only, and stub the handful of libSystem
     entry points a plain program actually calls. Much less faithful, but it does
     not need a Mac in the loop.
   Either way the next concrete step is a **static** Mach-O built against a real
   libc, which is `clang -static` on a Mac — worth getting one binary of that to
   test against before touching dyld at all.
2. **Threads.** `clone` is unimplemented, so anything that starts one stops. CPython
   only needs it once you `import threading`; the sibling x86 project has the shape to
   copy (per-thread stacks, a scheduler that runs one at a time).
3. **A trimmed Python for the browser demo.** The page can run CPython today, but the
   guest tree is 45 MB into MEMFS. Dropping the stdlib to what a script actually
   imports would make a shippable Pages demo.
4. **Speed.** ~48M instructions/sec interpreted. A decode cache keyed on the PC (the
   instruction word is fixed-width, so a table of decoded handlers is cheap) is the
   obvious next step if it ever matters. Measure first — CPython startup is 66M
   instructions, which is already about a second.
5. **`--strict` memory.** Unmapped reads return zero and unmapped writes allocate, so a
   wild pointer is invisible. Faulting instead would have caught the mmap/interpreter
   address collision immediately rather than 90,000 instructions later.

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
- Load/store exclusive is a plain load/store and always succeeds. Single-threaded,
  so nothing observes the difference; a threaded guest would need a real monitor.
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
