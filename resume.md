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

    sh tests/run_tests.sh      4 passed   freestanding C, built twice and diffed
    sh tests/run_busybox.sh    9 passed   Alpine's static aarch64-musl busybox
    sh tests/run_python.sh     5 passed   CPython 3.13, dynamically linked
    node web/test_node.mjs     5 passed   the same guests under WebAssembly

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
- **WebAssembly** (`web/`), running all of the above.

## ⏭ Next, in order

1. **Mach-O and Darwin** — Apple Silicon guests. Mach-O arm64 loading (`LC_SEGMENT_64`,
   `LC_MAIN`, chained fixups), `svc #0x80` with the BSD syscall numbering, the commpage
   and `mach_absolute_time`. A second personality *alongside* the Linux one in
   `syscalls.cpp`, selected by the image format — not a fork of it. The CPU is done;
   this is all kernel interface.
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
