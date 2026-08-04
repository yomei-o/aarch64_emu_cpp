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

    sh tests/run_tests.sh      8 passed   freestanding C, built twice and diffed
    sh tests/run_macho.sh      8 passed   the same sources as arm64 Mach-O, plus a dylib
    sh tests/run_busybox.sh    9 passed   Alpine's static aarch64-musl busybox
    sh tests/run_python.sh     7 passed   CPython 3.13, dynamically linked
    node web/test_node.mjs     8 passed   the same guests under WebAssembly

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
- **WebAssembly** (`web/`), running all of the above.

## ⏭ Next, in order

1. **A real macOS binary.** The linking machinery is done and tested against
   locally built dylibs; what is missing is **libSystem**, and that is not a
   technical problem. On macOS 11+ `/usr/lib/libSystem.B.dylib` and everything under
   it do not exist as files — they live only inside the **dyld shared cache**, which
   is several GB and only obtainable from a Mac.

   Steps, in order:
   - get the cache (`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/
     dyld_shared_cache_arm64e*`) and a real dynamically linked hello built by the
     Mac's own clang;
   - parse the cache header and map the dylibs out of it (they are pre-linked at
     fixed addresses in one big mapping — mapping the cache wholesale is easier
     than extracting individual libraries);
   - fill in the Darwin syscalls and Mach traps a real libSystem startup makes.
     Expect `shared_region_check_np`, `csops`, `proc_info`, `getrlimit`, `sysctl`
     with real answers, and the commpage at `0xFFFFFC000`.

   A macOS CPython is downloadable without a Mac (python-build-standalone publishes
   `aarch64-apple-darwin`), so the cache is the only Mac-only dependency.
2. **arm64e chained pointers.** Only `DYLD_CHAINED_PTR_64` and `_64_OFFSET` are
   implemented. System binaries are arm64e and use authenticated pointers
   (`DYLD_CHAINED_PTR_ARM64E`), where the slot carries a signing key and a
   discriminator. The emulator can ignore the signature — it has no PAC — but must
   read the different bit layout. Currently refused loudly.
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
