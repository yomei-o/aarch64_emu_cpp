# Where this is, and what to do next

Working notes for picking the project back up. The README says what the emulator
*is*; this says what is unfinished and what is known about it.

## The goal

Run a **stock CPython for ARM Linux, and then for Apple Silicon, on an x86 host and
in a browser** — the mirror image of x86_emu_cpp, which runs x86 guests on ARM.
Everything below is ordered by what that needs.

## State (verified, byte for byte against native)

`sh tests/run_tests.sh` — 4 tests, each built twice from one source and diffed:

- A64 integer core: ALU immediate and register forms, shifts, bitfield
  (SBFM/BFM/UBFM and all the aliases), EXTR, MADD/MSUB/MULH, UDIV/SDIV,
  CSEL/CSINC/CSINV/CSNEG, CCMP/CCMN, RBIT/REV/CLZ/CLS
- Branches: B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/BR/BLR/RET, and jump tables
- Loads and stores: every width, both extensions, unsigned-immediate,
  unscaled, pre- and post-index, register offset with extend/scale, LDP/STP,
  load-literal, SIMD Q-register forms, load/store exclusive
- System registers: TPIDR_EL0 (the TLS base — a libc does not reach `main`
  without it), FPCR/FPSR, NZCV, CTR_EL0, DCZID, MIDR
- Static ELF64 loading and the Linux initial stack: argv, envp, and an auxiliary
  vector with AT_PHDR/AT_ENTRY/AT_RANDOM/AT_HWCAP
- Linux syscalls (AArch64 "generic" numbering): write, writev, read, brk, mmap,
  exit/exit_group, uname, clock_gettime, getrandom, getpid and friends

## ⏭ Next, in order

1. **A real static musl guest.** Everything so far is freestanding code the tests
   compile themselves; the first outside binary is the real bring-up. Get a static
   `aarch64-linux-musl` hello and then busybox running. Expect to add: FP/SIMD used
   by musl's `memcpy`/`strlen` (`LD1`/`ST1`, `CMEQ`, `UMINV`), `set_tid_address`
   already stubbed, `ioctl` for isatty, `openat`/`close`/`fstat`/`lseek`.
2. **Files.** `src/files.*` does not exist yet — syscalls are console-only. Port the
   shape from x86_emu_cpp (`FileTable`, host path mapping, directory descriptors),
   which already solved `getdents64` and `O_DIRECTORY`.
3. **FP and SIMD properly.** Currently only what the tests reached: FMOV
   general↔vector, CNT, UADDLV/SADDLV/ADDV. CPython needs scalar double arithmetic
   (FADD/FSUB/FMUL/FDIV/FCMP/FCVT/SCVTF/FCVTZS) and the vector loads that a libc's
   string functions use. Add on demand and let the decoder tell you what is missing
   — `exec_fp_simd` prints the encoding.
4. **Dynamic linking.** `ld-linux-aarch64.so.1` plus AArch64 relocations
   (`R_AARCH64_RELATIVE`, `GLOB_DAT`, `JUMP_SLOT`, and the TLS ones). x86_emu_cpp
   took the shortcut of a *static* CPython first and it was the right call — do the
   same here and keep dynamic for later.
5. **CPython.** Static musl build first, exactly as the x86 project did.
6. **Mach-O / Darwin.** Apple Silicon guests: Mach-O arm64 loading, `svc #0x80`
   with the BSD syscall numbering, and `commpage`/`mach_absolute_time`. A separate
   personality alongside the Linux one, not a fork of it.
7. **WebAssembly.** The emulator is plain C++17 with no host dependencies, so this
   should be a build target rather than a port — but nothing has tried it yet.

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
