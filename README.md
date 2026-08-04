# aarch64_emu_cpp

A user-mode AArch64 emulator in C++17. It loads an ARM64 Linux ELF, interprets the
machine code instruction by instruction, and services the guest's syscalls on the
host — so an ARM binary runs on x86 Windows, on x86 Linux, and in a browser tab.

```console
$ ./aarch64emu tests/hello.elf
hello from aarch64
```

Sibling of [x86_emu_cpp](https://github.com/yomei-o/x86_emu_cpp), pointed the other
way: that one runs x86 guests on an ARM host, this one runs ARM guests on an x86
host. The goal is the same shape — **a stock CPython for ARM Linux, and later for
Apple Silicon, running instruction by instruction on a machine that is neither.**

No dependencies beyond a C++17 standard library.

## What runs today

| | status |
| --- | --- |
| A64 integer core (ALU, shifts, bitfield, multiply/divide, conditional select) | ✅ |
| Branches, compare-and-branch, test-and-branch, calls and returns | ✅ |
| Loads and stores: all widths, sign extension, pre/post-index, register offset, LDP/STP, SIMD Q registers | ✅ |
| System registers a userland guest touches (TPIDR_EL0, FPCR/FPSR, NZCV, CTR_EL0) | ✅ |
| Static ELF64 loading with a Linux-shaped initial stack and auxiliary vector | ✅ |
| Linux syscalls: write, writev, read, brk, mmap, exit, uname, clock_gettime, getrandom … | ✅ |
| FP and Advanced SIMD | scalar double/single arithmetic, compare, convert; DUP/INS/UMOV, the logical and compare vector ops, MOVI, shifts, CNT, across-lanes, LD1/ST1 |
| A real guest: **Alpine's static aarch64-musl busybox** | ✅ |
| Dynamic linking (`ld-linux-aarch64.so`) | ❌ next |
| Mach-O and Darwin syscalls (Apple Silicon guests) | ❌ planned |
| WebAssembly build | ❌ planned |

## Correctness is a diff, not an opinion

Every test is built **twice** from one source: once for AArch64 (freestanding, no
libc, syscalls written by hand) and once for the host (ordinary `printf`). The
emulator runs the first, the host runs the second, and they are compared byte for
byte.

```console
$ sh tests/run_tests.sh
ok   arith
ok   control
ok   hello
ok   mem
4 passed, 0 failed
```

And a second suite runs a **real** guest — Alpine's static aarch64-musl busybox, a
binary that has never heard of this emulator — against the *host's* own tools:

```console
$ sh tests/run_busybox.sh
ok   busybox md5sum
ok   busybox sha1sum
ok   busybox sha256sum
ok   busybox wc -l
ok   busybox uname
ok   busybox expr
ok   busybox seq
ok   busybox sort -u
ok   busybox od
9 passed, 0 failed
```

A digest is the strongest single check available: every byte of the file travels
through the emulated CPU, and one wrong bit anywhere in a million instructions
changes the answer.

That is the whole quality argument, and it earns its keep. `lsl x0, x0, #7` came
out as a rotate on the first run — the number looked entirely reasonable, and only
the diff against the host said otherwise. (The cause: the bitfield instructions
need *two* masks from `DecodeBitMasks`, and approximating them with one is correct
exactly when `imms >= immr`.)

## Building

```sh
sh build.sh                # g++ or clang++
cmake -B build && cmake --build build     # or MSVC
```

Tests need `clang` with the AArch64 target and `lld` — no cross-binutils, no
sysroot, because the test programs are freestanding:

```sh
sh tests/run_tests.sh
```

## Design

- `src/cpu.{h,cpp}` — the interpreter, laid out in the order the ARM ARM organises
  the encoding space: bits 28..25 pick the group, each group sub-decodes its own
  fields. An instruction is findable by the group name the manual gives it.
- `src/fp_simd.cpp` — FP and SIMD, grown strictly by demand. An unimplemented
  instruction **stops the machine and prints its encoding**; it never silently does
  nothing, because a guest that keeps running on a stale register fails somewhere
  unrelated and hours later.
- `src/memory.h` — 64 KiB pages in a hash map. A 64-bit guest spreads its image,
  heap, mmap arena and stack across terabytes and touches almost none of it.
- `src/elf_loader.cpp` — static ELF64, plus the initial process image Linux hands a
  new program: argv, envp, and the auxiliary vector a libc reads before `main`.
- `src/syscalls.cpp` — the kernel interface, AArch64's "generic" numbering (write
  is 64, not 1).

## Two things about A64 that bite

**Register 31 is not one register.** In most encodings it reads as zero and
discards writes; in the base of a load/store, the operand of ADD/SUB immediate and
a few others it means SP. The two go through different accessors so the choice is
always explicit.

**A 32-bit result clears the top half.** Writing W0 zeroes bits 63..32 of X0,
unlike x86 where a 16-bit write preserves them. Handled in one place.
