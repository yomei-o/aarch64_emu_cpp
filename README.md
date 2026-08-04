# aarch64_emu_cpp

A user-mode AArch64 emulator in C++17. It loads an ARM64 Linux ELF, interprets the
machine code instruction by instruction, and services the guest's syscalls on the
host — so an ARM binary runs on x86 Windows, on x86 Linux, and in a browser tab.

```console
$ ./aarch64emu tests/hello.elf
hello from aarch64

$ ./aarch64emu --root guests/sysroot guests/sysroot/opt/python/bin/python3.13       -c "import sys, platform, hashlib; print(sys.version.split()[0], platform.machine());           print(hashlib.sha256(b'aarch64_emu_cpp').hexdigest())"
3.13.14 aarch64
bffb6fd92e8571ee9842b4be91c59556fa99d85a203350610620d876755b4110
```

That is a stock CPython built for `aarch64-unknown-linux-musl`, **dynamically
linked**, running on x86 Windows: the emulator maps the program and its
interpreter the way the kernel does and starts at the interpreter's entry, and the
real musl `ld.so` does the relocation and symbol binding itself. The digest is the
host's digest of the same bytes.

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
| **Dynamic linking** — the real `ld-musl-aarch64.so.1` loads and relocates | ✅ |
| Signal delivery (SIGILL frames, `rt_sigreturn`) | ✅ |
| **A stock CPython 3.13 for ARM64 Linux** | ✅ |
| **Mach-O loading and Darwin syscalls** (Apple Silicon guests) | ✅ static binaries |
| **WebAssembly** — the same guests, in a browser tab | ✅ |
| Threads (`clone`) | ❌ planned |
| Dynamically linked Mach-O (needs Apple's `dyld`) | ❌ planned |

## Correctness is a diff, not an opinion

Every test is built **twice** from one source: once for AArch64 (freestanding, no
libc, syscalls written by hand) and once for the host (ordinary `printf`). The
emulator runs the first, the host runs the second, and they are compared byte for
byte.

```console
$ sh tests/run_tests.sh
ok   arith
ok   control
ok   file
ok   hello
ok   mem
5 passed, 0 failed
```

The **same sources** are then built a third time, as arm64 **Mach-O**, and run
against the same host oracle — so the Darwin personality is held to the Linux one's
answers rather than to its own:

```console
$ sh tests/run_macho.sh
ok   macho arith
ok   macho control
ok   macho file
ok   macho hello
ok   macho mem
5 passed, 0 failed
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

## In a browser

`web/` is the same emulator compiled to WebAssembly, in one self-contained
`aarch64emu.js` (the wasm is embedded), so it serves as static files. Drop an
AArch64 ELF on the page and it runs; drop its loader and libraries alongside and a
dynamically linked one runs too, because the guest's own `ld.so` does the linking.

```console
$ sh web/build.sh          # needs emscripten
$ node web/test_node.mjs
ok   wasm: hello.elf
ok   wasm: hello.macho (Darwin)
ok   wasm: busybox echo
ok   wasm: busybox uname
ok   wasm: busybox sha256sum
ok   wasm: cpython
6 passed, 0 failed
```

That last line is CPython 3.13 for ARM64 Linux, dynamically linked, running inside
WebAssembly — three architectures deep, and the sha256sum above it still agrees
with the host's.

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
- `src/macho_loader.cpp`, `src/darwin.cpp` — the second personality. Not a fork of
  the first: the same CPU, the same memory, the same file layer, reached through
  `svc #0x80` instead of `svc #0`.

## Two kernels, one build

An ELF guest traps with `svc #0`; a Mach-O guest traps with `svc #0x80`. That is
the whole personality switch — the immediate itself selects which kernel answers,
so both guests run in the same binary with no mode flag anywhere.

Darwin then differs in three ways that all matter:

- the syscall number is in **x16**, not x8, and it is BSD numbering (write is 4);
- **negative** numbers in x16 are Mach traps, an entirely separate table;
- errors come back in the **carry flag** — C set, positive errno in x0 — where
  Linux returns a negative errno. This is the dangerous one: get it wrong and a
  failed `open` returns a small positive number, which reads as a perfectly good
  file descriptor. `tests/file.c` opens something that is not there for exactly
  this reason, and the guest-side wrapper reads the flag back with `cset`.

`LC_LOAD_DYLINKER` is present on every Mach-O executable, including one linked
`-nostdlib` that imports nothing, so it cannot be the test for "needs a loader".
The loader instead asks whether there is anything for dyld to *do* — any dylib,
any bind opcode, any chained fixup — and runs the entry point directly when there
is not, which is where dyld would arrive anyway.

## Two things about A64 that bite

**Register 31 is not one register.** In most encodings it reads as zero and
discards writes; in the base of a load/store, the operand of ADD/SUB immediate and
a few others it means SP. The two go through different accessors so the choice is
always explicit.

**A 32-bit result clears the top half.** Writing W0 zeroes bits 63..32 of X0,
unlike x86 where a 16-bit write preserves them. Handled in one place.
