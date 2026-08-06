# aarch64_emu_cpp

A user-mode AArch64 emulator in C++17. It loads an ARM64 binary — a Linux ELF or a
macOS Mach-O — interprets the machine code instruction by instruction, and services
the guest's syscalls on the host, so an ARM program runs on x86 Windows, on x86
Linux, and in a browser tab.

```console
$ ./aarch64emu tests/hello.elf
hello from aarch64

$ ./aarch64emu --root guests/sysroot guests/sysroot/opt/python/bin/python3.13       -c "import sys, platform, hashlib; print(sys.version.split()[0], platform.machine());           print(hashlib.sha256(b'aarch64_emu_cpp').hexdigest())"
3.13.14 aarch64
bffb6fd92e8571ee9842b4be91c59556fa99d85a203350610620d876755b4110

$ ./aarch64emu --root guests/macos guests/macos/hello
hello from real macOS

$ ./aarch64emu --dyld-sections --root guests/macos_py       guests/macos_py/install/bin/python3.13       -c "import sys, platform; print(sys.version.split()[0], platform.machine(), sys.platform)"
3.13.14 arm64 darwin
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

**[▶ Try it in a browser](https://yomei-o.github.io/aarch64_emu_cpp/)** — one button runs a
real macOS binary against Apple's own libraries; another runs Apple's own CPython.

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
| **Mach-O loading and Darwin syscalls** (Apple Silicon guests) | ✅ |
| **Dynamic linking on Darwin** — chained fixups and export tries, done by the emulator | ✅ |
| **Pointer authentication** (arm64e): the PAC family, RETAA/BRAA/BLRAA | ✅ identity |
| **Threads** — `clone`, `futex`, a scheduler, a real exclusive monitor | ✅ |
| **WebAssembly** — the same guests, in a browser tab | ✅ |
| A real macOS binary against libSystem | ✅ |
| **Apple's clang and ld, hosted on Windows or Linux** — `.c` → signed arm64 Mach-O | ✅ [how to set it up](docs/macos-toolchain.md) |

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
ok   fp_fixed
ok   hello
ok   mem
ok   pac
ok   thread_linux
8 passed, 0 failed
```

The **same sources** are then built a third time, as arm64 **Mach-O**, and run
against the same host oracle — so the Darwin personality is held to the Linux one's
answers rather than to its own:

```console
$ sh tests/run_macho.sh
ok   macho arith
ok   macho control
ok   macho file
ok   macho fp_fixed
ok   macho hello
ok   macho mem
ok   macho pac
ok   macho dylib (bind + rebase)
8 passed, 0 failed
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

### ▶ [Live demo](https://yomei-o.github.io/aarch64_emu_cpp/)

Five guests, on one page.

**ARM64 Linux** — a freestanding static ELF; Alpine's `busybox`, a binary that has
never heard of this emulator; and a stock CPython 3.13.14 for
`aarch64-unknown-linux-musl` that is **dynamically linked**, so the guest's own
`ld.so` does the relocation and symbol binding and what runs is the real loader. A
22 MB fetch.

**`hello from real macOS`** — a stock arm64 Mach-O against Apple's own libSystem,
libobjc, libxpc, libdispatch and libcorecrypto, 46 libraries out of a Mac's dyld shared
cache, interpreted instruction by instruction in the tab. Apple's dyld cannot be
shipped, so the emulator does its job: mapping, chained fixups, symbol binding,
initializers in dyld's order, and the `exit` that flushes stdio. A 26 MB fetch.

**Apple's own CPython** — the stock `aarch64-apple-darwin` build of Python 3.13.14, on
CoreFoundation, Foundation and the 141 libraries under them. Type any expression; the
default prints a SHA-256 you can check against your own Python. Seventy-odd million
instructions, about five seconds, and every byte of that digest travels through the
emulated CPU. A 93 MB fetch, in three pieces, from the same site.

Both are decompressed by the browser's own `DecompressionStream` and unpacked into an
in-memory filesystem; nothing is uploaded, and the page is static files. You can also
drop your own AArch64 ELF or arm64 Mach-O on it.

The page is `web/index.html`; the root `index.html` is a redirect, because GitHub Pages
can only be pointed at the repository root or at `/docs`. Enable Pages for this repo
(Settings → Pages → deploy from `main`, `/`) and the link above works.

`web/` is the same emulator compiled to WebAssembly, in one self-contained
`aarch64emu.js` (the wasm is embedded), so it serves as static files. Drop an
AArch64 ELF on the page and it runs; drop its loader and libraries alongside and a
dynamically linked one runs too, because the guest's own `ld.so` does the linking.

```console
$ sh web/build.sh          # needs emscripten
$ node web/test_node.mjs
ok   wasm: hello.elf
ok   wasm: hello.macho (Darwin)
ok   wasm: mach-o dylib (bind + rebase)
ok   wasm: busybox echo
ok   wasm: busybox uname
ok   wasm: busybox sha256sum
ok   wasm: cpython
ok   wasm: cpython threading
8 passed, 0 failed
```

Those last two are CPython 3.13 for ARM64 Linux, dynamically linked, running inside
WebAssembly — three architectures deep, and the sha256sum above them still agrees
with the host's.

The threading one is worth a second look: four guest `pthread`s, a real mutex,
8000 increments, and the count comes out exactly right — **without WebAssembly
threads**. There is one wasm instance, so no `SharedArrayBuffer`, no cross-origin
isolation, and no COOP/COEP headers — which static hosting like GitHub Pages
cannot set anyway. The guest's threads are
interleaved by the emulator's own scheduler, and from inside the guest that is
indistinguishable from a single-core machine.

## A real macOS binary

`prebuilt/` carries the 48 libraries an arm64 macOS executable actually needs — 21 MB
packed, out of a 4.9 GB dyld shared cache, extracted by `tools/dsc_extract.c` on a Mac:

```console
$ sh prebuilt/unpack.sh
$ ./aarch64emu --root guests/macos guests/macos/hello
hello from real macOS

$ ./aarch64emu --dyld-sections --root guests/macos_py       guests/macos_py/install/bin/python3.13       -c "import sys, platform; print(sys.version.split()[0], platform.machine(), sys.platform)"
3.13.14 arm64 darwin
```

**That works.** 199,279 instructions of Apple's own arm64 code: 48 libraries from a real
Mac's dyld shared cache map and link, the emulator does dyld's job
(`src/macho_dyld.cpp`), initializers run in dyld's order, libSystem comes up over Mach IPC
and the commpage, **libobjc registers its images and realizes its classes out of the
cache's preoptimized tables**, libxpc initialises over a bootstrap port, libcorecrypto
runs AES on the emulated crypto instructions, stdio decides whether stdout is a terminal —
and then `main` returns and the host calls the guest's own `exit`, which is what flushes
that line out.

Nothing Apple ships is included: `prebuilt/` is the 48 libraries a hello world needs,
extracted from a Mac's cache by `tools/dsc_extract.c`. What is *emulated* is everything
between them and the kernel.

## Building macOS binaries, on a machine that is not a Mac

Apple's own clang and `ld` run here as guests, which makes this a
Windows- and Linux-hosted macOS cross-compiler:

```console
$ ./aarch64emu --dyld-sections --root guests/macos_clang guests/macos_clang/hello
hello from emulated clang
```

That `hello` is a signed, PIE arm64 Mach-O with `LC_MAIN` and chained fixups,
compiled by Apple's clang and linked by Apple's `ld` — the same binaries a Mac
runs, executing the same instructions, with no cross-toolchain anywhere. It runs
on a Mac too.

Getting there takes one trip to a Mac, because Apple's compiler is not
redistributable and cannot ship here. The system libraries it loads at run time
*are* in this repository, so that trip only has to fetch the toolchain itself.
**[docs/macos-toolchain.md](docs/macos-toolchain.md)** is the full guide: what to
run on the Mac, how to assemble the guest tree, the four placement details that
each cost an afternoon, and how to read the guest when something goes wrong.

`clang hello.c -o hello` takes 24.6 seconds on an 8 GB Windows host — nearly all of
it libdispatch and the loader starting up, so a bigger program costs little more.
The driver spawning its own linker is the harder case rather than the easier one:
it throws a C++ exception through the shared cache's libraries and re-execs itself,
three levels of nested guest process deep. `sh tests/run_macos_clang.sh` checks the
compile, the link, the run and the one-shot separately, and skips itself when the
guest tree is absent.

## Building

```sh
sh build.sh                              # g++ (or CXX=clang++)
CXX=cl sh build.sh                       # MSVC, from a developer prompt
cmake -B build && cmake --build build     # either, through CMake
```

The MSVC build is real rather than aspirational now: the two GCC/Clang extensions the
interpreter used — `__builtin_bswap32/64` and `__int128`, for `REV` and `UMULH`/`SMULH` —
are written out longhand in `cpu.cpp`. cl.exe and clang produce byte-identical output over
the 78,474-instruction macOS guest run, and the replacements were checked against
`__int128` over two million random and corner-case pairs.

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
- `src/macho_loader.cpp`, `src/macho_dyld.cpp`, `src/darwin.cpp` — the second
  personality, including the loader that stands in for Apple's dyld. Not a fork of
  the first: the same CPU, the same memory, the same file layer, reached through
  `svc #0x80` instead of `svc #0`.
- `src/threads.cpp` — `clone`, `futex`, and a scheduler. One emulated CPU running
  one guest thread at a time, switched at futex/yield/exit and preempted every
  20,000 instructions so a spin loop cannot keep the CPU.

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

## Being dyld

On the Linux side the guest's own `ld.so` runs and this emulator stays out of it —
which is both less work and more faithful. Darwin gets the opposite treatment, for
one reason: `/usr/lib/dyld` is not a file you can obtain without a Mac. So
`src/macho_dyld.cpp` does dyld's job.

For a binary built with chained fixups — the modern default — that job is narrower
than dyld's reputation suggests:

1. map the dependencies named by `LC_LOAD_DYLIB`, recursively and deduplicated;
2. walk `LC_DYLD_CHAINED_FIXUPS`: a linked list of pointer slots threaded through
   each page, where every slot is either a **rebase** (add the slide) or a **bind**
   (write an imported symbol's address);
3. resolve those symbols through the exporting image's **export trie**.

Lazy binding, the old `LC_DYLD_INFO` opcode programs, and two-level namespace hints
are all absent from that list, because a chained-fixups binary does not use them.
An image that *does* use them is **refused**, not loaded — a rebase that never
happened leaves a pointer that is merely somewhere else, and the guest gets a
plausible answer instead of a crash. `tests/dylib/` builds a real `.dylib` and a
program that imports a function, a variable, and a pointer needing a rebase, and
diffs all three against the host.

## Two things about A64 that bite

**Register 31 is not one register.** In most encodings it reads as zero and
discards writes; in the base of a load/store, the operand of ADD/SUB immediate and
a few others it means SP. The two go through different accessors so the choice is
always explicit.

**A 32-bit result clears the top half.** Writing W0 zeroes bits 63..32 of X0,
unlike x86 where a 16-bit write preserves them. Handled in one place.

## The exclusive monitor is not optional once there are threads

`LDXR`/`STXR` were a plain load and a store that always succeeded for as long as
the emulator was single-threaded, and nothing could tell. The moment a second
thread exists, "always succeeds" means two threads can both win the same
compare-and-swap, and a counter incremented 100,000 times comes out at 67,000 —
a number that looks like a plausible count and is simply wrong.

So the monitor is real: `LDXR` arms it, `STXR` fails unless it is still armed for
the same address, and a **context switch disarms it**, which is exactly what sends
the loser back round its retry loop. `tests/thread_linux.c` is four threads racing
on one counter through the compiler's atomics, and it is the only test in the
suite that fails if any of that is missing.

One trap in the same encoding: `LDAR`/`STLR` — the *ordered* accesses, bit 23 set —
share this group with `LDXR`/`STXR` but have no monitor and no status register. A
`STLR` routed through the exclusive path would start failing silently.
