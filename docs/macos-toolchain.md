# Building macOS binaries on Windows or Linux

This is the setup guide for the thing the emulator can do that nothing else here
can: run **Apple's own clang and ld** on a non-Apple machine, and get a real
arm64 Mach-O executable out.

    $ ./aarch64emu --dyld-sections --root guests/macos_clang guests/macos_clang/hello
    hello from emulated clang

That `hello` was compiled by Apple's clang and linked by Apple's `ld`, both
running as guests. No Mac was involved at build time, and no cross-toolchain was
used — it is the same compiler binary a Mac runs, executing the same
instructions.

## What this costs you

**One trip to a Mac, once.** Apple's compiler is not redistributable, so it
cannot ship in this repository and this guide cannot hand it to you. You copy it
off a Mac you already have access to, and the licence that came with it is the
one that governs what you do next — Apple's SDK terms restrict use to
Apple-branded hardware, so read them and decide for yourself whether your use
fits. Nothing here removes a check or works around a restriction; the emulator
runs the binary as-is, the way the Mac would.

Everything *else* — the system libraries the compiler and linker load at run time
— is already in this repository, so the Mac-side work is only the toolchain
itself.

You need:

- **An Apple Silicon Mac** with the Xcode Command Line Tools installed
  (`xcode-select --install`). Apple Silicon matters: the shared cache has to be
  the arm64e one. macOS 15 is what this was built and tested against.
- **About 760 MB of disk** on the target machine for the assembled guest tree.
- Some way to move ~300 MB between the two. A file share is easiest; the scripts
  produce single `.tar.gz` files on purpose.

## Step 1 — on the Mac: the toolchain

Copy `tools/pack_clang.sh` and `tools/pack_clang_dylibs.sh` to a folder on the
Mac and run them there.

```console
$ sh pack_clang.sh          # -> macos_clang.tar.gz     (clang, ld, headers, .tbd stubs)
$ sh pack_clang_dylibs.sh   # -> clang_dylibs.tar.gz    (libtapi, libLTO)
```

`pack_clang.sh` takes `clang` and `ld` themselves, clang's builtin headers
(`stdarg.h`, `arm_neon.h`, …), the SDK's `usr/include`, and every `.tbd` in the
SDK — 445 of them. Those `.tbd` files are text stubs, not libraries: `ld` links
against a description of a library's symbols and never opens a dylib at all. It
finishes by compiling a `hello.c` against *only the packaged subset*, so a
missing header is caught on the Mac rather than three hours later.

`pack_clang_dylibs.sh` handles the dependencies the two programs load at run
time. The split that matters is *where a dependency lives*: anything under
`/usr/lib` or `/System` is in the dyld shared cache and comes from step 3;
anything else is a real file inside the CommandLineTools and has to travel. The
script walks `otool -L` from both programs and resolves `@rpath` against each
binary's `LC_RPATH` rather than guessing at a list, which is how `libtapi` — the
one `ld` fails at startup without — is found.

## Step 2 — on the Mac: the two libraries that are not files

```console
$ sh extract_for_clang.sh   # -> clang_cache_libs.tar.gz
```

Copy `tools/extract_for_clang.sh` **and `tools/dsc_extract.c`** (the script
compiles it) to the same folder.

Two of `ld`'s dependencies are not files anywhere on the Mac. The tell is that
the SDK carries only a `.tbd` for them:

    sdk/usr/lib/libcodedirectory.tbd
    sdk/usr/lib/swift/libswiftDemangle.tbd

Their code lives inside the 4.9 GB dyld shared cache, so it has to be extracted.
`libcodedirectory` is the one that has to be real — `ld` ad-hoc signs every arm64
macOS binary it produces, through `libcd_create`. `libswiftDemangle` only
prettifies Swift names in diagnostics, but `ld` still refuses to start without
it.

## Step 3 — on Windows or Linux: assemble the tree

The system libraries are already here. Unpack them, then lay the three archives
from the Mac on top.

```sh
git clone https://github.com/yomei-o/aarch64_emu_cpp && cd aarch64_emu_cpp
sh build.sh
sh prebuilt/unpack.sh python            # -> guests/macos_py, the extracted cache

mkdir -p guests/macos_clang
cp -R guests/macos_py/usr guests/macos_py/System guests/macos_clang/

tar xzf macos_clang.tar.gz -C /tmp && cp -R /tmp/macos_clang/* guests/macos_clang/
tar xzf clang_dylibs.tar.gz    -C guests/macos_clang
tar xzf clang_cache_libs.tar.gz -C guests/macos_clang

mkdir -p guests/macos_clang/tmp
```

What you should end up with, and roughly how much of each:

    guests/macos_clang/
      usr/bin/clang, usr/bin/ld     the two programs
      usr/lib/clang/<ver>/include   clang's builtin headers
      usr/lib/**.dylib        124   the system closure + libtapi, libLTO,
                                    libcodedirectory, libswiftDemangle
      System/Library/**       26    frameworks: CoreFoundation, Foundation, …
      sdk/usr/include               the C headers
      sdk/usr/lib/**.tbd      445   what ld actually links against
      tmp/                          must exist; see below

### Four placement details, each of which cost an afternoon

- **`ld`'s only `LC_RPATH` is `@executable_path/../lib/`.** So `@rpath/...`
  resolves to `/usr/lib/` and *not* `/usr/lib/swift/`. `libswiftDemangle` needs a
  copy in **both** places.
- **`/tmp` must exist in the guest, and you must pass `--setenv TMPDIR=/tmp/`.**
  Without it the clang driver stops at "unable to make temporary file". The
  trailing slash is not decoration.
- **`libresolv.9.dylib` can be a stub.** clang names `res_9_*` and never calls
  them; `guests/macos/stub_libs.sh` builds a stand-in whose every symbol is a
  `ret`. If your extraction includes the real one, use that instead.
- **On Windows, run from Git Bash with `MSYS2_ARG_CONV_EXCL='*'` exported.**
  Otherwise MSYS rewrites every guest-absolute path into a Windows one on the way
  in, and `/hello.c` arrives as `C:/Program Files/Git/hello.c`.

## Step 4 — check it

```console
$ sh tests/run_macos_clang.sh
ok   macos clang -c (arm64 object, printf->puts)
ok   macos ld (LC_MAIN, chained fixups, ad-hoc signature)
ok   macos clang+ld output runs
3 passed, 0 failed
```

The three stages are checked apart rather than as one `clang hello.c -o hello`,
because they fail in different ways. The script skips itself with a note when
`guests/macos_clang` is not there, so it is safe to leave in a normal test run.

## Using it

Paths on the command line are **guest** paths — inside `--root` — except for the
program being run, which is a host path.

```sh
export MSYS2_ARG_CONV_EXCL='*'          # Windows/Git Bash only
EMU="./aarch64emu --setenv TMPDIR=/tmp/ --dyld-sections --root guests/macos_clang"

# compile
$EMU guests/macos_clang/usr/bin/clang \
     -target arm64-apple-macos15 -isysroot /sdk -O2 -c /hello.c -o /hello.o

# link
$EMU guests/macos_clang/usr/bin/ld \
     -arch arm64 -platform_version macos 15.0.0 15.0 -syslibroot /sdk \
     -o /hello /hello.o -lSystem

# run what came out
./aarch64emu --dyld-sections --root guests/macos_clang guests/macos_clang/hello
```

The result is a signed, PIE arm64 Mach-O with `LC_MAIN` and chained fixups —
`llvm-objdump --macho --all-headers` on it looks exactly like a Mac's output, and
it will run on a Mac.

Driving the two stages separately is what has been tested. The driver's own
`clang hello.c -o hello`, where clang `posix_spawn`s `ld` itself, goes through a
code path the emulator does implement (syscall 244, with its file actions) but
which is not covered by the test suite.

### Two things to expect

- **It is not fast.** Linking a hello world is about 190 million emulated
  instructions, a few minutes. Almost all of it is `ld` and libdispatch starting
  up, so it is close to a fixed cost rather than one that scales with your
  program.
- **`--dyld-sections` is not optional.** Without it libobjc never reads the
  shared cache's preoptimized class tables and libxpc fails its own type check
  long before clang starts.

## When something goes wrong

The guests are good at saying what is wrong, and the emulator now relays it.

- **Apple's fatal paths write a sentence into `__DATA,__crash_info` and then
  `BRK`.** The emulator prints it. Every blocker in getting `ld` to work named
  itself this way — "Missing Kevent WORKQ support", "thread_set_tsd_base() wasn't
  called by the kernel", "BUG IN CLIENT OF LIBDISPATCH: Corrupted priority". Read
  the message before inferring anything.
- **`ld` reports its own syscall failures**: `ld: ftruncate() failed, errno=78`
  is the emulator missing a syscall, not a linking problem.
- **A hang is usually the workqueue.** `ld` is heavily threaded through
  libdispatch; when every thread is parked or blocked the emulator prints a
  `[stall]` report with each thread's stack.
- **Redirect stdout to a file, not into `head`.** The guest's libc fully buffers
  a non-tty and flushes at exit, so your program's output arrives *last*, after
  all the loader chatter — piping into `head` drops it and looks like silence.

Other switches worth knowing: `--trace-sys` (also prints the printable strings of
any unimplemented MIG message, which is how service lookups identify themselves),
`--list-unresolved`, `A64EMU_TRACE_OPEN=1` for every file the guest opens.

`resume.md` has the full account of how the linker was made to work, including
the libdispatch priority encoding that was the last bug.
