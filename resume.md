# Where this is, and what to do next

Working notes for picking the project back up. The README says what the emulator
*is*; this says what is unfinished and what is known about it.

## Handoff — start here

**Everything needed is in the repository. No Mac is required to continue.**

    git pull
    sh build.sh
    sh prebuilt/unpack.sh                # 48 macOS libraries, 21 MB packed
    ./aarch64emu --root guests/macos guests/macos/hello

**That prints `hello from real macOS`.** 199,279 instructions of Apple's own arm64 code, from
a real Mac's shared cache, on an x86 host. The libraries load and link, the emulator does
dyld's job, initializers run in dyld's order, libSystem comes up over Mach IPC and the
commpage, libobjc realizes its classes out of the cache's preoptimized tables, libxpc
initialises over a bootstrap port, libcorecrypto runs AES on the emulated crypto
instructions, and `main` returns to the host, which calls the guest's `exit` — the thing
that flushes stdio, and without which the program printed nothing at all.

The macOS milestone is **met**. What is left on that side is breadth rather than a wall:
see "What to pick up".

Builds with **g++, clang or MSVC** (`CXX=cl sh build.sh`); the two compilers agree byte for
byte over the whole macOS run, which is the best differential oracle here for anyone
without a cross-compiler.

Run the four suites before touching anything — they should be 9 / 10 / 9 / 7, plus 8 for
`node web/test_node.mjs` if emscripten is around:

    sh tests/run_tests.sh    sh tests/run_macho.sh
    sh tests/run_busybox.sh  sh tests/run_python.sh

`EMU` is overridable, which is how the strict sweep is run and how a second build is
compared:

    EMU="./aarch64emu --strict" sh tests/run_busybox.sh

**Two of the four need only a download, not a cross-compiler**, which matters on a host
without one — `run_tests.sh` and `run_macho.sh` build their guests with
`clang --target=aarch64…`, but busybox and CPython are prebuilt binaries:

    cd guests
    curl -Lo bb.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-1.36.1-r31.apk
    tar xzf bb.apk && mv bin/busybox.static busybox
    curl -Lo py.tgz https://github.com/astral-sh/python-build-standalone/releases/download/20260728/cpython-3.13.14%2B20260728-aarch64-unknown-linux-musl-install_only_stripped.tar.gz
    mkdir -p sysroot/opt && tar xzf py.tgz -C sysroot/opt
    curl -Lo musl.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/musl-1.2.5-r3.apk
    tar xzf musl.apk -C sysroot

Those 16 tests plus the committed macOS guest are enough to work on any of this: they are
differential against the host's own tools, and between them they cover the integer core, the
SIMD groups, threads, dynamic linking and both personalities. They are also how a
compiler-portability change gets checked, since cl.exe and clang must agree.

The tools built for this, all of which take addresses straight out of a trace:

    --trace-sys              syscalls, Mach traps, MIG routines, [init]/[objc]/[call]
    --sample N               print the PC every N instructions
    --watch LO:HI            log every guest access in a range, with the PC
    --macho-info FILE [sym…] what a Mach-O contains; look symbols up in its export trie
    tools/whichlib.py        address -> library and nearest symbol
    tools/dis_macho.py       disassemble at a virtual address in a cache-extracted library
    tools/dyld_slots.py      names 98 of dyld's API vtable slots
    tools/profile_pcs.py     a --sample trace -> a per-function profile
    tools/dsc_extract.c      re-extract from a Mac's shared cache (only if the OS changes)

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

Four suites, all differential — the oracle is always the host, never a recorded
file:

    sh tests/run_tests.sh      9 passed   freestanding C, built twice and diffed
    sh tests/run_macho.sh     10 passed   the same sources as arm64 Mach-O, plus a dylib
    sh tests/run_busybox.sh    9 passed   Alpine's static aarch64-musl busybox
    sh tests/run_python.sh     7 passed   CPython 3.13, dynamically linked
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
- **WebAssembly** (`web/`), running all of the above.

## ⏭ Next, in order

1. ✅ **A real macOS binary runs.** `hello from real macOS`, 199,279 instructions, exit 0 — the
   same count with `--strict`.
   The account of how the last walls fell is in "How the macOS milestone was reached" below,
   because every one of them was a case of the host telling the guest something almost true.

   What is left on that side is breadth, not a wall:

   - **A guest that does more than print.** This one is a C hello world. The next
     interesting ones are a program that uses Foundation (needs CoreFoundation and
     Foundation extracted, which `dsc_extract` can do), and one that spawns a thread on
     Darwin (`bsdthread_create` is not implemented; the Linux side's scheduler is).
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
   - **The dyld API slots still answered with zero** are listed further down. Most are
     honest zeros now; `_dyld_lookup_section_info` (111) is called constantly and makes
     libobjc fall back to walking load commands, which works but costs 16% of the run.

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
