# A macOS libSystem, extracted from a dyld shared cache

`macos-libsystem-15.7.4-arm64e.tar.xz` — 1.8 MB compressed, 9.8 MB unpacked, 40 files.
This is what an arm64 macOS executable needs in order to run, and nothing else.

    sh prebuilt/unpack.sh                      # into guests/macos/
    ./aarch64emu --root guests/macos guests/macos/hello
    hello from real macOS

## What is in it

    usr/lib/libSystem.B.dylib                  the C library, which is almost
                                               entirely a list of re-exports
    usr/lib/system/lib*.dylib            (38)  where the code actually is:
                                               libsystem_c, libsystem_kernel,
                                               libsystem_malloc, libsystem_pthread,
                                               libdispatch, libxpc, libcorecrypto, …
    usr/lib/dsc_extras.dylib             1.2M  not a real library: the GOT pages the
                                               cache owns and no dylib does
    hello, h.c                                 a dynamically linked test program,
                                               built by the Mac's own clang

`CoreFoundation` and `libobjc` are **not** here, and this set is therefore not yet
enough. That was a wrong call, and the way it was wrong is worth keeping: nothing in the
closure *binds* a symbol from either, so the emulator reports no unresolved imports —
but the cache has already written the addresses, so libdispatch's initializer calls
straight into libobjc twenty-four thousand instructions later and branches into unmapped
memory. "No unresolved symbols" does not mean "no missing libraries" when the libraries
are pre-linked. `dsc_extract` now attributes every pointer in the extracted data and
names the libraries it points into, which is the check that was missing.

## Where it came from, and how to make another

macOS 15.7.4, Apple Silicon. On macOS 11 and later none of these libraries exist as
files: they live only inside `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/
dyld_shared_cache_arm64e`, which is 4.9 GB across two files. This is 0.2% of it —
the transitive closure of `libSystem.B.dylib` over non-weak, non-upward dependencies
inside `/usr/lib`.

`tools/dsc_extract.c` does the extraction, on the Mac, with nothing but the system
compiler:

    cc -O2 -o dsc_extract tools/dsc_extract.c
    CACHE=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
    ./dsc_extract --only /usr/lib/ -o out "$CACHE" /usr/lib/libSystem.B.dylib

That is worth knowing about even with this archive present, because a different macOS
version has a different cache, and because the tool reports what it did — how many
pointers it unpacked from the slide information, which libraries had none, what it
declined to follow. `resume.md` records the several ways a naive extraction goes wrong
while looking like it worked.

## What these files are not

They are Apple's, taken from an installed copy of macOS. They are here because moving
4.9 GB to reproduce 10 MB is absurd, not because there is a licence to redistribute
them — Apple's does not grant one. If that matters for how this repository is used,
delete the archive and run `tools/dsc_extract.c` on a Mac instead; it produces this
directory exactly, and `unpack.sh` will then have nothing to do.

The extracted libraries are also **not** loadable by a real macOS: the code signature
is blanked, the LINKEDIT is rebuilt from just the pieces a loader reads, and the
pointers are frozen at the cache's preferred addresses. They are input for an
emulator, not a working system.
