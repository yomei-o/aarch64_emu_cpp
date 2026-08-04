#!/bin/sh
# Build a macOS arm64 guest without a Mac.
#
# The committed `hello` was compiled on a Mac. Nothing about that is necessary: a
# Mach-O guest needs an arm64 code generator and a Mach-O linker, and clang and
# lld are both. What it does *not* need is an Apple SDK -- the extracted
# libraries under this directory are real dylibs with real export tries, so lld
# links against them directly, and a guest that declares its own prototypes needs
# no headers.
#
#     sh guests/macos/build.sh threads     -> guests/macos/threads
#
# Two halves, and they fail for different reasons, so they are reported
# separately:
#
#   * The **link** half is verified in this repository. `-syslibroot` pointed at
#     guests/macos resolves libSystem.B.dylib and all seventeen of its
#     re-exports out of usr/lib/system, which is the part specific to a
#     cache-extracted tree (a Mac links against .tbd stubs instead). With no
#     object file the only error left is the missing `_main`.
#   * The **compile** half needs a clang with the AArch64 target built in. The
#     emscripten clang this project is otherwise built with has only wasm and
#     x86, so on such a host this script stops and says so rather than
#     producing something that looks like a guest.
#
# CC and LD are overridable, which is the whole point on a host where the usable
# clang is not the first one on PATH.
set -e
cd "$(dirname "$0")"

name="${1:-hello}"
CC="${CC:-clang}"
LD="${LD:-lld}"

if [ ! -f "$name.c" ]; then
    echo "build.sh: no $name.c next to this script" >&2
    exit 2
fi

if ! "$CC" --print-targets 2>/dev/null | grep -qi aarch64; then
    echo "build.sh: $CC has no AArch64 target, so it cannot compile an arm64 guest." >&2
    echo "          Registered targets:" >&2
    "$CC" --print-targets 2>/dev/null | sed 's/^/          /' >&2
    echo "          Install an LLVM with AArch64 and re-run as CC=.../clang LD=.../lld" >&2
    exit 3
fi

# arm64, not arm64e. The libraries are arm64e, and linking against them works --
# but an arm64e *output* would carry DYLD_CHAINED_PTR_ARM64E fixups, which
# macho_dyld.cpp refuses (loudly, on purpose). The committed `hello` is arm64 for
# the same reason.
"$CC" --target=arm64-apple-macos15 -O2 -c "$name.c" -o "$name.o"
"$LD" -flavor darwin -arch arm64 -platform_version macos 15.0 15.0 \
      -syslibroot . -o "$name" "$name.o" /usr/lib/libSystem.B.dylib
rm -f "$name.o"
echo "built guests/macos/$name"
echo "  run it with: ./aarch64emu --root guests/macos guests/macos/$name"
