#!/bin/sh
# Build stand-in dylibs for libraries that are not in the extraction yet.
#
#     sh guests/macos/stub_libs.sh guests/macos_py bin/python3.13
#
# **These are scaffolding, not a substitute.** Every symbol resolves to a `ret`,
# so a guest that actually *calls* one gets a function that does nothing and
# returns whatever was in x0. The point is narrower and worth having: a
# pre-linked guest missing a library does not fail at the call, it fails at load
# with several hundred unresolved symbols -- and that stops every other question
# from being asked. With stubs the run reaches its real first problem, which is
# the one worth working on.
#
# This is how the stock macOS CPython was taken from "490 unresolved symbols" to a
# startup that could be traced, while the real CoreFoundation, SystemConfiguration,
# libncurses, libpanel, libedit and libz were still on the other side of a Mac.
# Delete the stubs once those arrive; the emulator names every missing library
# itself, so there is no list kept here to fall out of step.
#
# **It loops, and it has to.** A missing library hides more than its own symbols:
# every GOT slot that wanted one is reported without a library name, because there
# is no library to name. Stubbing what is visible reveals the next layer.
set -e
cd "$(dirname "$0")/../.."

ROOT=${1:?usage: stub_libs.sh <guest-root> <program-relative-to-root>}
PROG=${2:?usage: stub_libs.sh <guest-root> <program-relative-to-root>}
CC=${CC:-clang}
LD=${LD:-lld}
EMU=${EMU:-./aarch64emu}
# A *relative* work directory, deliberately. MSYS rewrites any argument starting
# with `/` into a Windows path before a native lld sees it, and CONV_EXCL names the
# prefixes that must survive -- the install names. An absolute work directory would
# then not be converted either, and lld would not find its own object file.
WORK=guests/.stubwork
CONV_EXCL='/System;/usr;/Library'
rm -rf "$WORK"
mkdir -p "$WORK"

# "SYMBOL  from  /path/to/library" is the emulator's own line for a symbol it could
# not resolve. `--list-unresolved` prints all of them rather than the first forty.
collect() {
    "$EMU" --list-unresolved --root "$ROOT" "$ROOT/$PROG" 2>&1 |
        sed -n 's/^ *\([A-Za-z_][A-Za-z0-9_$.]*\)  from \(\/.*\)$/\2 \1/p' |
        sort -u
}

round=0
while :; do
    round=$((round + 1))
    collect > "$WORK/pairs" || true
    if [ ! -s "$WORK/pairs" ]; then
        [ "$round" = 1 ] && echo "stub_libs: nothing unresolved."
        break
    fi
    if [ "$round" -gt 12 ]; then
        echo "stub_libs: still unresolved after $round rounds; something else is wrong." >&2
        exit 1
    fi

    for lib in $(cut -d' ' -f1 "$WORK/pairs" | sort -u); do
        out="$ROOT$lib"
        # Never write over a library that is already there. An unresolved symbol
        # attributed to a *present* library is a different problem entirely -- a
        # symbol this loader failed to find in it, most likely through a re-export
        # chain -- and stubbing it replaces a real 100 KB libSystem with a 19 KB
        # file full of `ret`, which turns one missing symbol into every symbol
        # missing. That happened once; hence this check and hence the loud stop.
        if [ -f "$out" ] && [ ! -f "$WORK/made$(echo "$lib" | tr '/.' '__')" ]; then
            echo "stub_libs: $lib exists but still has unresolved symbols:" >&2
            grep "^$lib " "$WORK/pairs" | cut -d' ' -f2 | sed 's/^/    /' >&2
            echo "  That is a lookup failure, not a missing library. Not stubbing it." >&2
            exit 1
        fi
        : > "$WORK/made$(echo "$lib" | tr '/.' '__')"
        mkdir -p "$(dirname "$out")"
        asm="$WORK/$(echo "$lib" | tr '/.' '__').s"
        # Each round rewrites the whole library, so the symbol list accumulates
        # rather than replaces -- otherwise round two drops what round one stubbed.
        grep "^$lib " "$WORK/pairs" | cut -d' ' -f2 >> "$asm.syms"
        sort -u "$asm.syms" -o "$asm.syms"
        {
            echo '.text'
            # One `ret` per symbol. A data symbol gets a `ret` too: reading it back
            # gives the instruction word, which is wrong but *mapped* -- and being
            # mapped is the difference between "the guest runs and shows its next
            # problem" and "the guest does not load at all".
            while read -r sym; do
                echo ".globl $sym"
                echo "$sym:"
                echo "    ret"
            done < "$asm.syms"
        } > "$asm"
        "$CC" --target=arm64-apple-macos15 -c "$asm" -o "$asm.o"
        MSYS2_ARG_CONV_EXCL="$CONV_EXCL" "$LD" -flavor darwin -arch arm64 -dylib \
            -platform_version macos 15.0 15.0 \
            -install_name "$lib" -o "$out" "$asm.o"
        echo "round $round: $lib ($(wc -l < "$asm.syms" | tr -d ' ') symbols)"
    done
done

echo
echo "These are stubs: every symbol returns immediately. Replace them with a real"
echo "extraction (see resume.md) before believing anything the guest computes."
