#!/bin/sh
# The same differential test as run_tests.sh, but the guest is an arm64 **Mach-O**
# instead of an ELF: a different loader, a different initial stack, and `svc #0x80`
# with BSD numbering instead of `svc #0` with Linux numbering.
#
# The oracle is unchanged -- still the host build of the same source -- so a pass
# means the Darwin path produces the same bytes the Linux path does, from the same
# code, which is the only way to be sure the second personality did not quietly
# diverge.
#
# clang can emit arm64 Mach-O on any host, so this needs no Mac.
set -e
cd "$(dirname "$0")"
EMU=${EMU:-../aarch64emu}
CLANG=${CLANG:-clang}
HOSTCC=${HOSTCC:-cc}
# -fno-stack-protector because the Darwin target enables it by default and there is
# no libc here to provide __stack_chk_guard.
MACHO="--target=arm64-apple-macos11 -ffreestanding -nostdlib -fno-stack-protector -fuse-ld=lld -Wl,-e,_start"
pass=0; fail=0
for src in *.c; do
    name=${src%.c}
    # Sources named *_linux.c use an interface Darwin does not have (clone, futex).
    # Skipping them out loud beats a build that quietly covers less than it looks like.
    case "$name" in
        *_linux) echo "skip $name (Linux-only interface)"; continue ;;
    esac
    if ! $CLANG $MACHO -DA64_DARWIN -O2 -I. -o "$name.macho" "$src" 2>"$name.cerr"; then
        echo "SKIP $name (no arm64-apple-macos target: $(head -1 "$name.cerr"))"
        continue
    fi
    $HOSTCC -DA64_NATIVE -O2 -I. -o "$name.native" "$src"
    "./$name.native" > "$name.expected"
    if $EMU "$name.macho" > "$name.actual" 2>"$name.err"; then :; else
        echo "FAIL $name (emulator stopped)"; sed 's/^/     /' "$name.err"; fail=$((fail+1)); continue
    fi
    if cmp -s "$name.expected" "$name.actual"; then
        echo "ok   macho $name"; pass=$((pass+1))
    else
        echo "FAIL macho $name"; diff "$name.expected" "$name.actual" | head -10; fail=$((fail+1))
    fi
done

# ---- dynamic linking, where the emulator has to be dyld ----------------------
#
# A real .dylib and a program that imports from it, both arm64 Mach-O, both built
# here. -fixup_chains is what modern Apple toolchains default to and what the
# emulator implements; without it the linker emits lazy binding stubs that expect
# dyld_stub_binder, which is a libSystem symbol and so unavailable off a Mac.
#
# The install name is @executable_path/... rather than an absolute path because
# this script runs under MSYS on Windows, where a leading slash in a command-line
# argument gets rewritten into a Windows path before clang ever sees it.
if $CLANG $MACHO -dynamiclib -Wl,-install_name,@executable_path/libfoo.dylib \
        -Wl,-fixup_chains -O2 -Idylib -o dylib/libfoo.dylib dylib/lib.c 2>dylib/cerr &&
   $CLANG $MACHO -Wl,-e,_start -Wl,-fixup_chains -DA64_DARWIN \
        -O2 -I. -Idylib -o dylib/main.macho dylib/main.c dylib/libfoo.dylib 2>>dylib/cerr; then
    $HOSTCC -DA64_NATIVE -O2 -I. -Idylib -o dylib/main.native dylib/main.c dylib/lib.c
    ./dylib/main.native > dylib/expected
    if $EMU --root dylib dylib/main.macho > dylib/actual 2>dylib/err; then
        if cmp -s dylib/expected dylib/actual; then
            echo "ok   macho dylib (bind + rebase)"; pass=$((pass+1))
        else
            echo "FAIL macho dylib"; diff dylib/expected dylib/actual | head -10; fail=$((fail+1))
        fi
    else
        echo "FAIL macho dylib (emulator stopped)"; sed 's/^/     /' dylib/err; fail=$((fail+1))
    fi
else
    echo "SKIP macho dylib ($(head -1 dylib/cerr))"
fi


# ---- the shared-cache extractor, round-tripped -------------------------------
#
# tools/dsc_extract.c has to be written without a Mac in reach, and the part most
# likely to be quietly wrong is not the cache header -- that is a documented struct
# -- but the Mach-O rewriting: packing a library's scattered segments into a fresh
# file and patching every file offset in the load commands to match. Get that wrong
# and the output still looks like a dylib and no longer loads.
#
# So: wrap the dylib built above in a synthetic one-image cache, extract it back
# out, and run the *same* program against the extracted copy. It has to produce the
# same bytes the host did. (This caught exactly one bug: LC_DYLD_CHAINED_FIXUPS was
# copied with its old offset, and the stale offset parsed as a fixup header.)
#
# Not covered, because it only exists in a real cache: subcaches, the newer image
# array location, and real addresses.
if [ -f dylib/libfoo.dylib ] && command -v python >/dev/null 2>&1; then
    $HOSTCC -O2 -o dylib/dsc_extract ../tools/dsc_extract.c 2>dylib/cerr2 || true
    if [ -x dylib/dsc_extract ] || [ -f dylib/dsc_extract.exe ]; then
        EX=./dylib/dsc_extract
        rm -rf dylib/dsc
        MSYS_NO_PATHCONV=1 python ../tools/make_fake_cache.py \
            dylib/libfoo.dylib /libfoo.dylib dylib/fake.cache >/dev/null
        MSYS_NO_PATHCONV=1 $EX -o dylib/dsc dylib/fake.cache /libfoo.dylib >dylib/dsc.log 2>&1
        if [ -f dylib/dsc/libfoo.dylib ]; then
            cp dylib/main.macho dylib/dsc/
            if $EMU --root dylib/dsc dylib/dsc/main.macho > dylib/dsc.actual 2>dylib/dsc.err &&
               cmp -s dylib/expected dylib/dsc.actual; then
                echo "ok   macho dylib via dsc_extract (round trip)"; pass=$((pass+1))
            else
                echo "FAIL macho dylib via dsc_extract"
                sed 's/^/     /' dylib/dsc.err 2>/dev/null | head -3
                diff dylib/expected dylib/dsc.actual 2>/dev/null | head -6
                fail=$((fail+1))
            fi
        else
            echo "FAIL dsc_extract produced nothing"; sed 's/^/     /' dylib/dsc.log | head -5
            fail=$((fail+1))
        fi
    else
        echo "SKIP dsc_extract ($(head -1 dylib/cerr2 2>/dev/null))"
    fi
else
    echo "SKIP dsc_extract (needs the dylib above and python)"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
