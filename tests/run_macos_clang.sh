#!/bin/sh
# Apple's clang and ld, running on Windows, building a macOS program.
#
# This is separate from run_macos.sh because it needs guests/macos_clang, which
# is several hundred MB of CommandLineTools and extracted shared-cache libraries
# that only exist on a machine where tools/pack_clang*.sh have been run.  It
# skips quietly when they are not there.
#
# The three stages are checked apart rather than as one `clang hello.c -o hello`,
# because they fail in different ways and a single verdict would hide which:
#
#   1. clang -c   -- the compiler alone, no linker.  Its output is inspected for
#                    the -O2 printf-to-puts rewrite, so a stage that "worked" but
#                    optimised nothing is not mistaken for a pass.
#   2. ld         -- the interesting one.  It is heavily threaded through
#                    libdispatch, and every hang so far has been the emulator
#                    mismodelling the workqueue rather than anything about
#                    linking.
#   3. run it     -- the only check that the bytes ld emitted are a real program:
#                    correct chained fixups, a bound _printf, an ad-hoc signature.
#
# Note the run needs its stdout on a file, not a pipe into head: the guest's libc
# fully buffers a non-tty and flushes at exit, so the greeting arrives last, after
# whatever dyld chatter came before it.
set -u
EMU=./aarch64emu
ROOT=guests/macos_clang
pass=0
fail=0

check() {                                          # check <name> <want> <got>
    if [ "$2" = "$3" ]; then
        echo "ok   $1"
        pass=$((pass + 1))
    else
        echo "FAIL $1"
        echo "       want: $2"
        echo "       got:  $3"
        fail=$((fail + 1))
    fi
}

# -f, not -x: these are Mach-O files on an NTFS share and carry no execute bit.
if [ ! -f "$ROOT/usr/bin/clang" ] || [ ! -f "$ROOT/usr/bin/ld" ]; then
    echo "guests/macos_clang is not set up; skipping (see tools/pack_clang_dylibs.sh)"
    exit 0
fi

# MSYS would rewrite every guest-absolute path into a Windows one on the way in.
MSYS2_ARG_CONV_EXCL='*'
export MSYS2_ARG_CONV_EXCL

cat > "$ROOT/hello.c" <<'EOF'
#include <stdio.h>
int main(void) { printf("hello from emulated clang\n"); return 0; }
EOF
rm -f "$ROOT/hello.o" "$ROOT/hello"

# ---- 1. compile -----------------------------------------------------------------
$EMU --setenv TMPDIR=/tmp/ --dyld-sections --root "$ROOT" \
     "$ROOT/usr/bin/clang" -target arm64-apple-macos15 -isysroot /sdk \
     -O2 -c /hello.c -o /hello.o >/dev/null 2>&1
if [ -f "$ROOT/hello.o" ]; then
    # An arm64 MH_OBJECT that calls _puts: clang rewrites a printf of a constant
    # string ending in \n, so seeing _puts proves the optimiser ran too.
    syms=$(llvm-nm "$ROOT/hello.o" 2>/dev/null | grep -cE ' _(main|puts)$')
    check "macos clang -c (arm64 object, printf->puts)" "2" "$syms"
else
    check "macos clang -c (arm64 object, printf->puts)" "2" "no hello.o"
fi

# ---- 2. link --------------------------------------------------------------------
if [ -f "$ROOT/hello.o" ]; then
    $EMU --setenv TMPDIR=/tmp/ --dyld-sections --root "$ROOT" \
         "$ROOT/usr/bin/ld" -arch arm64 -platform_version macos 15.0.0 15.0 \
         -syslibroot /sdk -o /hello /hello.o -lSystem >/dev/null 2>&1
    if [ -f "$ROOT/hello" ]; then
        # PIE, an entry point, and ld's own ad-hoc signature.
        got=$(llvm-objdump --macho --all-headers "$ROOT/hello" 2>/dev/null |
              grep -cE 'cmd LC_(MAIN|CODE_SIGNATURE|DYLD_CHAINED_FIXUPS)([^A-Z_]|$)')
        check "macos ld (LC_MAIN, chained fixups, ad-hoc signature)" "3" "$got"
    else
        check "macos ld (LC_MAIN, chained fixups, ad-hoc signature)" "3" "no output"
    fi
fi

# ---- 3. run what came out -------------------------------------------------------
if [ -f "$ROOT/hello" ]; then
    out=$(mktemp)
    $EMU --dyld-sections --root "$ROOT" "$ROOT/hello" >"$out" 2>/dev/null
    got=$(tr -d '\015' < "$out")
    rm -f "$out"
    check "macos clang+ld output runs" "hello from emulated clang" "$got"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
