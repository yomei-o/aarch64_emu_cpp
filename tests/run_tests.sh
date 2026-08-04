#!/bin/sh
# Builds each test twice -- once for AArch64, once for the host -- runs the first
# under the emulator and the second directly, and diffs. A test passes only if the
# emulator reproduces the host byte for byte.
set -e
cd "$(dirname "$0")"
EMU=../aarch64emu
CLANG=${CLANG:-clang}
HOSTCC=${HOSTCC:-cc}
A64="--target=aarch64-linux-gnu -ffreestanding -nostdlib -fuse-ld=lld -static"
pass=0; fail=0
for src in *.c; do
    name=${src%.c}
    $CLANG $A64 -O2 -I. -o "$name.elf" "$src"
    $HOSTCC -DA64_NATIVE -O2 -I. -o "$name.native" "$src"
    "./$name.native" > "$name.expected"
    if $EMU "$name.elf" > "$name.actual" 2>"$name.err"; then :; else
        echo "FAIL $name (emulator stopped)"; sed 's/^/     /' "$name.err"; fail=$((fail+1)); continue
    fi
    if cmp -s "$name.expected" "$name.actual"; then
        echo "ok   $name"; pass=$((pass+1))
    else
        echo "FAIL $name"; diff "$name.expected" "$name.actual" | head -10; fail=$((fail+1))
    fi
done
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
