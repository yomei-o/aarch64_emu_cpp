#!/bin/sh
# Disassemble one or more A64 encodings:  sh tools/dis.sh 2E611000 4E285800
#
# The bring-up loop is "run the guest, read the encoding the emulator printed,
# implement it" -- and working out a bit layout by hand is how you end up
# implementing a different instruction than the one that stopped you. Ask the
# assembler instead.
set -e
t=$(mktemp -d)
for w in "$@"; do echo ".inst 0x$w"; done > "$t/a.s"
${CLANG:-clang} --target=aarch64-linux-gnu -c -o "$t/a.o" "$t/a.s"
llvm-objdump -d --triple=aarch64 "$t/a.o" | tail -n +7
rm -rf "$t"
