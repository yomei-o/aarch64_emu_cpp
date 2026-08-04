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
EMU=../aarch64emu
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
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
