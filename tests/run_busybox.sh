#!/bin/sh
# Differential test against a *real* guest: Alpine's static aarch64-musl busybox.
#
# The oracle is the host's own tools. `busybox sha256sum X` under the emulator has
# to agree with the host's sha256 of X, `busybox wc -l X` with the host's line
# count, and so on. That is a far harder test than a fixed expected file: it checks
# the emulator against a binary that was never built for it, and a digest disagrees
# on a single wrong bit anywhere in a million instructions.
#
# Skipped when guests/busybox is absent, so a clone without it still runs the
# freestanding suite. To fetch it:
#   curl -Lo bb.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/busybox-static-1.36.1-r31.apk
#   tar xzf bb.apk && mkdir -p guests && mv bin/busybox.static guests/busybox
set -e
cd "$(dirname "$0")/.."
BB=guests/busybox
# Overridable so the same suite can be run under a different build or flag --
# `EMU="./aarch64emu --strict" sh tests/run_busybox.sh` is how the strict sweep is done.
EMU=${EMU:-./aarch64emu}
if [ ! -f "$BB" ]; then
    echo "skip busybox tests (no $BB -- see the header for how to fetch it)"
    exit 0
fi

pass=0; fail=0
# Both sides get CR stripped before comparing. Not to hide a difference -- the
# emulator is the more faithful of the two here: the guest reads the file's raw
# bytes, CRLF and all, while a host tool built for Windows strips CR on the way in.
# Normalising is what makes the two comparable on this host at all.
norm() { tr -d '\015'; }
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1))
    else echo "FAIL $1"; echo "     host: $2"; echo "     emu:  $3"; fail=$((fail+1)); fi
}

F=README.md

# A digest is the strongest single check available: every byte of the file has to
# travel through the emulated CPU and come out in the right order.
for algo in md5sum sha1sum sha256sum; do
    host=$( { command -v "$algo" >/dev/null && "$algo" "$F"; } 2>/dev/null | cut -d' ' -f1 )
    [ -n "$host" ] || continue
    emu=$($EMU "$BB" $algo "$F" 2>/dev/null | cut -d' ' -f1)
    check "busybox $algo" "$host" "$emu"
done

check "busybox wc -l" \
      "$(wc -l < $F | tr -d ' ')" \
      "$($EMU "$BB" wc -l "$F" < /dev/null 2>/dev/null | tr -s ' ' | cut -d' ' -f1)"
check "busybox uname" "aarch64" "$($EMU "$BB" uname -m 2>/dev/null | norm)"
check "busybox expr"  "42"      "$($EMU "$BB" expr 6 '*' 7 2>/dev/null | norm)"
check "busybox seq"   "1 2 3 4 5" \
      "$($EMU "$BB" seq 1 5 2>/dev/null | norm | tr '\n' ' ' | sed 's/ $//')"
check "busybox sort -u" \
      "$(sort -u tests/hello.c | norm | md5sum | cut -d' ' -f1)" \
      "$($EMU "$BB" sort -u tests/hello.c 2>/dev/null | norm | md5sum | cut -d' ' -f1)"
check "busybox od" \
      "$(od -An -tx1 -N16 $F 2>/dev/null | tr -s ' ')" \
      "$($EMU "$BB" od -An -tx1 -N16 $F < /dev/null 2>/dev/null | tr -s ' ')"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
