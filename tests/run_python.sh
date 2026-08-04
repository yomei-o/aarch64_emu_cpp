#!/bin/sh
# CPython 3.13 for aarch64-linux-musl, dynamically linked, running under the
# emulator with the real musl ld.so doing the loading.
#
# Same rule as the busybox suite: the oracle is the host, not a recorded file.
# A digest computed by the guest has to match the host's digest of the same bytes,
# and the arithmetic has to agree exactly.
#
# Skipped when the guest tree is absent. To build it:
#   curl -Lo py.tgz https://github.com/astral-sh/python-build-standalone/releases/download/20260728/cpython-3.13.14%2B20260728-aarch64-unknown-linux-musl-install_only_stripped.tar.gz
#   mkdir -p guests/sysroot/opt && tar xzf py.tgz -C guests/sysroot/opt
#   curl -Lo musl.apk https://dl-cdn.alpinelinux.org/alpine/v3.20/main/aarch64/musl-1.2.5-r3.apk
#   tar xzf musl.apk -C guests/sysroot          # gives lib/ld-musl-aarch64.so.1
set -e
cd "$(dirname "$0")/.."
PY=guests/sysroot/opt/python/bin/python3.13
EMU="./aarch64emu --root guests/sysroot"
if [ ! -f "$PY" ]; then
    echo "skip python tests (no $PY -- see the header for how to fetch it)"
    exit 0
fi

pass=0; fail=0
norm() { tr -d '\015'; }
check() {
    if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1))
    else echo "FAIL $1"; echo "     want: $2"; echo "     got:  $3"; fail=$((fail+1)); fi
}

check "python version"  "3.13.14 aarch64" \
      "$($EMU $PY -c 'import sys,platform;print(sys.version.split()[0],platform.machine())' 2>/dev/null | norm)"
check "python arithmetic" "5050 3.141593" \
      "$($EMU $PY -c 'import math;print(sum(range(1,101)), round(math.pi,6))' 2>/dev/null | norm)"
# hashlib exercises the SHA/PMULL instructions and a lot of the integer core.
check "python hashlib" "$(printf 'aarch64_emu_cpp' | sha256sum | cut -d' ' -f1)" \
      "$($EMU $PY -c 'import hashlib;print(hashlib.sha256(b"aarch64_emu_cpp").hexdigest())' 2>/dev/null | norm)"
check "python json" '{"a": 1, "b": [2, 3]}' \
      "$($EMU $PY -c 'import json;print(json.dumps({"a":1,"b":[2,3]}))' 2>/dev/null | norm)"
check "python str/re" "['a1', 'b22', 'c333']" \
      "$($EMU $PY -c 'import re;print(re.findall(r"[a-z]\d+", "a1 b22 c333"))' 2>/dev/null | norm)"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
