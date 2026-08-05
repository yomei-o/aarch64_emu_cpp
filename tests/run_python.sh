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
# Overridable, so the suite can be run under a different build or flag; --root has to
# stay, since the guest tree is what makes it a sysroot.
EMU="${EMU:-./aarch64emu} --root guests/sysroot"
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

# Threads. The interesting part is not that it prints a number, it is that the
# number is exact: four threads and 8000 increments through a real pthread mutex,
# which is clone, futex, per-thread TLS and the exclusive monitor all at once. A
# lost update anywhere shows up here and nowhere else.
check "python threading" "8000 4950 True" \
      "$($EMU $PY -c '
import threading, queue
n=[0]; lock=threading.Lock()
def w():
    for _ in range(2000):
        with lock: n[0]+=1
ts=[threading.Thread(target=w) for _ in range(4)]
[t.start() for t in ts]; [t.join() for t in ts]
q=queue.Queue()
def prod():
    for i in range(100): q.put(i)
    q.put(None)
threading.Thread(target=prod).start()
s=0
while True:
    v=q.get()
    if v is None: break
    s+=v
ev=threading.Event()
threading.Thread(target=ev.set).start()
ev.wait()
print(n[0], s, ev.is_set())' 2>/dev/null | norm)"

# A thread pool, which is where the fixed-point FP conversions turn up: a float
# timeout becomes a lock deadline through FCVTZU with a scale.
check "python thread pool" "20 5feceb66 9400f1b2" \
      "$($EMU $PY -c '
from concurrent.futures import ThreadPoolExecutor
import hashlib
def work(i): return hashlib.sha256(str(i).encode()).hexdigest()[:8]
with ThreadPoolExecutor(max_workers=4) as ex:
    r=list(ex.map(work, range(20)))
print(len(r), r[0], r[-1])' 2>/dev/null | norm)"

# ---- a child process, which is fork + execve + a pipe + wait4 -----------------
#
# `subprocess` is the shape gcc and make need: fork, redirect the child's stdout onto
# a pipe, exec, and wait. The oracle is the host's own sha256 of the same file, and
# it goes through a *second* guest -- busybox -- so a pass says the parent's pipe, the
# child's redirect and the exec all lined up.
#
# The child runs to completion before the parent resumes (see src/process.cpp), which
# is why the pipe buffer is unbounded and why this is `capture_output` rather than a
# streaming read.
if [ -f guests/busybox ]; then
    cp guests/busybox guests/sysroot/busybox 2>/dev/null || true
    want="$(sha256sum guests/busybox | cut -d' ' -f1)"
    got=$($EMU $PY -c '
import subprocess
r = subprocess.run(["/busybox","sha256sum","/busybox"], capture_output=True)
print(r.returncode, r.stdout.split()[0].decode())' 2>/dev/null | norm)
    check "python subprocess (fork/exec/pipe/wait)" "0 $want" "$got"
else
    echo "skip python subprocess (no guests/busybox)"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
