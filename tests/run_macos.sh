#!/bin/sh
# The macOS guest, in both memory modes, with the counts compared.
#
# Unlike the other four suites there is no host oracle here: an x86 host cannot run
# Apple's arm64 libraries, so nothing outside the emulator can say what this program
# should print. What can be checked is stronger than it sounds:
#
#   1. **The output**, which the guest's own libSystem produced -- printf through
#      stdio through `write`, and `exit` flushing it on the way out.
#   2. **Permissive and --strict agree, instruction for instruction.** This is the
#      real assertion. `--strict` stops the run at the first read of a page nobody
#      mapped; permissive mode hands the guest a zero and carries on. If the two
#      execute the same number of instructions then no branch anywhere in the run
#      turned on a zero that came from nowhere -- which is exactly the failure mode
#      that produced a guest that printed correctly for months while `environ` was
#      null and every getenv in the process answered "unset".
#   3. **The count does not drift.** It is checked against a recorded number rather
#      than only against itself, because a change that quietly adds fifty thousand
#      instructions to a startup is worth noticing even when the output is right.
#      Update kExpect deliberately, in the commit that changes it, with the reason.
#
# Skipped when the guest tree is absent -- it is Apple's code and is not in the
# repository. `sh prebuilt/unpack.sh` puts it there.
set -e
cd "$(dirname "$0")/.."
EMU=${EMU:-./aarch64emu}
G=guests/macos/hello
if [ ! -f "$G" ]; then
    echo "skip macOS tests (no $G -- run: sh prebuilt/unpack.sh)"
    exit 0
fi

# What the run costs today. Tolerance is 2%: the count is deterministic on one
# build, but the two compilers do not have to agree on, say, how many times a
# libc loop runs when a host-supplied timestamp differs.
#
# 199279 -> 192101 when MIG `task_set_special_port` (3410) started succeeding.
# libxpc stores the bootstrap port back after adding a send right, and a failure
# there sent it down a reporting path -- os_assumes_log, a sysctl, three dyld
# slots -- that did seven thousand instructions of work to complain about
# something that is now simply fine. A count going *down* is the shape a removed
# failure path has.
kExpect=192101
kTolerance=2

pass=0; fail=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1))
    else echo "FAIL $1"; echo "     want: $2"; echo "     got:  $3"; fail=$((fail+1)); fi
}

want="hello from real macOS"
count() {   # count <extra-flags...> -- instructions, or empty if the run failed
    $EMU --stats "$@" --root guests/macos "$G" 2>&1 |
        tr -d '\015' | sed -n 's/^\[stats\] \([0-9]*\) instructions.*/\1/p'
}

got=$($EMU --root guests/macos "$G" 2>/dev/null | tr -d '\015' | tail -1)
check "macos hello" "$want" "$got"

got=$($EMU --strict --root guests/macos "$G" 2>/dev/null | tr -d '\015' | tail -1)
check "macos hello --strict" "$want" "$got"

n=$(count)
s=$(count --strict)
check "macos permissive and --strict run the same instructions" "$n" "$s"

# Both are reported, because "the count moved" and "the count is missing" are
# different failures and the second one means the run did not finish.
if [ -z "$n" ]; then
    echo "FAIL macos instruction count (no [stats] line -- the run did not finish)"
    fail=$((fail+1))
else
    lo=$((kExpect - kExpect * kTolerance / 100))
    hi=$((kExpect + kExpect * kTolerance / 100))
    if [ "$n" -ge "$lo" ] && [ "$n" -le "$hi" ]; then
        echo "ok   macos instruction count ($n, expected ~$kExpect)"
        pass=$((pass+1))
    else
        echo "FAIL macos instruction count"
        echo "     want: $lo..$hi (recorded $kExpect)"
        echo "     got:  $n"
        echo "     If this is intended, update kExpect in this script and say why."
        fail=$((fail+1))
    fi
fi

# ---- four Darwin threads, a mutex, and an answer the host can check -----------
#
# The one macOS guest that does have an oracle, and it needs no Mac and no
# emulator to compute: the workers sum 1..1000, 1..2000, 1..3000 and 1..4000, so
# the total is fixed arithmetic and the guest prints what it expected alongside
# what it got. A thread that never ran contributes zero and says so -- which is
# exactly how the missing preemption in the Darwin run loop was found.
#
# `--strict` runs it too, because thread creation is where the host invents the
# most memory on the guest's behalf: the TSD array, the mach port in tsd[3], and
# a stack the guest allocated but the kernel is supposed to know about.
T=guests/macos/threads
if [ -f "$T" ]; then
    want="total 15005000 (expected 15005000)"
    got=$($EMU --root guests/macos "$T" 2>/dev/null | tr -d '\015' | tail -1)
    check "macos threads (bsdthread_create + ulock)" "$want" "$got"
    got=$($EMU --strict --root guests/macos "$T" 2>/dev/null | tr -d '\015' | tail -1)
    check "macos threads --strict" "$want" "$got"
else
    echo "skip macos threads (no $T -- run: sh guests/macos/build.sh threads)"
fi

# ---- thread-local storage, which on Darwin is a loader feature ----------------
#
# A `_Thread_local` reference compiles to a *call* through a descriptor the loader
# fills in, so TLS here is dyld's job rather than the compiler's. Two properties,
# and they fail differently: the declared initial value has to arrive (a thunk that
# hands back a fresh zeroed block passes a write-then-read test but not this), and
# each thread has to get its own (a thunk that hands back one shared block passes
# both of those and is wrong in the way that matters).
L=guests/macos/tls
if [ -f "$L" ]; then
    want='main counter 100 scratch 0
workers 1230 (expected 1230)
main after 107 (expected 107)'
    got=$($EMU --root guests/macos "$L" 2>/dev/null | tr -d '\015')
    check "macos thread-local storage" "$want" "$got"
else
    echo "skip macos tls (no $L -- run: sh guests/macos/build.sh tls)"
fi

# ---- the filesystem, through Apple's own libc ---------------------------------
#
# `tests/file.c` covers open/read/write, but freestanding: it makes the syscalls
# itself, so it tests the syscall table and nothing above it. This guest goes
# through libsystem_c -- getcwd, opendir/readdir, access, fopen/fgets -- which is
# what CPython does when it hunts for its standard library, and which reaches
# fstatfs, getdirentries64 and getrlimit that the freestanding path never touches.
#
# And it has a real oracle: the host computes the same directory count, the same
# FNV hash of the same names, and the same hash of the same line, from the same
# tree. A wrong `struct dirent` offset changes the hash rather than the count,
# which is the failure worth catching -- Darwin's name field starts at 21, not 24.
F=guests/macos/files
if [ -f "$F" ] && command -v python >/dev/null 2>&1; then
    want=$(python - <<'PY'
import os
h0 = 1469598103934665603
def fnv(b):
    h = h0
    for c in b:
        h ^= c
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h
names, n = 0, 0
for e in sorted(os.listdir('guests/macos/usr/lib/system')):
    if e.startswith('.'):
        continue
    names ^= fnv(e.encode())
    n += 1
with open('guests/macos/hello.txt', 'rb') as f:
    line = fnv(f.readline())
print('cwd ok: 1')
print('entries %d' % n)
print('names %x' % names)
print('access libsystem_c 0')
print('access nonesuch -1')
print('access hello 0')
# strcmp and strncmp are stub-and-resolver exports; these lines are what says the
# loader bound the stub to something that really compares.
print('strcmp 0 1 1')
print('strncmp 0 1')
print('line %x' % line)
PY
)
    # Windows python prints CRLF, so the oracle needs the same stripping the guest
    # output gets. Comparing one against the other without it fails on every line
    # while printing two blocks that look identical, which wastes a good minute.
    want=$(printf '%s\n' "$want" | tr -d '\015')
    got=$($EMU --root guests/macos "$F" 2>/dev/null | tr -d '\015')
    check "macos files (libc: opendir, stat, stdio)" "$want" "$got"
else
    echo "skip macos files (no $F -- run: sh guests/macos/build.sh files)"
fi

# ---- the stock macOS CPython --------------------------------------------------
#
# Apple's own build, against Apple's own libraries, and the one macOS guest with a
# *real* oracle: the host's Python computes the same digest from the same bytes.
# A digest is the strongest single check there is -- every byte travels through the
# emulated CPU, and one wrong bit anywhere in six hundred million instructions
# changes the answer.
#
# `--dyld-sections` is not optional here. Without it libobjc never reads the shared
# cache's preoptimized class tables, and libxpc fails its own type check long before
# Python starts.
#
# Skipped without the guest tree: `sh prebuilt/unpack.sh python` puts it there.
P=guests/macos_py/install/bin/python3.13
if [ -f "$P" ] && command -v python >/dev/null 2>&1; then
    code="import sys, platform, hashlib
print(sys.version.split()[0], platform.machine(), sys.platform)
print(hashlib.sha256(b'aarch64_emu_cpp').hexdigest())"
    want="3.13.14 arm64 darwin
$(python -c "import hashlib; print(hashlib.sha256(b'aarch64_emu_cpp').hexdigest())" | tr -d '\015')"
    got=$($EMU --dyld-sections --root guests/macos_py "$P" -c "$code" 2>/dev/null | tr -d '\015')
    check "macos cpython (sha256 against the host's)" "$want" "$got"
else
    echo "skip macos cpython (no $P -- run: sh prebuilt/unpack.sh python)"
fi

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
