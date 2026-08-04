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
kExpect=199279
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

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
