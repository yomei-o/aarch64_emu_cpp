#!/bin/sh
# The Alpine gcc toolchain, end to end: compile, link, and run the result.
#
# This is the sharpest test in the tree, and the reason is *who* checks the answer.
# The compile is checked by the emulator itself: the hello that gcc produces runs
# on the same CPU that ran gcc. A wrong bit anywhere -- in cc1's SIMD-heavy
# hashing, in as writing relocations, in ld resolving them -- lands in the output
# binary, and the output binary is then executed instruction by instruction. The
# loop closes with no oracle needed.
#
# What one `gcc hello.c -o hello` actually exercises: the driver forks and execs
# cc1, as, collect2, and ld (four child processes, each a full musl start-up),
# pipes between them, temporary files created and unlinked, and -- the part that
# cost a day -- musl's ld.so telling libraries apart by st_dev/st_ino, which is
# why Files::fill_stat hashes the path into the inode instead of answering 1.
#
# Skipped when the toolchain is absent. It is ~120 MB of Alpine packages and not
# in the repository; resume.md's gcc section says how to fetch it.
set -e
cd "$(dirname "$0")/.."
EMU=${EMU:-./aarch64emu}
R=guests/gccroot
GCC=$R/usr/bin/gcc
if [ ! -f "$GCC" ]; then
    echo "skip gcc tests (no $GCC -- see resume.md for the Alpine package list)"
    exit 0
fi

pass=0; fail=0
check() {   # check <label> <expected> <actual>
    if [ "$2" = "$3" ]; then echo "ok   $1"; pass=$((pass+1))
    else echo "FAIL $1"; echo "     want: $2"; echo "     got:  $3"; fail=$((fail+1)); fi
}
run() { MSYS2_ARG_CONV_EXCL='*' $EMU --root $R "$@"; }

# ---- gcc --version: the driver alone, no children ------------------------------
got=$(run $GCC --version 2>/dev/null | tr -d '\015' | head -1)
check "gcc --version" "gcc (Alpine 13.2.1_git20240309) 13.2.1 20240309" "$got"

# ---- gcc -c: driver -> cc1 -> as, and a real relocatable comes out --------------
cat > $R/t.c <<'EOF'
int add(int a, int b) { return a + b; }
EOF
rm -f $R/t.o
run $GCC -c /t.c -o /t.o 2>/dev/null
# The first four bytes are the ELF magic; read them without needing readelf.
got=$(od -An -tx1 -N4 $R/t.o 2>/dev/null | tr -d ' \015')
check "gcc -c produces an ELF object" "7f454c46" "$got"

# ---- the whole pipeline, and then the emulator runs what it built ---------------
cat > $R/emit.c <<'EOF'
#include <stdio.h>
int main(void) {
    printf("built by the guest, run by the guest: %d\n", 6 * 7);
    return 0;
}
EOF
rm -f $R/emit
run $GCC /emit.c -o /emit 2>/dev/null
# The program path is a *host* path -- the loader opens it before any --root
# translation exists -- where the paths gcc sees above are guest paths under it.
got=$(run $R/emit 2>/dev/null | tr -d '\015')
check "gcc-built binary runs under the emulator" \
      "built by the guest, run by the guest: 42" "$got"

rm -f $R/t.c $R/t.o $R/emit.c $R/emit
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
