#!/bin/sh
# Package Apple clang + ld + a minimal SDK for the aarch64 emulator on Windows.
#
# Run on the Mac:   cd /Volumes/.../test  (this folder)   sh pack_clang.sh
# Everything it prints also lands in pack_clang.out, and the result is
# macos_clang.tar.gz next to this script.
#
# What goes in and why:
#   usr/bin/clang, usr/bin/ld    the compiler and the linker (ld-prime), both
#                                arm64 Mach-O; the emulator runs them directly
#   lib/clang/*/include          clang's builtin headers (stdarg.h, arm_neon.h...)
#   SDK usr/include              the C headers
#   SDK usr/lib/libSystem.tbd    ld links against *text stubs*, not dylibs, so
#     + everything .tbd it       the "libraries" are small YAML files. The real
#       re-exports               code comes from the emulator's shared-cache
#                                extraction at run time, same as the python guest.
set -e
exec > pack_clang.out 2>&1

CLT=/Library/Developer/CommandLineTools
SDK=$(xcrun --show-sdk-path)
OUT=macos_clang
rm -rf "$OUT"
mkdir -p "$OUT/usr/bin"

echo "== CLT: $CLT"
echo "== SDK: $SDK"

# -- the two programs -------------------------------------------------------
cp "$CLT/usr/bin/clang" "$OUT/usr/bin/clang"
cp "$CLT/usr/bin/ld"    "$OUT/usr/bin/ld"
file "$OUT/usr/bin/clang" "$OUT/usr/bin/ld"

# clang finds its builtin headers relative to its own path: ../lib/clang/<ver>/include
RES=$("$CLT/usr/bin/clang" -print-resource-dir)
echo "== resource dir: $RES"
mkdir -p "$OUT/usr/lib/clang"
cp -R "$RES" "$OUT/usr/lib/clang/"

# -- the SDK, headers and text stubs only -----------------------------------
mkdir -p "$OUT/sdk/usr"
cp -R "$SDK/usr/include" "$OUT/sdk/usr/include"
mkdir -p "$OUT/sdk/usr/lib"
# every .tbd, keeping the directory shape (libSystem re-exports usr/lib/system/*.tbd)
(cd "$SDK/usr/lib" && find . -name '*.tbd' | tar cf - -T -) | (cd "$OUT/sdk/usr/lib" && tar xf -)
echo "== tbd count: $(find "$OUT/sdk/usr/lib" -name '*.tbd' | wc -l)"

# -- what does clang exec? worth knowing before the emulator finds out ------
echo "== clang -### for a hello.c (the process tree it will want):"
printf 'int main(void){return 0;}\n' > /tmp/pc_probe.c
"$CLT/usr/bin/clang" -isysroot "$SDK" -### /tmp/pc_probe.c -o /tmp/pc_probe 2>&1 | tail -5

# -- sanity: does this *subset* actually compile hello.c on the Mac? --------
echo "== compiling hello.c against only the packaged subset:"
printf '#include <stdio.h>\nint main(void){printf("hi\\n");return 0;}\n' > /tmp/pc_hello.c
"$OUT/usr/bin/clang" -isysroot "$PWD/$OUT/sdk" /tmp/pc_hello.c -o /tmp/pc_hello && /tmp/pc_hello

# -- pack -------------------------------------------------------------------
tar czf macos_clang.tar.gz "$OUT"
ls -lh macos_clang.tar.gz
echo "== done"
