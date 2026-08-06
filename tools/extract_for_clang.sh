#!/bin/sh
# Run this ON THE MAC, from this directory.
#
#     cd <this folder> && sh extract_for_clang.sh
#
# Pulls the shared-cache libraries `ld` needs out of the local dyld cache and
# tars them up as clang_cache_libs.tar.gz, whose paths are relative to the guest
# root.
#
# Why these are not in clang_dylibs.tar.gz: that script packaged the dependencies
# that are real files inside the CommandLineTools (libtapi, libLTO).  These two
# are not - the SDK carries only `.tbd` stubs for them, which is the tell that the
# code lives in the shared cache:
#
#     sdk/usr/lib/libcodedirectory.tbd
#     sdk/usr/lib/swift/libswiftDemangle.tbd
#
# `ld` names them `@rpath/...` and its LC_RPATH is `@executable_path/../lib/`, so
# in the guest they resolve to /usr/lib/libcodedirectory.dylib and
# /usr/lib/swift/libswiftDemangle.dylib.  libcodedirectory is the one that has to
# be real: ld ad-hoc signs every arm64 macOS binary it produces, through
# libcd_create.  libswiftDemangle only prettifies Swift names in diagnostics.
#
# A couple of minutes, a few MB.
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/dsc_extract.c"
OUT="$HERE/clang_cache_libs"

[ -f "$SRC" ] || { echo "dsc_extract.c is not next to this script."; exit 1; }

CACHE=""
for c in \
  /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
  /System/Library/dyld/dyld_shared_cache_arm64e
do
  [ -f "$c" ] && { CACHE="$c"; break; }
done
[ -n "$CACHE" ] || { echo "no arm64e shared cache found"; exit 1; }
echo "cache: $CACHE"

cc -O2 -o "$HERE/dsc_extract_new" "$SRC"

# `--only` bounds the dependency closure the same way the Python extraction does;
# without it these two reach most of the system.  The swift prefix is separate
# because /usr/lib/swift is not covered by a /usr/lib/ prefix match in the
# extractor's own path test - keep it listed even if it looks redundant.
"$HERE/dsc_extract_new" -o "$OUT" \
  --only /usr/lib/ \
  --only /usr/lib/swift/ \
  --only /System/Library/Frameworks/ \
  --only /System/Library/PrivateFrameworks/ \
  "$CACHE" \
  /usr/lib/libcodedirectory.dylib \
  /usr/lib/swift/libswiftDemangle.dylib

echo
echo "extracted $(find "$OUT" -type f | wc -l | tr -d ' ') files, $(du -sh "$OUT" | cut -f1)"
find "$OUT" -type f | sed "s|$OUT|  |"

# Paths relative to the guest root, so it unpacks straight over guests/macos_clang.
tar czf clang_cache_libs.tar.gz -C "$OUT" .
ls -lh clang_cache_libs.tar.gz
echo "== done -- untar with:  tar xzf clang_cache_libs.tar.gz -C guests/macos_clang"
