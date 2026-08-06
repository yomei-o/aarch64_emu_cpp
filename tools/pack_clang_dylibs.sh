#!/bin/sh
# Collect the dylibs Apple's clang and ld need that are *not* in the shared cache.
#
#     cd /Volumes/.../test      (this folder)
#     sh pack_clang_dylibs.sh
#
# pack_clang.sh packaged the two programs, the headers and the .tbd stubs, but not
# the libraries the programs themselves load: `ld` failed at startup with
#
#     Library not loaded: @rpath/libtapi.dylib
#
# The split that matters is *where a dependency lives*.  Anything under /usr/lib or
# /System is in the dyld shared cache, and the emulator supplies those from its own
# extraction - packaging them would be pointless and huge.  Anything else is a real
# file on disk, shipped inside the CommandLineTools, and has to travel.  So rather
# than guessing at a list, this walks `otool -L` from both programs, resolves
# @rpath/@loader_path against each binary's LC_RPATH, and copies what it finds.
# Whatever `ld` wants beyond libtapi comes along in the same trip.
#
# Output: clang_dylibs.tar.gz, whose paths are relative to the guest root.
# It prints to the terminal rather than to a log file - add `| tee out.txt` if you
# want both; pack_clang.sh's silent redirect was unpleasant to watch over a share.
set -e

CLT=${CLT:-/Library/Developer/CommandLineTools}
OUT=clang_dylibs

echo "== CLT: $CLT"
rm -rf "$OUT" "$OUT.list"
mkdir -p "$OUT"
: > "$OUT.list"
: > "$OUT.seen"
: > "$OUT.skipped"

# The install names a binary can be loaded through, so a dependency of a
# dependency resolves the same way dyld would resolve it.
rpaths_of() {
    otool -l "$1" 2>/dev/null | awk '
        /cmd LC_RPATH/ { want = 1 }
        want && /path /  { print $2; want = 0 }
    '
}

# Every LC_LOAD_DYLIB install name, minus the first line (which is the file
# itself) and the version annotations.
deps_of() {
    otool -L "$1" 2>/dev/null | tail -n +2 | sed 's/ (compatibility.*//; s/^[[:space:]]*//'
}

# In the shared cache?  Then the emulator already has it and we must not ship it.
in_shared_cache() {
    case "$1" in
        /usr/lib/*|/System/*) return 0 ;;
        *) return 1 ;;
    esac
}

walk() {                                   # walk <binary>
    bin=$1
    rp=$(rpaths_of "$bin")
    loader_dir=$(dirname "$bin")

    deps_of "$bin" | while read -r dep; do
        [ -n "$dep" ] || continue

        # Resolve the three install-name prefixes dyld understands.  @rpath is the
        # one that matters here: `ld` names libtapi as @rpath/libtapi.dylib and
        # carries an LC_RPATH pointing at its own ../lib.
        resolved=""
        case "$dep" in
            @rpath/*)
                tail=${dep#@rpath/}
                for r in $rp; do
                    cand=$(echo "$r" | sed "s|@loader_path|$loader_dir|; s|@executable_path|$loader_dir|")
                    if [ -f "$cand/$tail" ]; then resolved="$cand/$tail"; break; fi
                done
                ;;
            @loader_path/*|@executable_path/*)
                tail=${dep#@*path/}
                [ -f "$loader_dir/$tail" ] && resolved="$loader_dir/$tail"
                ;;
            /*)
                [ -f "$dep" ] && resolved="$dep"
                ;;
        esac

        if in_shared_cache "$dep"; then
            echo "  cache   $dep"
            continue
        fi
        if [ -z "$resolved" ]; then
            echo "  MISSING $dep   (from $(basename "$bin"))"
            echo "$dep" >> "$OUT.skipped"
            continue
        fi
        # Already handled?  A diamond in the dependency graph is normal.
        if grep -qxF "$resolved" "$OUT.seen" 2>/dev/null; then continue; fi
        echo "$resolved" >> "$OUT.seen"

        # Where it goes in the guest.  A CommandLineTools path becomes the same
        # place under the guest's /usr, because that is where clang and ld live
        # there - so @loader_path/../lib resolves to /usr/lib either way.
        case "$resolved" in
            "$CLT"/*) rel="${resolved#$CLT/}" ;;
            *)        rel="usr/lib/$(basename "$resolved")" ;;
        esac
        echo "  copy    $dep"
        echo "            -> $rel"
        mkdir -p "$OUT/$(dirname "$rel")"
        cp "$resolved" "$OUT/$rel"
        echo "$resolved" >> "$OUT.list"
        walk "$resolved"
    done
}

for prog in "$CLT/usr/bin/clang" "$CLT/usr/bin/ld"; do
    echo "== $prog"
    [ -x "$prog" ] || { echo "  not there, skipping"; continue; }
    echo "   rpaths: $(rpaths_of "$prog" | tr '\n' ' ')"
    walk "$prog"
done

# clang hands the linker an absolute -lto_library path built from its own install
# directory, so libLTO has to sit at the guest's /usr/lib whether or not anything
# lists it as a dependency.
if [ -f "$CLT/usr/lib/libLTO.dylib" ] && [ ! -f "$OUT/usr/lib/libLTO.dylib" ]; then
    echo "== also libLTO.dylib (clang passes -lto_library <installdir>/../lib/libLTO.dylib)"
    mkdir -p "$OUT/usr/lib"
    cp "$CLT/usr/lib/libLTO.dylib" "$OUT/usr/lib/"
fi

echo "== collected:"
find "$OUT" -type f | sed 's/^/    /'
if [ -s "$OUT.skipped" ]; then
    echo "== could not resolve (worth a look):"
    sort -u "$OUT.skipped" | sed 's/^/    /'
fi

# The tar's paths are relative to the *guest root*, so it unpacks straight over
# guests/macos_clang on the other side.
tar czf clang_dylibs.tar.gz -C "$OUT" .
ls -lh clang_dylibs.tar.gz
rm -f "$OUT.list" "$OUT.seen" "$OUT.skipped"
echo "== done -- untar with:  tar xzf clang_dylibs.tar.gz -C guests/macos_clang"
