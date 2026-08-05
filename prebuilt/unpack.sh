#!/bin/sh
# Unpack the macOS guest trees, where the test suite looks for them.
#
#   sh prebuilt/unpack.sh              # both
#   sh prebuilt/unpack.sh hello        # just the 48-library libSystem set
#   sh prebuilt/unpack.sh python       # just CPython and its closure
#
#   ./aarch64emu --root guests/macos guests/macos/hello
#   ./aarch64emu --dyld-sections --root guests/macos_py \
#       guests/macos_py/install/bin/python3.13 -c 'print(1+1)'
#
# The Python set is **split into parts**: xz gets it to 64 MB, and GitHub warns
# above 50 MB for a single file. `cat` puts it back together, which is why the
# checksum below is of the *joined* archive rather than of either half -- a
# missing part and a corrupt part should fail the same way, loudly.
set -e
cd "$(dirname "$0")/.."

# Checked rather than assumed: these are binaries nobody can eyeball, and a
# truncated clone or a half-fetched LFS object is a plausible way to end up with a
# guest that fails somewhere strange and far away.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
    else echo SKIP; fi
}
check() {   # check <file> <want>
    got=$(sha256_of "$1")
    [ "$got" = SKIP ] && { echo "note: no sha256 tool, skipping the checksum"; return 0; }
    [ "$got" = "$2" ] && return 0
    echo "checksum mismatch for $1:"; echo "  want $2"; echo "  got  $got"
    return 1
}

unpack_hello() {
    ARCHIVE=prebuilt/macos-libsystem-objc-15.7.4-arm64e.tar.xz
    DEST=guests/macos
    WANT=7347f3be562ae48aea5cc966d8c6c8007b66ae79581bcb5e6561ca6fa4bbfea3
    [ -f "$ARCHIVE" ] || { echo "$ARCHIVE is not here; see prebuilt/README.md"; return 1; }
    check "$ARCHIVE" "$WANT"
    mkdir -p "$DEST"
    tar xJf "$ARCHIVE" -C "$DEST"
    echo "unpacked into $DEST/  ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
    echo "try:  ./aarch64emu --root $DEST $DEST/hello"
}

unpack_python() {
    PARTS='prebuilt/macos-python-3.13.14-arm64.tar.xz.aa prebuilt/macos-python-3.13.14-arm64.tar.xz.ab'
    DEST=guests/macos_py
    WANT=ebece7f8f42c8e82c7a7a6ee77fcef5baf15c8e1e69cc37b7ecf05cda85cd087
    JOINED=prebuilt/.macos-python-joined.tar.xz
    for p in $PARTS; do
        [ -f "$p" ] || { echo "$p is not here; see prebuilt/README.md"; return 1; }
    done
    cat $PARTS > "$JOINED"
    if check "$JOINED" "$WANT"; then :; else rm -f "$JOINED"; return 1; fi
    mkdir -p "$DEST"
    tar xJf "$JOINED" -C "$DEST"
    rm -f "$JOINED"
    echo "unpacked into $DEST/  ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
    echo "try:  ./aarch64emu --dyld-sections --root $DEST \\"
    echo "        $DEST/install/bin/python3.13 -c 'print(1+1)'"
}

case "${1:-all}" in
    hello)  unpack_hello ;;
    python) unpack_python ;;
    all)    unpack_hello; echo; unpack_python ;;
    *)      echo "usage: sh prebuilt/unpack.sh [hello|python|all]"; exit 2 ;;
esac
