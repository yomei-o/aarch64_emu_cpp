#!/bin/sh
# Unpack the macOS libSystem set into guests/macos/, where the test suite looks for it.
#
#   sh prebuilt/unpack.sh
#   ./aarch64emu --root guests/macos guests/macos/hello
set -e
cd "$(dirname "$0")/.."

ARCHIVE=prebuilt/macos-libsystem-objc-15.7.4-arm64e.tar.xz
DEST=guests/macos
WANT=7347f3be562ae48aea5cc966d8c6c8007b66ae79581bcb5e6561ca6fa4bbfea3

[ -f "$ARCHIVE" ] || { echo "$ARCHIVE is not here; see prebuilt/README.md"; exit 1; }

# The checksum is checked rather than assumed: these are binaries nobody can eyeball,
# and a truncated clone is a plausible way to get a guest that fails somewhere strange.
if command -v sha256sum >/dev/null 2>&1; then GOT=$(sha256sum "$ARCHIVE" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then GOT=$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)
else GOT=$WANT; echo "note: no sha256 tool, skipping the checksum"; fi
[ "$GOT" = "$WANT" ] || { echo "checksum mismatch:"; echo "  want $WANT"; echo "  got  $GOT"; exit 1; }

mkdir -p "$DEST"
tar xJf "$ARCHIVE" -C "$DEST"
echo "unpacked into $DEST/  ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
echo
echo "try:  ./aarch64emu --root $DEST $DEST/hello"
