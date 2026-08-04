#!/usr/bin/env python3
"""Build a minimal, synthetic dyld shared cache around one real dylib.

`dsc_extract.c` has to be written without a Mac in reach, and its riskiest part is
not the cache header -- that is a documented struct -- but the *Mach-O rewriting*:
packing a library's scattered segments into a fresh file and patching every file
offset in the load commands to match. A mistake there produces a file that still
looks like a dylib and no longer loads.

So this wraps a locally built dylib in just enough cache to be parsed, the extractor
pulls it back out, and the result is run under the emulator against the same host
oracle the ordinary dylib test uses. That checks the rewriting end to end without
any Apple file being involved.

What it does *not* check: the newer image-array location, subcaches, and the real
address layout. Those only exist in a real cache.

    python tools/make_fake_cache.py tests/dylib/libfoo.dylib /libfoo.dylib out.cache
"""
import struct
import sys

HDR = 0x200          # header size we claim
MAP_OFF = 0x200      # where the mapping array goes
IMG_OFF = 0x300      # where the image array goes
STR_OFF = 0x400      # where the path string goes
BODY = 0x1000        # where the dylib's bytes go


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    dylib_path, install_name, out_path = sys.argv[1:4]
    with open(dylib_path, "rb") as f:
        dylib = f.read()

    # The one property that makes this work: a cache maps [address, address+size)
    # to a file offset, and this dylib's segments have vmaddr == fileoff (it was
    # linked to prefer address 0). So a single mapping based at address 0 makes
    # every segment address resolve to the right bytes.
    span = (len(dylib) + 0xFFFF) & ~0xFFFF

    out = bytearray(BODY + len(dylib))
    # dyld_cache_header, only the fields dsc_extract reads.
    out[0:16] = b"dyld_v1  arm64e\x00"[:16]
    struct.pack_into("<I", out, 0x10, MAP_OFF)     # mappingOffset
    struct.pack_into("<I", out, 0x14, 1)           # mappingCount
    struct.pack_into("<I", out, 0x18, IMG_OFF)     # imagesOffsetOld
    struct.pack_into("<I", out, 0x1C, 1)           # imagesCountOld

    # dyld_cache_mapping_info: address, size, fileOffset, maxProt, initProt
    struct.pack_into("<QQQII", out, MAP_OFF, 0, span, BODY, 5, 5)
    # dyld_cache_image_info: address, modTime, inode, pathFileOffset, pad
    struct.pack_into("<QQQII", out, IMG_OFF, 0, 0, 0, STR_OFF, 0)
    name = install_name.encode() + b"\x00"
    out[STR_OFF:STR_OFF + len(name)] = name
    out[BODY:BODY + len(dylib)] = dylib

    with open(out_path, "wb") as f:
        f.write(out)
    print(f"wrote {out_path}: {len(out)} bytes, one image {install_name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
