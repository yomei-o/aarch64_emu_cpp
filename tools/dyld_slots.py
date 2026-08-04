#!/usr/bin/env python3
"""Map dyld API vtable slots to the libdyld functions that call them.

    python tools/dyld_slots.py guests/macos/usr/lib/system/libdyld.dylib

libdyld.dylib is a shim: each `_dyld_*` entry point is a virtual call through
`dyld4::gAPIs`, and every one of them looks the same --

    mov x17, #<offset>
    add x16, x16, x17
    ldr x8, [x16]
    ... blraa x8, x17

so scanning for that shape and naming the enclosing symbol gives the whole slot table at
once. Without it, an unimplemented slot is a number: this turns it into
`_dyld_get_active_platform` before anything has to be guessed at.
"""
import struct
import sys


def load(path):
    d = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", d, 16)[0]
    o, segs, sym = 32, [], (0, 0, 0)
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, o)
        if cmd == 0x19:
            name = d[o + 8:o + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, o + 24)
            segs.append((name, vmaddr, fileoff, filesize))
        elif cmd == 0x02:
            sym = struct.unpack_from("<III", d, o + 8)[0:2] + (
                struct.unpack_from("<I", d, o + 16)[0],)
        o += cmdsize
    return d, segs, sym


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    d, segs, (symoff, nsyms, stroff) = load(sys.argv[1])

    # Every symbol with an address, sorted, so a code address can be named.
    syms = []
    for i in range(nsyms):
        e = symoff + i * 16
        strx = struct.unpack_from("<I", d, e)[0]
        val = struct.unpack_from("<Q", d, e + 8)[0]
        if val:
            nm = d[stroff + strx:stroff + strx + 200].split(b"\0")[0]
            syms.append((val, nm.decode("utf-8", "replace")))
    syms.sort()

    def name_of(addr):
        lo, hi = 0, len(syms)
        while lo < hi:
            mid = (lo + hi) // 2
            if syms[mid][0] <= addr:
                lo = mid + 1
            else:
                hi = mid
        return syms[lo - 1][1] if lo else "?"

    found = {}
    for segname, vmaddr, fileoff, filesize in segs:
        if segname != "__TEXT":
            continue
        for off in range(0, filesize - 12, 4):
            a, b, c = struct.unpack_from("<III", d, fileoff + off)
            slot = None
            # Two shapes, because the compiler folds the offset either into a register or
            # into the load:
            #   mov x17, #off ; add x16, x16, x17 ; ldr x8, [x16]
            #   ldr x8, [x16, #off]
            # The destination register varies (x1 as often as x8), so it is masked out.
            # Requiring x8 found five slots out of a hundred and thirty.
            if ((a & 0xFFE0001F) == 0xD2800011 and b == 0x8B110210
                    and (c & 0xFFFFFFE0) == 0xF9400200):
                imm = (a >> 5) & 0xFFFF
                if imm % 8 == 0:
                    slot = imm // 8
            elif (a & 0xFFC003E0) == 0xF9400200 and (a >> 10) & 0xFFF:
                slot = (a >> 10) & 0xFFF
            if slot is None:
                continue
            found.setdefault(slot, name_of(vmaddr + off))

    print(f"{len(found)} slot(s) identified")
    for slot in sorted(found):
        print(f"  slot {slot:4}  +0x{slot * 8:<5X}  {found[slot]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
