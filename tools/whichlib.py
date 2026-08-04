#!/usr/bin/env python3
"""Which extracted library owns an address, and which symbol is it in?

    python tools/whichlib.py guests/macos 18027CCD4 [more addresses...]

Cache-extracted libraries keep the cache's addresses, so a PC out of a trace means
nothing until it is attributed. This does the attribution, including the nearest
preceding symbol -- which is usually the function name.
"""
import os
import struct
import sys


def images(root):
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                d = open(path, "rb").read()
            except OSError:
                continue
            if len(d) < 32 or struct.unpack_from("<I", d, 0)[0] != 0xFEEDFACF:
                continue
            yield path, d


def parse(d):
    ncmds = struct.unpack_from("<I", d, 16)[0]
    o, segs, sym = 32, [], (0, 0, 0)
    for _ in range(ncmds):
        if o + 8 > len(d):
            break
        cmd, cmdsize = struct.unpack_from("<II", d, o)
        if cmd == 0x19:
            name = d[o + 8:o + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, o + 24)
            segs.append((name, vmaddr, vmsize))
        elif cmd == 0x02:
            symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", d, o + 8)
            sym = (symoff, nsyms, stroff)
        o += cmdsize
    return segs, sym


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    root = sys.argv[1]
    targets = [int(a, 16) for a in sys.argv[2:]]
    cache = [(p, d, *parse(d)) for p, d in images(root)]

    for t in targets:
        hit = None
        for path, d, segs, (symoff, nsyms, stroff) in cache:
            for name, vmaddr, vmsize in segs:
                if vmaddr <= t < vmaddr + vmsize:
                    hit = (path, name, d, symoff, nsyms, stroff)
                    break
            if hit:
                break
        if not hit:
            print(f"{t:012x}  in no extracted library")
            continue
        path, seg, d, symoff, nsyms, stroff = hit
        best = None
        for i in range(nsyms):
            e = symoff + i * 16
            strx = struct.unpack_from("<I", d, e)[0]
            val = struct.unpack_from("<Q", d, e + 8)[0]
            if 0 < val <= t and (best is None or t - val < best[0]):
                nm = d[stroff + strx:stroff + strx + 200].split(b"\0")[0]
                best = (t - val, nm.decode("utf-8", "replace"), val)
        where = f"{best[1]} +{best[0]}" if best and best[0] < 0x4000 else "(no nearby symbol)"
        print(f"{t:012x}  {os.path.relpath(path, root)}  {seg}  {where}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
