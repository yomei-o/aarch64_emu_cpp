#!/usr/bin/env python3
"""Turn a list of sampled PCs into a per-function profile.

    aarch64emu --root guests/macos --sample 1 prog 2>&1 | grep '^\\[pc\\]' | awk '{print $2}' > pcs
    python tools/profile_pcs.py guests/macos pcs [top]

Answers "where did those thirty-five thousand instructions go", which is the question that
follows any "it ran and did nothing" — a call that returns without an error but without an
effect either. Attribution is by nearest preceding symbol, cached per address, so a trace
of a hundred thousand samples costs one pass.
"""
import collections
import os
import struct
import sys


def images(root):
    out = []
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                d = open(path, "rb").read()
            except OSError:
                continue
            if len(d) < 32 or struct.unpack_from("<I", d, 0)[0] != 0xFEEDFACF:
                continue
            ncmds = struct.unpack_from("<I", d, 16)[0]
            o, text, syms = 32, None, []
            symoff = nsyms = stroff = 0
            for _ in range(ncmds):
                cmd, cmdsize = struct.unpack_from("<II", d, o)
                if cmd == 0x19 and d[o + 8:o + 14] == b"__TEXT":
                    vmaddr, vmsize = struct.unpack_from("<QQ", d, o + 24)
                    text = (vmaddr, vmaddr + vmsize)
                elif cmd == 0x02:
                    symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", d, o + 8)
                o += cmdsize
            if not text:
                continue
            for i in range(nsyms):
                e = symoff + i * 16
                strx = struct.unpack_from("<I", d, e)[0]
                val = struct.unpack_from("<Q", d, e + 8)[0]
                if text[0] <= val < text[1]:
                    nm = d[stroff + strx:stroff + strx + 200].split(b"\0")[0]
                    syms.append((val, nm.decode("utf-8", "replace")))
            syms.sort()
            out.append((os.path.basename(path), text, syms))
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    root, pcfile = sys.argv[1], sys.argv[2]
    top = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    imgs = images(root)
    cache = {}

    def attribute(addr):
        if addr in cache:
            return cache[addr]
        label = "(unmapped)"
        for base, (lo, hi), syms in imgs:
            if not (lo <= addr < hi):
                continue
            label = f"{base}: ?"
            i, j = 0, len(syms)
            while i < j:
                mid = (i + j) // 2
                if syms[mid][0] <= addr:
                    i = mid + 1
                else:
                    j = mid
            if i:
                label = f"{base}: {syms[i - 1][1]}"
            break
        cache[addr] = label
        return label

    counts = collections.Counter()
    total = 0
    with open(pcfile) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            counts[attribute(int(line, 16))] += 1
            total += 1

    print(f"{total} samples")
    for label, n in counts.most_common(top):
        print(f"  {100.0 * n / total:5.1f}%  {n:7}  {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
