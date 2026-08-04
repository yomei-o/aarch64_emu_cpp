#!/usr/bin/env python3
"""Disassemble N instructions at a virtual address inside a Mach-O.

    python tools/dis_macho.py <file> <hex addr> [count]

Turns the bytes into `.inst` directives and prints the assembler's own disassembly with
real addresses, which is the only way to read a cache-extracted library: the addresses
are the cache's, no debugger will load the file, and guessing at an encoding is how a
morning goes.
"""
import os
import struct
import subprocess
import sys
import tempfile


def find(path, addr):
    d = open(path, "rb").read()
    ncmds = struct.unpack_from("<I", d, 16)[0]
    o = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, o)
        if cmd == 0x19:
            name = d[o + 8:o + 24].split(b"\0")[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", d, o + 24)
            if vmaddr <= addr < vmaddr + filesize:
                return d, fileoff + (addr - vmaddr), name
        o += cmdsize
    return None, None, None


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, addr = sys.argv[1], int(sys.argv[2], 16)
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 24
    d, off, seg = find(path, addr)
    if d is None:
        print(f"{addr:x} is not inside any segment of {path} that has file content")
        return 1

    tmp = tempfile.mkdtemp()
    src, obj = os.path.join(tmp, "d.s"), os.path.join(tmp, "d.o")
    with open(src, "w") as f:
        f.write(".arch armv8.4-a\n")
        for i in range(0, count * 4, 4):
            f.write(f"  .inst 0x{struct.unpack_from('<I', d, off + i)[0]:08x}\n")
    if subprocess.call(["clang", "--target=aarch64-linux-gnu", "-c", "-o", obj, src]) != 0:
        return 1
    out = subprocess.run(["llvm-objdump", "-d", obj], capture_output=True, text=True).stdout

    print(f"{path}  {seg}  {addr:x}")
    for line in out.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2 or not parts[0].strip():
            continue
        try:
            off_here = int(parts[0].strip(), 16)
        except ValueError:
            continue
        print(f"  {addr + off_here:012x}: {parts[1].strip()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
