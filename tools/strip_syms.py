#!/usr/bin/env python3
"""Drop the symbol table from cache-extracted dylibs, for shipping.

    python tools/strip_syms.py guests/macos            # in place, with a keep-list
    python tools/strip_syms.py --dry-run guests/macos  # just say what it would save

A dyld shared cache keeps one symbol table for the whole system, so every library
extracted from it carries its own copy of the names it needs -- and across a
hundred libraries that is a third of the bytes. Nothing at *run* time reads them:
binding goes through the export trie, which is a different LINKEDIT blob.

Three libraries are the exception and are left alone, because `macho_lookup_symtab`
looks up private symbols in them that the trie does not export:

    libdyld.dylib          dyld4::gAPIs -- the API object the emulator stands in for
    libsystem_kernel.dylib bootstrap_port -- which the host fills in before the guest
    libSystem.B.dylib      _exit -- called when an LC_MAIN `main` returns

`tools/whichlib.py` and `tools/dis_macho.py` read symbols to name an address, so a
stripped tree is worse to debug in. That is the trade: strip a copy for shipping,
keep the full one for working.

What it does is deliberately minimal. LC_SYMTAB's `nsyms` and `strsize` go to zero
and the bytes they covered are zeroed in place. The file does not shrink -- moving
LINKEDIT would mean relocating the export trie, the chained fixups and the indirect
symbol table, which is a rewrite rather than an edit -- but a run of zeros costs
almost nothing once the archive is compressed, which is the point.
"""
import os
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B

KEEP = ("libdyld.dylib", "libsystem_kernel.dylib", "libSystem.B.dylib")


def strip(path, dry_run):
    with open(path, "rb") as f:
        d = bytearray(f.read())
    if len(d) < 32 or struct.unpack_from("<I", d, 0)[0] != MH_MAGIC_64:
        return 0
    ncmds = struct.unpack_from("<I", d, 16)[0]
    o, saved = 32, 0
    for _ in range(ncmds):
        if o + 8 > len(d):
            break
        cmd, cmdsize = struct.unpack_from("<II", d, o)
        if cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", d, o + 8)
            saved = nsyms * 16 + strsize
            if not dry_run:
                # Zero the bytes first, then the counts -- in that order, so a run
                # interrupted half way leaves a table that is merely empty rather
                # than one whose header disagrees with its contents.
                d[symoff:symoff + nsyms * 16] = b"\0" * (nsyms * 16)
                d[stroff:stroff + strsize] = b"\0" * strsize
                struct.pack_into("<IIII", d, o + 8, symoff, 0, stroff, 0)
        elif cmd == LC_DYSYMTAB and not dry_run:
            # The indirect symbol table stays: a pre-linked library's null __got
            # slots are resolved through it, and it indexes symbols by *number*
            # rather than by name, so it survives an empty symbol table. Only the
            # local/external/undefined ranges, which do not, are cleared.
            struct.pack_into("<8I", d, o + 8, 0, 0, 0, 0, 0, 0, 0, 0)
        o += cmdsize
    if saved and not dry_run:
        with open(path, "wb") as f:
            f.write(d)
    return saved


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    dry_run = "--dry-run" in sys.argv
    if not args:
        print(__doc__)
        return 2
    total, files = 0, 0
    for root in args:
        for dirpath, _, names in os.walk(root):
            for name in names:
                if name in KEEP:
                    continue
                p = os.path.join(dirpath, name)
                try:
                    n = strip(p, dry_run)
                except OSError:
                    continue
                if n:
                    total += n
                    files += 1
    print("%s %d file(s), %.1f MB of symbol table" %
          ("would clear" if dry_run else "cleared", files, total / 1048576))
    return 0


if __name__ == "__main__":
    sys.exit(main())
