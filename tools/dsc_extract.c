// dsc_extract — pull individual dylibs out of a macOS dyld shared cache.
//
// Build and run this **on the Mac**; it needs nothing but the system compiler:
//
//     cc -O2 -o dsc_extract dsc_extract.c
//     ./dsc_extract --list  /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
//     ./dsc_extract -o out  /System/.../dyld_shared_cache_arm64e  /usr/lib/libSystem.B.dylib
//
// Why this exists: on macOS 11 and later `/usr/lib/libSystem.B.dylib` and the
// thirty-odd libraries under it are not files. They exist only inside the shared
// cache, which is about 5 GB — far too much to move around for the sake of a libc.
// The dylibs themselves are small; it is the cache that is large.
//
// The extraction is possible because a cache dylib is **pre-linked at a fixed
// address**. Every pointer from one cache library into another is already correct,
// so nothing needs rebasing or binding: copying out a library's segments, keeping
// their addresses, is enough to run it.
//
// What has to be repaired is only the *file* layout. In the cache a dylib's
// segments are scattered — all the __TEXT of every library together, all the
// __DATA together, one shared __LINKEDIT — so the load commands' file offsets
// point into a 5 GB file. This writes each library out as an ordinary Mach-O with
// its segments packed in order and those offsets patched to match, which makes the
// result loadable by anything that reads a Mach-O.
//
// Subcaches (the `.01`, `.02`, … files) are handled by opening every file next to
// the main one and reading each one's own mapping table, so an address is resolved
// by looking it up across all of them. That avoids depending on the exact layout of
// the subcache array, which has changed between OS versions.
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
// mmap on the platform this is meant for, and a plain read elsewhere -- only so the
// file can be compiled and checked on the machine that wrote it. A 5 GB cache wants
// mmap; a syntax check does not care.
#if defined(__APPLE__) || defined(__unix__) || defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#define DSC_HAVE_MMAP 1
#endif
#ifdef _WIN32
#include <direct.h>
#define mkdir(p, m) _mkdir(p)
#endif

// ---- Mach-O and cache structures, only the fields used ----------------------

#define LC_SEGMENT_64          0x19
#define LC_SYMTAB              0x02
#define LC_ID_DYLIB            0x0D
#define LC_LOAD_DYLIB          0x0C
#define LC_LOAD_WEAK_DYLIB     0x80000018u
#define LC_REEXPORT_DYLIB      0x8000001Fu
#define LC_DYLD_INFO_ONLY      0x80000022u
#define LC_DYLD_EXPORTS_TRIE   0x80000033u
#define LC_DYLD_CHAINED_FIXUPS 0x80000034u
#define LC_FUNCTION_STARTS     0x26
#define LC_DATA_IN_CODE        0x29
#define LC_CODE_SIGNATURE      0x1D
#define LC_DYLIB_CODE_SIGN_DRS 0x2B
#define LC_LINKER_OPTIMIZATION_HINT 0x2E
#define LC_DYSYMTAB            0x0B

struct mach_header_64 {
    uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved;
};
struct load_command { uint32_t cmd, cmdsize; };
struct segment_command_64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};
struct section_64 {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags, reserved1, reserved2, reserved3;
};
struct symtab_command { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; };
struct linkedit_data_command { uint32_t cmd, cmdsize, dataoff, datasize; };
struct dyld_info_command {
    uint32_t cmd, cmdsize, rebase_off, rebase_size, bind_off, bind_size,
             weak_bind_off, weak_bind_size, lazy_bind_off, lazy_bind_size,
             export_off, export_size;
};

struct dyld_cache_mapping_info {
    uint64_t address, size, fileOffset;
    uint32_t maxProt, initProt;
};
struct dyld_cache_image_info {
    uint64_t address, modTime, inode;
    uint32_t pathFileOffset, pad;
};

// ---- a cache, possibly spread over several files ----------------------------

#define MAX_FILES 32
#define MAX_MAPS  256

struct region {
    uint64_t addr, size;
    const uint8_t* base;      // where in the mapped file that address lives
};

static struct {
    const uint8_t* file[MAX_FILES];
    size_t file_size[MAX_FILES];
    int nfiles;
    struct region map[MAX_MAPS];
    int nmaps;
    const uint8_t* main;      // the main cache file, which holds the image paths
    size_t main_size;
} C;

static void die(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "dsc_extract: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static const uint8_t* map_file(const char* path, size_t* out_size) {
#ifdef DSC_HAVE_MMAP
    const int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    void* p = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) return NULL;
    *out_size = (size_t)st.st_size;
    return (const uint8_t*)p;
#else
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    const long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* p = n > 0 ? (uint8_t*)malloc((size_t)n) : NULL;
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)n;
    return p;
#endif
}

// Record every mapping of one cache file, so an address can later be turned into
// a pointer without caring which file it came from.
static void add_cache_file(const uint8_t* f, size_t size, const char* label) {
    if (size < 0x18 || memcmp(f, "dyld_v1", 7) != 0)
        die("%s does not look like a dyld cache (magic is not dyld_v1)", label);
    uint32_t mapping_off, mapping_count;
    memcpy(&mapping_off, f + 0x10, 4);
    memcpy(&mapping_count, f + 0x14, 4);
    for (uint32_t i = 0; i < mapping_count; ++i) {
        struct dyld_cache_mapping_info m;
        memcpy(&m, f + mapping_off + i * sizeof m, sizeof m);
        if (C.nmaps >= MAX_MAPS) die("too many cache mappings");
        C.map[C.nmaps].addr = m.address;
        C.map[C.nmaps].size = m.size;
        C.map[C.nmaps].base = f + m.fileOffset;
        C.nmaps++;
    }
    C.file[C.nfiles] = f;
    C.file_size[C.nfiles] = size;
    C.nfiles++;
}

// The one primitive everything else is built on: a cache virtual address to a
// pointer at the bytes.
static const uint8_t* at(uint64_t addr, uint64_t need) {
    for (int i = 0; i < C.nmaps; ++i)
        if (addr >= C.map[i].addr && addr + need <= C.map[i].addr + C.map[i].size)
            return C.map[i].base + (addr - C.map[i].addr);
    return NULL;
}

// Cache *file* offsets appear in LINKEDIT-referencing load commands. They are
// offsets into whichever file holds that dylib's LINKEDIT, and the only reliable
// way to know which is to go through the address of the __LINKEDIT segment.
static const uint8_t* at_linkedit(uint64_t seg_vmaddr, uint64_t seg_fileoff,
                                  uint32_t off, uint32_t size) {
    if (!size) return NULL;
    if (off < seg_fileoff) return NULL;
    return at(seg_vmaddr + (off - seg_fileoff), size);
}

// ---- the image table --------------------------------------------------------

static uint32_t images_offset, images_count;

static void find_images(void) {
    uint32_t mapping_off, old_off, old_count;
    memcpy(&mapping_off, C.main + 0x10, 4);
    memcpy(&old_off, C.main + 0x18, 4);
    memcpy(&old_count, C.main + 0x1C, 4);
    // Old caches keep the image array at 0x18/0x1C; newer ones zero those and use
    // imagesOffset/imagesCount at 0x1C0/0x1C4. Deciding by "is the old one zero"
    // rather than by OS version keeps this working across both.
    if (old_off && old_count) {
        images_offset = old_off;
        images_count = old_count;
        return;
    }
    if (mapping_off < 0x1C8) die("cache header has neither image array");
    memcpy(&images_offset, C.main + 0x1C0, 4);
    memcpy(&images_count, C.main + 0x1C4, 4);
}

static const char* image_path(int i) {
    struct dyld_cache_image_info info;
    memcpy(&info, C.main + images_offset + (size_t)i * sizeof info, sizeof info);
    if (info.pathFileOffset >= C.main_size) return NULL;
    return (const char*)C.main + info.pathFileOffset;
}

static uint64_t image_addr(int i) {
    struct dyld_cache_image_info info;
    memcpy(&info, C.main + images_offset + (size_t)i * sizeof info, sizeof info);
    return info.address;
}

static int find_image(const char* path) {
    for (uint32_t i = 0; i < images_count; ++i) {
        const char* p = image_path((int)i);
        if (p && strcmp(p, path) == 0) return (int)i;
    }
    return -1;
}

// ---- extraction -------------------------------------------------------------

#define MAX_WANT 512
static const char* want[MAX_WANT];
static int nwant;

static void want_add(const char* p) {
    for (int i = 0; i < nwant; ++i) if (strcmp(want[i], p) == 0) return;
    if (nwant >= MAX_WANT) die("too many libraries");
    want[nwant++] = p;
}

static const char* lc_str(const uint8_t* cmd, uint32_t cmdsize, size_t at_off) {
    uint32_t off;
    memcpy(&off, cmd + at_off, 4);
    if (off >= cmdsize) return NULL;
    return (const char*)cmd + off;
}

// Walk one dylib's load commands and queue everything it depends on. Re-exports
// matter as much as plain loads: libSystem is almost entirely a list of them, so a
// closure that ignored LC_REEXPORT_DYLIB would extract a library with no code.
static void queue_deps(uint64_t mh_addr) {
    const uint8_t* mh = at(mh_addr, sizeof(struct mach_header_64));
    if (!mh) die("mach_header at %llx is outside every mapping", (unsigned long long)mh_addr);
    struct mach_header_64 h;
    memcpy(&h, mh, sizeof h);
    size_t o = sizeof h;
    for (uint32_t i = 0; i < h.ncmds; ++i) {
        struct load_command lc;
        memcpy(&lc, mh + o, sizeof lc);
        if (lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_LOAD_WEAK_DYLIB ||
            lc.cmd == LC_REEXPORT_DYLIB) {
            const char* name = lc_str(mh + o, lc.cmdsize, 8);
            if (name) want_add(name);
        }
        o += lc.cmdsize;
    }
}

struct outbuf { uint8_t* p; size_t len, cap; };

static void ob_need(struct outbuf* b, size_t n) {
    if (b->len + n <= b->cap) return;
    while (b->cap < b->len + n) b->cap = b->cap ? b->cap * 2 : 65536;
    b->p = realloc(b->p, b->cap);
    if (!b->p) die("out of memory");
}
static size_t ob_put(struct outbuf* b, const void* d, size_t n) {
    ob_need(b, n);
    const size_t at_off = b->len;
    memcpy(b->p + at_off, d, n);
    b->len += n;
    return at_off;
}
static void ob_pad(struct outbuf* b, size_t align) {
    while (b->len % align) { const uint8_t z = 0; ob_put(b, &z, 1); }
}

// No blob belonging to one library is this big. The first version of this tool
// copied LC_SYMTAB's strsize -- which in a shared cache spans the string pool of
// *every* library -- and produced 434 MB dylibs without complaining once. A ceiling
// that reports what it dropped is the difference between a bug found in a minute and
// a bug found by wondering why the output is enormous.
#define MAX_BLOB (64u << 20)

static uint32_t put_blob(struct outbuf* b, const uint8_t* d, uint32_t size,
                         const char* what, const char* path, uint32_t* out_size) {
    if (!d || !size) { *out_size = 0; return 0; }
    if (size > MAX_BLOB) {
        fprintf(stderr, "  ! %s: %s is %u bytes -- too large to belong to one "
                        "library; dropped\n", path, what, size);
        *out_size = 0;
        return 0;
    }
    *out_size = size;
    return (uint32_t)ob_put(b, d, size);
}

// Rebuild one cache dylib as a standalone Mach-O file.
static int extract_one(const char* path, const char* outdir, uint64_t* out_bytes) {
    const int idx = find_image(path);
    if (idx < 0) { fprintf(stderr, "  ! not in this cache: %s\n", path); return 0; }
    const uint64_t mh_addr = image_addr(idx);
    const uint8_t* mh = at(mh_addr, sizeof(struct mach_header_64));
    if (!mh) { fprintf(stderr, "  ! unmapped: %s\n", path); return 0; }

    struct mach_header_64 h;
    memcpy(&h, mh, sizeof h);
    const size_t hdr_bytes = sizeof h + h.sizeofcmds;

    // The header and load commands go out verbatim, then get patched in place: the
    // structure is identical, only file offsets move.
    struct outbuf ob = {0};
    ob_put(&ob, mh, hdr_bytes);

    // __LINKEDIT tells us how to turn the cache file offsets in the remaining load
    // commands into addresses, so find it before touching anything else.
    uint64_t le_vmaddr = 0, le_fileoff = 0;
    {
        size_t o = sizeof h;
        for (uint32_t i = 0; i < h.ncmds; ++i) {
            struct load_command lc;
            memcpy(&lc, mh + o, sizeof lc);
            if (lc.cmd == LC_SEGMENT_64) {
                struct segment_command_64 sc;
                memcpy(&sc, mh + o, sizeof sc);
                if (strncmp(sc.segname, "__LINKEDIT", 16) == 0) {
                    le_vmaddr = sc.vmaddr;
                    le_fileoff = sc.fileoff;
                }
            }
            o += lc.cmdsize;
        }
    }

    // Pass one: the segments. __LINKEDIT is rebuilt afterwards from just the blobs
    // that are actually referenced -- in the cache it is one shared region tens of
    // megabytes long, and copying that per library would defeat the point.
    size_t o = sizeof h;
    size_t linkedit_cmd_at = 0;
    for (uint32_t i = 0; i < h.ncmds; ++i) {
        struct load_command lc;
        memcpy(&lc, mh + o, sizeof lc);
        if (lc.cmd == LC_SEGMENT_64) {
            struct segment_command_64 sc;
            memcpy(&sc, mh + o, sizeof sc);
            if (strncmp(sc.segname, "__LINKEDIT", 16) == 0) {
                linkedit_cmd_at = o;
            } else if (sc.filesize) {
                const uint8_t* src = at(sc.vmaddr, sc.filesize);
                if (!src) {
                    fprintf(stderr, "  ! %s: segment %.16s is not mapped\n", path, sc.segname);
                    free(ob.p);
                    return 0;
                }
                ob_pad(&ob, 16384);
                const size_t new_off = ob_put(&ob, src, sc.filesize);
                // Patch this segment's fileoff, and every section's offset with it.
                const uint64_t delta_from = sc.fileoff;
                struct segment_command_64* dst =
                    (struct segment_command_64*)(ob.p + o);
                dst->fileoff = new_off;
                struct section_64* sect = (struct section_64*)(ob.p + o + sizeof sc);
                for (uint32_t s = 0; s < sc.nsects; ++s) {
                    if (sect[s].offset)
                        sect[s].offset = (uint32_t)(new_off + (sect[s].offset - delta_from));
                }
            }
        }
        o += lc.cmdsize;
    }

    // Pass two: the LINKEDIT blobs each remaining load command points at. Copy the
    // bytes, then rewrite the offset to where they landed.
    ob_pad(&ob, 16384);
    const size_t le_start = ob.len;
    o = sizeof h;
    for (uint32_t i = 0; i < h.ncmds; ++i) {
        struct load_command lc;
        memcpy(&lc, mh + o, sizeof lc);
        switch (lc.cmd) {
            // The symbol table needs rebuilding, not copying. In a shared cache the
            // *string pool is shared by every library*: each dylib's LC_SYMTAB has
            // its own symoff/nsyms but its stroff points into one common pool and
            // strsize covers the whole thing -- hundreds of megabytes. Copying
            // strsize bytes per library is what made the first version emit 434 MB
            // dylibs. So each symbol's name is looked up individually and a private
            // string table is built from just those.
            case LC_SYMTAB: {
                struct symtab_command sc;
                memcpy(&sc, mh + o, sizeof sc);
                struct symtab_command* dst = (struct symtab_command*)(ob.p + o);
                const uint8_t* syms = at_linkedit(le_vmaddr, le_fileoff, sc.symoff,
                                                  (uint64_t)sc.nsyms * 16);
                if (!syms || !sc.nsyms) {
                    dst->symoff = dst->nsyms = dst->stroff = dst->strsize = 0;
                    break;
                }
                struct outbuf nl = {0}, st = {0};
                const uint8_t zero = 0;
                ob_put(&st, &zero, 1);              // index 0 is the empty name
                for (uint32_t s = 0; s < sc.nsyms; ++s) {
                    uint8_t ent[16];
                    memcpy(ent, syms + (size_t)s * 16, 16);
                    uint32_t strx;
                    memcpy(&strx, ent, 4);
                    uint32_t new_strx = 0;
                    if (strx && strx < sc.strsize) {
                        const uint8_t* nm = at_linkedit(le_vmaddr, le_fileoff,
                                                        sc.stroff + strx, 1);
                        if (nm) {
                            const size_t len = strnlen((const char*)nm, 4096);
                            new_strx = (uint32_t)st.len;
                            ob_put(&st, nm, len + 1);
                        }
                    }
                    memcpy(ent, &new_strx, 4);
                    ob_put(&nl, ent, 16);
                }
                dst->symoff = (uint32_t)ob_put(&ob, nl.p, nl.len);
                dst->stroff = (uint32_t)ob_put(&ob, st.p, st.len);
                dst->strsize = (uint32_t)st.len;
                free(nl.p);
                free(st.p);
                break;
            }
            case LC_DYLD_INFO_ONLY: {
                struct dyld_info_command dc;
                memcpy(&dc, mh + o, sizeof dc);
                struct dyld_info_command* dst = (struct dyld_info_command*)(ob.p + o);
                // Only the export trie is worth carrying: a cache dylib is already
                // linked, so its rebase and bind programs are empty or irrelevant.
                dst->rebase_off = dst->rebase_size = 0;
                dst->bind_off = dst->bind_size = 0;
                dst->weak_bind_off = dst->weak_bind_size = 0;
                dst->lazy_bind_off = dst->lazy_bind_size = 0;
                const uint8_t* ex = at_linkedit(le_vmaddr, le_fileoff, dc.export_off,
                                                dc.export_size);
                dst->export_off = put_blob(&ob, ex, dc.export_size, "export trie", path,
                                           &dst->export_size);
                break;
            }
            // LC_DYLD_CHAINED_FIXUPS belongs here even though a cache dylib is
            // pre-linked and has none: a library extracted from anywhere else may,
            // and a *stale* offset is worse than no fixups at all -- it points at
            // whatever now lives there and gets parsed as a fixup header. That is
            // how the round-trip test caught this one.
            case LC_DYLD_CHAINED_FIXUPS:
            case LC_DYLD_EXPORTS_TRIE:
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE: {
                struct linkedit_data_command dc;
                memcpy(&dc, mh + o, sizeof dc);
                struct linkedit_data_command* dst = (struct linkedit_data_command*)(ob.p + o);
                const uint8_t* d = at_linkedit(le_vmaddr, le_fileoff, dc.dataoff, dc.datasize);
                dst->dataoff = put_blob(&ob, d, dc.datasize, "a LINKEDIT blob", path,
                                        &dst->datasize);
                break;
            }
            // A code signature covers file offsets that no longer exist, and a
            // rewritten file cannot carry a valid one. Blanking it is honest; leaving
            // a stale offset would make the file look signed and not be.
            case LC_CODE_SIGNATURE:
            case LC_DYLIB_CODE_SIGN_DRS:
            case LC_LINKER_OPTIMIZATION_HINT: {
                struct linkedit_data_command* dst = (struct linkedit_data_command*)(ob.p + o);
                dst->dataoff = 0;
                dst->datasize = 0;
                break;
            }
            // LC_DYSYMTAB's tables (indirect symbols, relocations, the local/extern
            // symbol ranges) are all LINKEDIT offsets. They are not carried, because
            // nothing that loads a pre-linked library reads them -- but the whole
            // command has to be zeroed rather than left pointing at offsets that no
            // longer mean anything.
            case LC_DYSYMTAB: {
                uint32_t* w = (uint32_t*)(ob.p + o);
                for (uint32_t k = 2; k < lc.cmdsize / 4; ++k) w[k] = 0;
                break;
            }
            default: break;
        }
        o += lc.cmdsize;
    }

    if (linkedit_cmd_at) {
        struct segment_command_64* le = (struct segment_command_64*)(ob.p + linkedit_cmd_at);
        le->fileoff = le_start;
        le->filesize = ob.len - le_start;
        le->vmsize = (le->filesize + 0x3FFF) & ~0x3FFFull;
    }

    // Write it out under the same path shape, so the emulator can find it by the
    // install name the dependent libraries use.
    char full[2048];
    snprintf(full, sizeof full, "%s%s", outdir, path);
    for (char* s = full + strlen(outdir) + 1; *s; ++s) {
        if (*s != '/') continue;
        *s = 0;
        mkdir(full, 0755);
        *s = '/';
    }
    FILE* f = fopen(full, "wb");
    if (!f) die("cannot write %s: %s", full, strerror(errno));
    fwrite(ob.p, 1, ob.len, f);
    fclose(f);
    // Segments and LINKEDIT reported separately: a total alone does not say which
    // half is unreasonable, and it was the LINKEDIT half that went wrong.
    printf("  %-48s %8.1f KiB  (code+data %.0f, linkedit %.0f)\n", path, ob.len / 1024.0,
           le_start / 1024.0, (ob.len - le_start) / 1024.0);
    *out_bytes += ob.len;
    free(ob.p);
    return 1;
}

int main(int argc, char** argv) {
    const char* outdir = NULL;
    int list = 0, i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--list") == 0) list = 1;
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outdir = argv[++i];
        else break;
    }
    if (i >= argc) {
        fprintf(stderr,
            "usage: dsc_extract [--list] [-o outdir] <cache> [dylib ...]\n"
            "\n"
            "  --list          print every library in the cache and stop\n"
            "  -o outdir       where to write; the tree mirrors the install names\n"
            "  dylib ...       what to extract; dependencies follow automatically.\n"
            "                  Defaults to /usr/lib/libSystem.B.dylib.\n");
        return 2;
    }

    const char* cache_path = argv[i++];
    C.main = map_file(cache_path, &C.main_size);
    if (!C.main) die("cannot open %s: %s", cache_path, strerror(errno));
    add_cache_file(C.main, C.main_size, cache_path);

    // Subcaches sit next to the main file as .01, .02, … Opening whatever is there
    // and reading its own mapping table avoids depending on the subcache array
    // layout, which has changed between releases.
    for (int n = 1; n < 40; ++n) {
        char sub[2048];
        snprintf(sub, sizeof sub, "%s.%02d", cache_path, n);
        size_t sz;
        const uint8_t* f = map_file(sub, &sz);
        if (!f) continue;
        add_cache_file(f, sz, sub);
        printf("subcache %s\n", sub);
    }

    find_images();
    printf("cache %.16s: %d file(s), %d mapping(s), %u image(s)\n",
           (const char*)C.main, C.nfiles, C.nmaps, images_count);
    for (int m = 0; m < C.nmaps; ++m)
        printf("  mapping %2d  %016llx + %10llu\n", m,
               (unsigned long long)C.map[m].addr, (unsigned long long)C.map[m].size);

    if (list) {
        for (uint32_t k = 0; k < images_count; ++k) {
            const char* p = image_path((int)k);
            printf("%016llx  %s\n", (unsigned long long)image_addr((int)k), p ? p : "?");
        }
        return 0;
    }

    if (i < argc) for (; i < argc; ++i) want_add(argv[i]);
    else want_add("/usr/lib/libSystem.B.dylib");

    // Transitive closure. `want` grows while it is walked, which is the point.
    for (int k = 0; k < nwant; ++k) {
        const int idx = find_image(want[k]);
        if (idx >= 0) queue_deps(image_addr(idx));
    }
    printf("\n%d librar%s in the closure\n", nwant, nwant == 1 ? "y" : "ies");

    if (!outdir) { for (int k = 0; k < nwant; ++k) printf("  %s\n", want[k]); return 0; }

    mkdir(outdir, 0755);
    uint64_t total = 0;
    int done = 0;
    for (int k = 0; k < nwant; ++k) done += extract_one(want[k], outdir, &total);
    printf("\n%d of %d written, %.1f MiB total, into %s\n",
           done, nwant, total / 1048576.0, outdir);
    return 0;
}
