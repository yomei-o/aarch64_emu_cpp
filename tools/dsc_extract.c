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
#define LC_LOAD_UPWARD_DYLIB   0x80000023u
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

// A mapping that also carries slide information. This is the part that makes a
// naive extraction produce a library that links and then branches to nonsense: the
// pointers in a cache's __DATA and __AUTH segments are **not pointers**. They are
// packed `dyld_cache_slide_pointer3` values -- an offset from the cache base plus,
// for authenticated ones, a signing key and a diversity value -- threaded into
// per-page chains. The kernel rewrites them when it maps the cache. Copy them
// verbatim and the guest reads something like 0x80140000004377AC as a function
// pointer, where 0x8014… is the signature field and 0x4377AC is the real offset.
struct slidemap {
    uint64_t addr, size;
    const uint8_t* info;      // the dyld_cache_slide_info for this mapping
    uint64_t info_size;
};

static struct {
    const uint8_t* file[MAX_FILES];
    size_t file_size[MAX_FILES];
    int nfiles;
    struct region map[MAX_MAPS];
    int nmaps;
    struct slidemap slide[MAX_MAPS];
    int nslides;
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
    // The slide information lives in a *second*, parallel mapping table --
    // mappingWithSlideOffset/Count at 0x138/0x13C -- with the same address ranges plus
    // a slideInfoFileOffset into this same file. Older caches have neither field, and
    // then there is nothing to decode.
    if (size > 0x140) {
        uint32_t ws_off, ws_count;
        memcpy(&ws_off, f + 0x138, 4);
        memcpy(&ws_count, f + 0x13C, 4);
        if (ws_off && ws_off + (size_t)ws_count * 56 <= size) {
            for (uint32_t i = 0; i < ws_count; ++i) {
                const uint8_t* e = f + ws_off + (size_t)i * 56;
                uint64_t addr, msize, si_off, si_size;
                memcpy(&addr, e, 8);
                memcpy(&msize, e + 8, 8);
                memcpy(&si_off, e + 24, 8);
                memcpy(&si_size, e + 32, 8);
                if (!si_off || !si_size || si_off + si_size > size) continue;
                if (C.nslides >= MAX_MAPS) die("too many slide mappings");
                C.slide[C.nslides].addr = addr;
                C.slide[C.nslides].size = msize;
                C.slide[C.nslides].info = f + si_off;
                C.slide[C.nslides].info_size = si_size;
                C.nslides++;
            }
        }
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

// ---- slide information ------------------------------------------------------
//
// Turn a segment's copied bytes into real pointers. The chains are per page and are
// described by dyld_cache_slide_info3:
//
//     uint32 version (3), page_size, page_starts_count, pad
//     uint64 auth_value_add
//     uint16 page_starts[page_starts_count]      0xFFFF = nothing on this page
//
// Each slot is a union: bit 63 says whether it is authenticated. Authenticated slots
// hold an offset from the cache base in the low 32 bits (the signature above it is
// discarded -- there is no PAC here, and the emulator treats signing as the
// identity). Plain slots hold a 51-bit value whose top 8 bits are shifted down, a
// packing that has to be undone exactly or every pointer lands 8 TiB away.
//
// Cache segments are not page aligned, so a chain can begin in the previous
// library's bytes and run into ours: the walk follows the whole chain and writes back
// only the slots that fall inside this segment.
static int slide_unsupported_version;
static uint64_t total_still_packed;
static int slide_version_seen;

static void apply_slide(uint8_t* dst, uint64_t seg_addr, uint64_t seg_size) {
    for (int m = 0; m < C.nslides; ++m) {
        const struct slidemap* sm = &C.slide[m];
        if (seg_addr >= sm->addr + sm->size || seg_addr + seg_size <= sm->addr) continue;
        uint32_t version, page_size, page_count;
        memcpy(&version, sm->info, 4);
        memcpy(&page_size, sm->info + 4, 4);
        memcpy(&page_count, sm->info + 8, 4);
        // Versions 3 and 5 have identical headers and differ only in how a slot is
        // packed. Version 5 arrived with macOS 14; a Sequoia arm64e cache uses it,
        // and treating it as version 3 puts `next` one bit out and the offset field
        // two bits wide too many.
        if (version != 3 && version != 5) {
            if (!slide_unsupported_version) {
                fprintf(stderr, "  ! slide info version %u is not implemented; pointers in "
                                "data segments will be left packed and the result will not "
                                "run\n", version);
                slide_unsupported_version = (int)version;
            }
            continue;
        }
        slide_version_seen = (int)version;
        uint64_t value_add;
        memcpy(&value_add, sm->info + 16, 8);
        const uint8_t* starts = sm->info + 24;
        if (24 + (size_t)page_count * 2 > sm->info_size) continue;

        for (uint32_t p = 0; p < page_count; ++p) {
            uint16_t start;
            memcpy(&start, starts + (size_t)p * 2, 2);
            if (start == 0xFFFF) continue;
            const uint64_t page_addr = sm->addr + (uint64_t)p * page_size;
            if (page_addr >= seg_addr + seg_size || page_addr + page_size <= seg_addr) continue;
            uint64_t addr = page_addr + start;
            for (;;) {
                const uint8_t* src = at(addr, 8);
                if (!src) break;
                uint64_t raw;
                memcpy(&raw, src, 8);
                uint64_t value;
                if (version == 5) {
                    // v5: runtimeOffset is 34 bits and everything is relative to
                    // value_add. A plain slot also carries the top byte of the
                    // pointer, which is where a tagged pointer keeps its tag.
                    const uint64_t rt = raw & 0x3FFFFFFFFull;
                    value = value_add + rt;
                    if (!(raw >> 63)) value |= ((raw >> 34) & 0xFFull) << 56;
                } else if (raw >> 63) {                // v3, authenticated
                    value = value_add + (raw & 0xFFFFFFFFull);
                } else {                               // v3, plain
                    const uint64_t v = raw & 0x0007FFFFFFFFFFFFull;   // 51 bits
                    const uint64_t top8 = v & 0x0007F80000000000ull;
                    const uint64_t bottom43 = v & 0x000007FFFFFFFFFFull;
                    value = (top8 << 13) | bottom43;
                }
                if (addr >= seg_addr && addr + 8 <= seg_addr + seg_size)
                    memcpy(dst + (addr - seg_addr), &value, 8);
                const uint64_t next = version == 5 ? ((raw >> 52) & 0x7FF)
                                                   : ((raw >> 51) & 0x7FF);
                if (!next) break;
                addr += next * 8;
                if (addr >= page_addr + page_size) break;    // a chain stays on its page
            }
        }
    }
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
// Off by default. A pre-linked library is loaded through its export trie, so the
// symbol table is not needed to *run* it -- and in a shared cache it is the single
// most dangerous thing to copy, because both the nlist array and the string pool
// are shared by every library. Opt in when you want to inspect the result with nm.
static int want_symbols = 1;
// Where the bytes went, per library. Printed always: guessing which part is
// oversized has already cost two round trips.
struct parts { uint64_t segs, symtab, exports, other, still_packed; };

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

// Which dependency edges the closure follows, and the reason the defaults are what
// they are -- measured, on macOS 15.7.4, starting from /usr/lib/libSystem.B.dylib:
//
//     every edge kind                    477 libraries   784 MB
//     without weak                       157             260 MB
//     without weak or upward             137             231 MB
//     without weak or upward, /usr/lib    39             8.8 MB
//
// The last line is the libc. The first is most of macOS, and it arrives through one
// chain: libxpc has an *upward* dependency on libobjc, a *weak* one on XPCSupport,
// and a plain one on CoreFoundation — and from CoreFoundation, everything.
//
// Weak and upward are excluded because of what they mean, not because they are
// inconvenient. A weak dependency may legitimately be absent; an upward one exists
// to break a cycle and is loaded later, if at all. A plain LC_LOAD_DYLIB outside the
// prefix filter *is* a real dependency, so dropping one is reported rather than
// assumed harmless.
static int follow_all_kinds;                 // --all-deps
static const char* only_prefix[8];
static int n_only;
static int skipped_kind, skipped_prefix;
static const char* skipped_example[8];
static int n_skipped_example;

static void note_skip(const char* name, int by_prefix) {
    if (by_prefix) skipped_prefix++; else skipped_kind++;
    if (n_skipped_example < 8) {
        for (int i = 0; i < n_skipped_example; ++i)
            if (strcmp(skipped_example[i], name) == 0) return;
        skipped_example[n_skipped_example++] = name;
    }
}

static void queue_deps(uint64_t mh_addr) {
    const uint8_t* mh = at(mh_addr, sizeof(struct mach_header_64));
    if (!mh) die("mach_header at %llx is outside every mapping", (unsigned long long)mh_addr);
    struct mach_header_64 h;
    memcpy(&h, mh, sizeof h);
    size_t o = sizeof h;
    for (uint32_t i = 0; i < h.ncmds; ++i) {
        struct load_command lc;
        memcpy(&lc, mh + o, sizeof lc);
        const int is_dep = lc.cmd == LC_LOAD_DYLIB || lc.cmd == LC_REEXPORT_DYLIB;
        const int is_soft = lc.cmd == LC_LOAD_WEAK_DYLIB || lc.cmd == LC_LOAD_UPWARD_DYLIB;
        if (is_dep || is_soft) {
            const char* name = lc_str(mh + o, lc.cmdsize, 8);
            if (!name) { o += lc.cmdsize; continue; }
            if (is_soft && !follow_all_kinds) { note_skip(name, 0); o += lc.cmdsize; continue; }
            int allowed = n_only == 0;
            for (int k = 0; k < n_only; ++k)
                if (strncmp(name, only_prefix[k], strlen(only_prefix[k])) == 0) allowed = 1;
            if (!allowed) { note_skip(name, 1); o += lc.cmdsize; continue; }
            want_add(name);
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

// Patch a field of an already-written load command, by offset.
//
// This exists because the obvious version does not work. Holding a pointer into the
// buffer across an append is use-after-free: `ob_put` reallocs, and
//
//     dst->symoff = ob_put(...);        // fine, or fine by luck
//     dst->stroff = ob_put(...);        // dst now dangles -- write is lost
//
// silently loses the second write, leaving the *cache's* offset in the field. The
// result is a file whose LC_SYMTAB claims a 445 MB string table at offset 2.2 GB,
// which llvm-objdump rejects and a loader might not. libSystem happened to survive
// it; libxpc did not.
static void patch32(struct outbuf* b, size_t cmd_off, size_t field, uint32_t v) {
    memcpy(b->p + cmd_off + field, &v, 4);
}

// Rebuild one cache dylib as a standalone Mach-O file.
static int extract_one(const char* path, const char* outdir, uint64_t* out_bytes) {
    const int idx = find_image(path);
    if (idx < 0) { fprintf(stderr, "  ! not in this cache: %s\n", path); return 0; }
    const uint64_t mh_addr = image_addr(idx);
    const uint8_t* mh = at(mh_addr, sizeof(struct mach_header_64));
    if (!mh) { fprintf(stderr, "  ! unmapped: %s\n", path); return 0; }

    struct parts pt_local = {0, 0, 0, 0, 0};
    struct parts* pt = &pt_local;

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
                pt->segs += sc.filesize;
                // Undo the cache's pointer packing in the copy, which is the step
                // that turns a library that loads into a library that runs.
                apply_slide(ob.p + new_off, sc.vmaddr, sc.filesize);
                // Check the work rather than assume it. A slot that still has bit 63
                // set *and* a plausible cache offset below it was never decoded --
                // which is what an unimplemented slide-info version looks like, and
                // it produced a guest that ran 24 instructions and branched to
                // 0x80140000004377AC. Counting them here turns a silent miss into a
                // number on the same line as the library.
                if (strncmp(sc.segname, "__TEXT", 6) != 0) {
                    for (uint64_t k = 0; k + 8 <= sc.filesize; k += 8) {
                        uint64_t v;
                        memcpy(&v, ob.p + new_off + k, 8);
                        if ((v >> 63) && (v & 0xFFFFFFFFull) &&
                            ((v >> 32) & 0x7FFFFFFF) < 0x10000)
                            pt->still_packed++;
                    }
                }
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
                // In a shared cache the string pool is shared by every library, so
                // this command's strsize spans hundreds of megabytes that are not
                // this library's. Each name is therefore looked up individually and
                // a private string table built from just those.
                const uint8_t* syms = at_linkedit(le_vmaddr, le_fileoff, sc.symoff,
                                                  (uint64_t)sc.nsyms * 16);
                if (!want_symbols || !syms || !sc.nsyms ||
                    (uint64_t)sc.nsyms * 16 > MAX_BLOB) {
                    if (want_symbols && sc.nsyms && (uint64_t)sc.nsyms * 16 > MAX_BLOB)
                        fprintf(stderr, "  ! %s: LC_SYMTAB claims %u symbols, which is "
                                        "the cache's table and not this library's; "
                                        "dropped\n", path, sc.nsyms);
                    patch32(&ob, o, 8, 0);   patch32(&ob, o, 12, 0);
                    patch32(&ob, o, 16, 0);  patch32(&ob, o, 20, 0);
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
                // Every append first, every patch afterwards. Interleaving them is
                // the bug documented on patch32.
                const uint32_t sym_at = (uint32_t)ob_put(&ob, nl.p, nl.len);
                const uint32_t str_at = (uint32_t)ob_put(&ob, st.p, st.len);
                patch32(&ob, o, 8, sym_at);
                patch32(&ob, o, 12, sc.nsyms);
                patch32(&ob, o, 16, str_at);
                patch32(&ob, o, 20, (uint32_t)st.len);
                pt->symtab = nl.len + st.len;
                free(nl.p);
                free(st.p);
                break;
            }
            case LC_DYLD_INFO_ONLY: {
                struct dyld_info_command dc;
                memcpy(&dc, mh + o, sizeof dc);
                const uint8_t* ex = at_linkedit(le_vmaddr, le_fileoff, dc.export_off,
                                                dc.export_size);
                uint32_t sz = 0;
                const uint32_t at_off = put_blob(&ob, ex, dc.export_size, "export trie",
                                                 path, &sz);
                // Only the export trie is worth carrying: a cache dylib is already
                // linked, so its rebase and bind programs are empty or irrelevant.
                for (size_t fld = 8; fld <= 36; fld += 4) patch32(&ob, o, fld, 0);
                patch32(&ob, o, 40, at_off);
                patch32(&ob, o, 44, sz);
                pt->exports += sz;
                break;
            }
            // LC_DYLD_CHAINED_FIXUPS belongs here even though a cache dylib is
            // pre-linked and has none: a library extracted from anywhere else may,
            // and a *stale* offset is worse than no fixups at all -- it points at
            // whatever now lives there and gets parsed as a fixup header.
            case LC_DYLD_CHAINED_FIXUPS:
            case LC_DYLD_EXPORTS_TRIE:
            case LC_FUNCTION_STARTS:
            case LC_DATA_IN_CODE: {
                struct linkedit_data_command dc;
                memcpy(&dc, mh + o, sizeof dc);
                const uint8_t* d = at_linkedit(le_vmaddr, le_fileoff, dc.dataoff, dc.datasize);
                uint32_t sz = 0;
                const uint32_t at_off = put_blob(&ob, d, dc.datasize, "a LINKEDIT blob",
                                                 path, &sz);
                patch32(&ob, o, 8, at_off);
                patch32(&ob, o, 12, sz);
                if (lc.cmd == LC_DYLD_EXPORTS_TRIE) pt->exports += sz;
                else pt->other += sz;
                break;
            }
            // A code signature covers file offsets that no longer exist, and a
            // rewritten file cannot carry a valid one. Blanking it is honest; leaving
            // a stale offset would make the file look signed and not be.
            case LC_CODE_SIGNATURE:
            case LC_DYLIB_CODE_SIGN_DRS:
            case LC_LINKER_OPTIMIZATION_HINT:
                patch32(&ob, o, 8, 0);
                patch32(&ob, o, 12, 0);
                break;
            // LC_DYSYMTAB's tables (indirect symbols, relocations, the local/extern
            // symbol ranges) are all LINKEDIT offsets. They are not carried, because
            // nothing that loads a pre-linked library reads them -- but the whole
            // command has to be zeroed rather than left pointing at offsets that no
            // longer mean anything.
            case LC_DYSYMTAB:
                for (uint32_t k = 2; k < lc.cmdsize / 4; ++k) patch32(&ob, o, k * 4, 0);
                break;
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
    // Broken out by part, always. A total alone does not say which piece is
    // unreasonable, and twice now it was a LINKEDIT piece that had quietly picked up
    // something shared by the whole cache.
    printf("  %-46s %7.0f KiB = code/data %.0f + syms %.0f + exports %.0f + other %.0f%s\n",
           path, ob.len / 1024.0, pt->segs / 1024.0, pt->symtab / 1024.0,
           pt->exports / 1024.0, pt->other / 1024.0,
           pt->still_packed ? "   <-- POINTERS STILL PACKED" : "");
    total_still_packed += pt->still_packed;
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
        else if (strcmp(argv[i], "--all-deps") == 0) follow_all_kinds = 1;
        else if (strcmp(argv[i], "--no-symbols") == 0) want_symbols = 0;
        else if (strcmp(argv[i], "--only") == 0 && i + 1 < argc) {
            if (n_only < 8) only_prefix[n_only++] = argv[++i]; else ++i;
        } else break;
    }
    if (i >= argc) {
        fprintf(stderr,
            "usage: dsc_extract [options] <cache> [dylib ...]\n"
            "\n"
            "  --list          print every library in the cache and stop\n"
            "  -o outdir       where to write; the tree mirrors the install names\n"
            "  --only PREFIX   only follow dependencies whose path starts with PREFIX\n"
            "                  (repeatable). Whatever is dropped gets reported.\n"
            "  --all-deps      also follow weak and upward dependencies. On macOS 15\n"
            "                  this takes libSystem's closure from 39 libraries and\n"
            "                  8.8 MB to 477 and 784 MB, via libxpc -> libobjc and\n"
            "                  CoreFoundation, so it is off by default.\n"
            "  --no-symbols    do not carry a symbol table (the export trie is what a\n"
            "                  loader uses; symbols are for reading the result)\n"
            "  dylib ...       what to extract; dependencies follow automatically.\n"
            "                  Defaults to /usr/lib/libSystem.B.dylib.\n"
            "\n"
            "For a libc and nothing else:\n"
            "  dsc_extract --only /usr/lib/ -o out <cache> /usr/lib/libSystem.B.dylib\n");
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
    // Never a silent cap: a dropped dependency is a real dependency that a loader
    // would have loaded, so say how many and give examples. The emulator reports the
    // symbols it then cannot resolve, which is how the list gets extended.
    if (skipped_kind || skipped_prefix) {
        printf("not followed: %d weak/upward, %d outside --only. For example:\n",
               skipped_kind, skipped_prefix);
        for (int k = 0; k < n_skipped_example; ++k) printf("    %s\n", skipped_example[k]);
    }

    if (!outdir) { for (int k = 0; k < nwant; ++k) printf("  %s\n", want[k]); return 0; }

    mkdir(outdir, 0755);
    uint64_t total = 0;
    int done = 0;
    for (int k = 0; k < nwant; ++k) done += extract_one(want[k], outdir, &total);
    printf("\n%d of %d written, %.1f MiB total, into %s\n",
           done, nwant, total / 1048576.0, outdir);
    printf("slide info: %d mapping(s), version %d\n", C.nslides, slide_version_seen);
    // The single most useful line in the output. A guest whose data pointers were
    // never unpacked links perfectly and then branches to a signature field, tens of
    // instructions in, nowhere near the cause.
    if (total_still_packed)
        printf("WARNING: %llu pointer(s) still look packed -- the slide information was "
               "not fully applied, and the result will not run\n",
               (unsigned long long)total_still_packed);
    else
        printf("all data pointers unpacked\n");
    return 0;
}
