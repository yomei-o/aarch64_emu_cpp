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
static uint64_t total_slid;
static int libs_without_slide;
static int slide_version_seen;

static uint64_t apply_slide(uint8_t* dst, uint64_t seg_addr, uint64_t seg_size) {
    uint64_t rewrote = 0;
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
                if (addr >= seg_addr && addr + 8 <= seg_addr + seg_size) {
                    memcpy(dst + (addr - seg_addr), &value, 8);
                    rewrote++;
                }
                const uint64_t next = version == 5 ? ((raw >> 52) & 0x7FF)
                                                   : ((raw >> 51) & 0x7FF);
                if (!next) break;
                addr += next * 8;
                if (addr >= page_addr + page_size) break;    // a chain stays on its page
            }
        }
    }
    return rewrote;
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
struct parts { uint64_t segs, symtab, exports, other, slid, data_bytes; };

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

// Defined further down with the rest of the patch-table machinery; needed here
// because a library's own segments can be patch targets.
static uint64_t apply_patches(uint8_t* dst, uint64_t lo, uint64_t size);

// Rebuild one cache dylib as a standalone Mach-O file.
static int extract_one(const char* path, const char* outdir, uint64_t* out_bytes) {
    const int idx = find_image(path);
    if (idx < 0) { fprintf(stderr, "  ! not in this cache: %s\n", path); return 0; }
    const uint64_t mh_addr = image_addr(idx);
    const uint8_t* mh = at(mh_addr, sizeof(struct mach_header_64));
    if (!mh) { fprintf(stderr, "  ! unmapped: %s\n", path); return 0; }

    struct parts pt_local = {0, 0, 0, 0, 0, 0};
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
                pt->slid += apply_slide(ob.p + new_off, sc.vmaddr, sc.filesize);
                // A library's own GOT slots can be patch targets too, so the same fill
                // applies here and not only to the islands.
                apply_patches(ob.p + new_off, sc.vmaddr, sc.filesize);
                if (strncmp(sc.segname, "__TEXT", 6) != 0) pt->data_bytes += sc.filesize;
                // Patch this segment's fileoff, and every section's offset with it.
                // Taken after the appends above, never before: see patch32.
                const uint64_t delta_from = sc.fileoff;
                struct segment_command_64* dst = (struct segment_command_64*)(ob.p + o);
                dst->fileoff = new_off;
                struct section_64* sect = (struct section_64*)(ob.p + o + sizeof sc);
                for (uint32_t s = 0; s < sc.nsects; ++s)
                    if (sect[s].offset)
                        sect[s].offset = (uint32_t)(new_off + (sect[s].offset - delta_from));
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
            // LC_DYSYMTAB. Zeroing all of this was wrong, and wrong in a way that took
            // a while to see: a cache dylib's __got slots for *data* imports are left
            // null for dyld to fill, and the indirect symbol table is what says which
            // symbol each slot wants. Discard it and libsystem_platform reads a null
            // pointer where `&vm_page_size` belongs, dereferences it, gets zero from
            // an unmapped page, and asks the kernel for a zero-byte allocation.
            //
            // So the indirect symbols come along (four bytes an entry) and the rest of
            // the command -- relocations, the module table, the per-module symbol
            // ranges, none of which a loader needs -- is zeroed.
            case LC_DYSYMTAB: {
                uint32_t indirectoff, nindirect;
                memcpy(&indirectoff, mh + o + 56, 4);
                memcpy(&nindirect, mh + o + 60, 4);
                const uint8_t* ind = at_linkedit(le_vmaddr, le_fileoff, indirectoff,
                                                 (uint64_t)nindirect * 4);
                for (uint32_t k = 2; k < lc.cmdsize / 4; ++k) patch32(&ob, o, k * 4, 0);
                uint32_t sz = 0;
                const uint32_t at_off = put_blob(&ob, ind, nindirect * 4,
                                                 "the indirect symbol table", path, &sz);
                if (sz) {
                    patch32(&ob, o, 56, at_off);
                    patch32(&ob, o, 60, sz / 4);
                    pt->other += sz;
                }
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
    // Broken out by part, always. A total alone does not say which piece is
    // unreasonable, and twice now it was a LINKEDIT piece that had quietly picked up
    // something shared by the whole cache.
    printf("  %-46s %7.0f KiB = code/data %.0f + syms %.0f + exports %.0f + other %.0f%s\n",
           path, ob.len / 1024.0, pt->segs / 1024.0, pt->symtab / 1024.0,
           pt->exports / 1024.0, pt->other / 1024.0,
           (pt->data_bytes && !pt->slid) ? "   <-- NO POINTERS UNPACKED" : "");
    total_slid += pt->slid;
    if (pt->data_bytes && !pt->slid) libs_without_slide++;
    *out_bytes += ob.len;
    free(ob.p);
    return 1;
}

// ---- the regions no library owns ---------------------------------------------
//
// A per-library extraction is not quite enough, and the reason is worth stating.
// Recent caches coalesce GOT entries into shared islands: `libsystem_platform`'s
// `__auth_stubs` loads its function pointer from 0x1E2465DB8, which lies inside no
// dylib's LC_SEGMENT_64 at all. Extract every library and that address is simply not
// there, so the stub branches through a zero and the guest dies in a stub table
// hundreds of instructions from anything that explains it.
//
// So: mark every page any *image in the cache* covers -- all of them, not just the
// ones being extracted -- and whatever the slide information still rebases outside
// that is cache-owned. Those pages are emitted as one synthetic MH_DYLIB with a
// segment per contiguous run, which means the loader needs no new concept: it is just
// another library, pre-linked at fixed addresses like every other.
struct run { uint64_t addr; uint8_t* data; uint64_t size, cap; };
#define MAX_RUNS 4096
static struct run runs[MAX_RUNS];
static int nruns;

// The owned ranges are built once and merged. Asking every image about every page --
// four thousand images against a hundred thousand pages -- is a few billion range
// checks and takes long enough that it reads as a hang.
struct range { uint64_t lo, hi; };
static struct range* owned;
static size_t n_owned;

static int range_cmp(const void* a, const void* b) {
    const uint64_t x = ((const struct range*)a)->lo, y = ((const struct range*)b)->lo;
    return x < y ? -1 : (x > y ? 1 : 0);
}

// Only the libraries actually being extracted count as owned.
//
// The first version excluded every page owned by *any* image in the cache, on the
// reasoning that such a page belongs to that library and not to us. That is wrong,
// and the way it is wrong is instructive: the cache coalesces GOT entries, so the
// slot libsystem_platform reads to find `vm_page_size` sits at 0x1E7FEC378 -- inside
// a *different* library's __DATA_CONST. Excluding it left the collected run ending at
// 0x1E7FEC000, 0x378 short, and the guest read a zero where a pointer belonged.
//
// So a page is skipped only when it is inside a library that is being written out
// anyway. Everything else the slide information rebases comes along.
static void build_owned_ranges(void) {
    size_t cap = 4096;
    owned = malloc(cap * sizeof *owned);
    if (!owned) die("out of memory");
    for (int wi = 0; wi < nwant; ++wi) {
        const int k = find_image(want[wi]);
        if (k < 0) continue;
        const uint8_t* mh = at(image_addr(k), sizeof(struct mach_header_64));
        if (!mh) continue;
        struct mach_header_64 h;
        memcpy(&h, mh, sizeof h);
        size_t o = sizeof h;
        for (uint32_t i = 0; i < h.ncmds; ++i) {
            struct load_command lc;
            memcpy(&lc, mh + o, sizeof lc);
            if (lc.cmd == LC_SEGMENT_64) {
                struct segment_command_64 sc;
                memcpy(&sc, mh + o, sizeof sc);
                if (sc.vmsize) {
                    if (n_owned == cap) {
                        cap *= 2;
                        owned = realloc(owned, cap * sizeof *owned);
                        if (!owned) die("out of memory");
                    }
                    owned[n_owned].lo = sc.vmaddr;
                    owned[n_owned].hi = sc.vmaddr + sc.vmsize;
                    n_owned++;
                }
            }
            o += lc.cmdsize;
        }
    }
    qsort(owned, n_owned, sizeof *owned, range_cmp);
    // Merge, so a lookup can stop at the first range that starts past the page.
    size_t w = 0;
    for (size_t r = 0; r < n_owned; ++r) {
        if (w && owned[r].lo <= owned[w - 1].hi) {
            if (owned[r].hi > owned[w - 1].hi) owned[w - 1].hi = owned[r].hi;
        } else {
            owned[w++] = owned[r];
        }
    }
    n_owned = w;
}

static int page_owned_by_any_image(uint64_t page, uint64_t page_size) {
    size_t lo = 0, hi = n_owned;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (owned[mid].hi <= page) lo = mid + 1;
        else hi = mid;
    }
    return lo < n_owned && owned[lo].lo < page + page_size;
}

static void run_add(uint64_t addr, const uint8_t* data, uint64_t size) {
    // Merge into the previous run when adjacent: the islands are contiguous stretches
    // of pointer table, so this collapses thousands of pages into a handful of
    // segments.
    if (nruns && runs[nruns - 1].addr + runs[nruns - 1].size == addr) {
        struct run* r = &runs[nruns - 1];
        if (r->size + size > r->cap) {
            r->cap = (r->size + size) * 2;
            r->data = realloc(r->data, r->cap);
            if (!r->data) die("out of memory");
        }
        memcpy(r->data + r->size, data, size);
        r->size += size;
        return;
    }
    if (nruns >= MAX_RUNS) die("too many cache-owned regions");
    struct run* r = &runs[nruns++];
    r->addr = addr;
    r->cap = size * 2;
    r->data = malloc(r->cap);
    if (!r->data) die("out of memory");
    memcpy(r->data, data, size);
    r->size = size;
}

// Emit the runs as a Mach-O dylib. Nothing reads its symbol table; it exists to be
// mapped at the addresses it names.
static void write_extras(const char* outdir, const char* install_name) {
    if (!nruns) return;
    const uint32_t ncmds = (uint32_t)nruns;
    uint32_t sizeofcmds = ncmds * (uint32_t)sizeof(struct segment_command_64);
    // LC_ID_DYLIB, so the loader can find this by name like any other library.
    const uint32_t idsize = (uint32_t)((24 + strlen(install_name) + 1 + 7) & ~7u);
    sizeofcmds += idsize;

    struct outbuf ob = {0};
    struct mach_header_64 h = {0xFEEDFACF, 0x0100000C, 0, 6 /*MH_DYLIB*/, ncmds + 1,
                               sizeofcmds, 0, 0};
    h.ncmds = ncmds + 1;
    ob_put(&ob, &h, sizeof h);
    const size_t cmds_at = ob.len;
    for (int i = 0; i < nruns; ++i) {
        struct segment_command_64 sc;
        memset(&sc, 0, sizeof sc);
        sc.cmd = LC_SEGMENT_64;
        sc.cmdsize = sizeof sc;
        snprintf(sc.segname, sizeof sc.segname, "__DSC%d", i);
        sc.vmaddr = runs[i].addr;
        sc.vmsize = (runs[i].size + 0x3FFF) & ~0x3FFFull;
        sc.filesize = runs[i].size;
        sc.maxprot = sc.initprot = 3;                 // read/write
        ob_put(&ob, &sc, sizeof sc);
    }
    {
        uint8_t idcmd[512];
        memset(idcmd, 0, sizeof idcmd);
        const uint32_t cmd = LC_ID_DYLIB;
        memcpy(idcmd, &cmd, 4);
        memcpy(idcmd + 4, &idsize, 4);
        const uint32_t nameoff = 24;
        memcpy(idcmd + 8, &nameoff, 4);
        memcpy(idcmd + nameoff, install_name, strlen(install_name) + 1);
        ob_put(&ob, idcmd, idsize);
    }
    for (int i = 0; i < nruns; ++i) {
        ob_pad(&ob, 16384);
        const size_t at_off = ob_put(&ob, runs[i].data, runs[i].size);
        struct segment_command_64* sc =
            (struct segment_command_64*)(ob.p + cmds_at + (size_t)i * sizeof *sc);
        sc->fileoff = at_off;
    }

    char full[2048];
    snprintf(full, sizeof full, "%s%s", outdir, install_name);
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
    uint64_t bytes = 0;
    for (int i = 0; i < nruns; ++i) bytes += runs[i].size;
    printf("\ncache-owned regions: %d run(s), %.1f MiB, written as %s\n",
           nruns, bytes / 1048576.0, install_name);
    free(ob.p);
}

// Which outside pages the extracted code actually reaches.
//
// "Every rebased page that no extracted library owns" is correct and useless: it is
// every other library's data, 301 MiB of it. What is wanted is the few pages our
// libraries reach into, and those can be found exactly rather than guessed, by reading
// the code.
//
// Every such reference is an ADRP -- the only way AArch64 forms an address more than
// 1 MiB away -- usually followed by an ADD or an LDR that supplies the low twelve
// bits. So: scan the __TEXT of each extracted library, decode each ADRP and the
// instruction after it, and note the page of anything that lands outside the extracted
// libraries. The GOT islands are exactly those pages.
static uint64_t* refpage;
static size_t n_refpage, cap_refpage;

static int u64_cmp(const void* a, const void* b) {
    const uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

static void refpage_add(uint64_t page) {
    if (n_refpage == cap_refpage) {
        cap_refpage = cap_refpage ? cap_refpage * 2 : 4096;
        refpage = realloc(refpage, cap_refpage * sizeof *refpage);
        if (!refpage) die("out of memory");
    }
    refpage[n_refpage++] = page;
}

static void scan_text_for_references(uint64_t page_size) {
    for (int wi = 0; wi < nwant; ++wi) {
        const int k = find_image(want[wi]);
        if (k < 0) continue;
        const uint8_t* mh = at(image_addr(k), sizeof(struct mach_header_64));
        if (!mh) continue;
        struct mach_header_64 h;
        memcpy(&h, mh, sizeof h);
        size_t o = sizeof h;
        for (uint32_t i = 0; i < h.ncmds; ++i) {
            struct load_command lc;
            memcpy(&lc, mh + o, sizeof lc);
            if (lc.cmd == LC_SEGMENT_64) {
                struct segment_command_64 sc;
                memcpy(&sc, mh + o, sizeof sc);
                // Per *section*, and only sections marked as instructions. Scanning the
                // whole __TEXT segment reads __cstring and __const as code, and random
                // bytes decode as ADRP with arbitrary immediates -- which named pages
                // all over the cache and collected 316 MiB of other libraries' data.
                for (uint32_t s = 0; s < sc.nsects; ++s) {
                    const uint8_t* sect = mh + o + sizeof sc + (size_t)s * 80;
                    uint64_t saddr, ssize;
                    uint32_t sflags;
                    memcpy(&saddr, sect + 32, 8);
                    memcpy(&ssize, sect + 40, 8);
                    memcpy(&sflags, sect + 64, 4);
                    // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
                    if (!(sflags & 0x80000400u) || ssize < 8) continue;
                    const uint8_t* code = at(saddr, ssize);
                    if (code) {
                        const uint64_t base = saddr;
                        for (uint64_t off = 0; off + 8 <= ssize; off += 4) {
                            uint32_t insn, next;
                            memcpy(&insn, code + off, 4);
                            memcpy(&next, code + off + 4, 4);
                            // ADRP: bit31 set, bits 28..24 == 10000.
                            if (!(insn >> 31) || ((insn >> 24) & 0x1F) != 0x10) continue;
                            const uint32_t rd = insn & 0x1F;
                            const uint64_t immlo = (insn >> 29) & 3;
                            const uint64_t immhi = (insn >> 5) & 0x7FFFF;
                            int64_t imm = (int64_t)((immhi << 2) | immlo);
                            if (imm & (1 << 20)) imm -= (1 << 21);      // sign extend 21 bits
                            uint64_t target = ((base + off) & ~0xFFFull) +
                                              (uint64_t)(imm * 4096);
                            // ADD immediate, 64-bit: 1 00 100010 sh imm12 Rn Rd
                            if ((next >> 23) == 0x244 && ((next >> 5) & 0x1F) == rd) {
                                uint64_t imm12 = (next >> 10) & 0xFFF;
                                if ((next >> 22) & 1) imm12 <<= 12;
                                target += imm12;
                            // LDR immediate, unsigned offset, 64-bit: 1111100101 imm12 Rn Rt
                            } else if ((next >> 22) == 0x3E5 && ((next >> 5) & 0x1F) == rd) {
                                target += ((next >> 10) & 0xFFF) * 8;
                            }
                            if (page_owned_by_any_image(target, 1)) continue;
                            refpage_add(target & ~(page_size - 1));
                        }
                    }
                }
            }
            o += lc.cmdsize;
        }
    }
    qsort(refpage, n_refpage, sizeof *refpage, u64_cmp);
    size_t w = 0;
    for (size_t r = 0; r < n_refpage; ++r)
        if (!w || refpage[r] != refpage[w - 1]) refpage[w++] = refpage[r];
    n_refpage = w;
}

static int page_is_referenced(uint64_t page) {
    size_t lo = 0, hi = n_refpage;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (refpage[mid] < page) lo = mid + 1; else hi = mid;
    }
    return lo < n_refpage && refpage[lo] == page;
}

// ---- the cache patch table ---------------------------------------------------
//
// The last thing dyld does that a copy of the bytes cannot: fill in GOT slots the
// cache deliberately leaves null.
//
// libsystem_platform loads `&vm_page_size` from a slot at 0x1E7FEC378, which is inside
// no dylib's segments and which the slide information never rebases -- it is zero in
// the file. The cache records, for every exported symbol of every dylib, the list of
// slots referencing it, so that dyld can fill them (and refill them if something
// interposes). Reading that table and writing the addresses in is exactly dyld's job,
// and doing it here means the emulator sees an already-linked cache.
//
// This is a lot of nested structure to get right without the header, so the parse
// checks itself: the table carries the symbol *names*, and the run prints a few. If
// they read as `_vm_page_size` and `_mach_task_self_`, the walk is right; if they are
// garbage, it is wrong and obviously so.
struct patch_target { uint64_t addr; uint64_t value; };
static struct patch_target* patches;
static size_t n_patches, cap_patches;
static const char* patch_sym;          // --patch-sym NAME: show both readings
static int n_shown_sym;
static int patch_cache_relative;       // --patch-cache-relative
static uint64_t cache_base;            // the first mapping's address

static void patch_add(uint64_t addr, uint64_t value) {
    if (n_patches == cap_patches) {
        cap_patches = cap_patches ? cap_patches * 2 : 8192;
        patches = realloc(patches, cap_patches * sizeof *patches);
        if (!patches) die("out of memory");
    }
    patches[n_patches].addr = addr;
    patches[n_patches].value = value;
    n_patches++;
}

// Is this cache image one of the ones being extracted? The patch table on macOS 15
// lists 3.65 *million* locations across 3257 images, and all but a handful belong to
// libraries nobody asked for. A fixed cap on the collection stopped after the first
// 65536 -- every one of them in libobjc, never reaching libsystem_platform, which is
// the whole reason the table was being read.
static int image_is_wanted(uint32_t index) {
    const char* p = image_path((int)index);
    if (!p) return 0;
    for (int i = 0; i < nwant; ++i) if (strcmp(want[i], p) == 0) return 1;
    return 0;
}

static void read_patch_table(void) {
    uint64_t info_addr = 0, info_size = 0;
    memcpy(&info_addr, C.main + 0x98, 8);
    memcpy(&info_size, C.main + 0xA0, 8);
    if (!info_addr || info_size < 112) { printf("patch table: absent\n"); return; }
    const uint8_t* pi = at(info_addr, 112);
    if (!pi) { printf("patch table: at %llx, unmapped\n", (unsigned long long)info_addr); return; }

    uint32_t table_version, loc_version;
    memcpy(&table_version, pi, 4);
    memcpy(&loc_version, pi + 4, 4);
    if (table_version != 2 && table_version != 3 && table_version != 4) {
        printf("patch table: version %u is not implemented; GOT slots the cache leaves "
               "null will stay null\n", table_version);
        return;
    }
    uint64_t f[12];
    for (int i = 0; i < 12; ++i) memcpy(&f[i], pi + 8 + i * 8, 8);
    const uint64_t images_addr = f[0], images_n = f[1];
    const uint64_t exports_addr = f[2], exports_n = f[3];
    const uint64_t clients_addr = f[4], clients_n = f[5];
    const uint64_t cl_exports_addr = f[6], cl_exports_n = f[7];
    const uint64_t locs_addr = f[8], locs_n = f[9];
    const uint64_t names_addr = f[10], names_size = f[11];
    printf("patch table: v%u/%u  %llu images, %llu exports, %llu clients, %llu locations\n",
           table_version, loc_version, (unsigned long long)images_n,
           (unsigned long long)exports_n, (unsigned long long)clients_n,
           (unsigned long long)locs_n);

    const uint8_t* images = at(images_addr, images_n * 16);
    const uint8_t* exports = at(exports_addr, exports_n * 8);
    const uint8_t* clients = at(clients_addr, clients_n * 12);
    const uint8_t* cl_exports = at(cl_exports_addr, cl_exports_n * 12);
    const uint8_t* locs = at(locs_addr, locs_n * 8);
    const uint8_t* names = at(names_addr, names_size);
    if (!images || !exports || !clients || !cl_exports || !locs || !names) {
        printf("patch table: one of its arrays is not mapped; skipped\n");
        return;
    }

    int shown = 0;
    for (uint64_t im = 0; im < images_n && im < images_count; ++im) {
        uint32_t clients_start, clients_count, exports_start, exports_count;
        memcpy(&clients_start, images + im * 16 + 0, 4);
        memcpy(&clients_count, images + im * 16 + 4, 4);
        memcpy(&exports_start, images + im * 16 + 8, 4);
        memcpy(&exports_count, images + im * 16 + 12, 4);
        (void)exports_start; (void)exports_count;
        const uint64_t impl_base = image_addr((int)im);

        for (uint32_t c = 0; c < clients_count; ++c) {
            const uint64_t ci = clients_start + c;
            if (ci >= clients_n) break;
            uint32_t client_index, ce_start, ce_count;
            memcpy(&client_index, clients + ci * 12 + 0, 4);
            memcpy(&ce_start, clients + ci * 12 + 4, 4);
            memcpy(&ce_count, clients + ci * 12 + 8, 4);
            if (client_index >= images_count) continue;
            // Only the libraries being written out. Everything else is somebody
            // else's GOT.
            if (!image_is_wanted(client_index)) continue;
            const uint64_t client_base = image_addr((int)client_index);

            for (uint32_t e = 0; e < ce_count; ++e) {
                const uint64_t ei = ce_start + e;
                if (ei >= cl_exports_n) break;
                uint32_t export_index, loc_start, loc_count;
                memcpy(&export_index, cl_exports + ei * 12 + 0, 4);
                memcpy(&loc_start, cl_exports + ei * 12 + 4, 4);
                memcpy(&loc_count, cl_exports + ei * 12 + 8, 4);
                if (export_index >= exports_n) continue;
                uint32_t impl_off, name_and_kind;
                memcpy(&impl_off, exports + export_index * 8 + 0, 4);
                memcpy(&name_and_kind, exports + export_index * 8 + 4, 4);
                const uint32_t name_off = name_and_kind & 0x0FFFFFFF;
                const char* sym = name_off < names_size ? (const char*)names + name_off : "?";
                if (shown < 6) {
                    printf("    e.g. %s  ->  %llu location(s) in image %u\n", sym,
                           (unsigned long long)loc_count, client_index);
                    shown++;
                }
                for (uint32_t l = 0; l < loc_count; ++l) {
                    const uint64_t li = loc_start + l;
                    if (li >= locs_n) break;
                    uint32_t use_off, bits;
                    memcpy(&use_off, locs + li * 8 + 0, 4);
                    memcpy(&bits, locs + li * 8 + 4, 4);
                    const uint32_t addend = (bits >> 7) & 0x1F;
                    // `dylibOffsetOfUse` and `dylibOffsetOfImpl` are offsets, and the
                    // question is *from where*: the client dylib's mach_header, or the
                    // cache's base. The two differ by wherever that dylib starts, so
                    // one of them produces GOT slots and the other produces addresses
                    // a few megabytes away that are still inside the cache and still
                    // look plausible. --patch-sym prints both for a named symbol so
                    // the answer comes from the cache rather than from reasoning.
                    const uint64_t use_from_dylib = client_base + use_off;
                    const uint64_t use_from_cache = cache_base + use_off;
                    const uint64_t val_from_dylib = impl_base + impl_off + addend;
                    const uint64_t val_from_cache = cache_base + impl_off + addend;
                    // Matches either the symbol name or the client library's path, so
                    // one flag answers both "where does this symbol get patched" and
                    // "what gets patched into this library" -- and the second is the
                    // more useful question when the first turns up nothing.
                    const char* cp = image_path((int)client_index);
                    const int wanted_line =
                        patch_sym && (strcmp(patch_sym, sym) == 0 ||
                                      (cp && strstr(cp, patch_sym) != NULL));
                    if (wanted_line && n_shown_sym < 24) {
                        printf("    %s in %s:\n"
                           "        use  dylib-relative %012llX   cache-relative %012llX\n"
                           "        impl dylib-relative %012llX   cache-relative %012llX\n",
                           sym, image_path((int)client_index),
                           (unsigned long long)use_from_dylib,
                           (unsigned long long)use_from_cache,
                           (unsigned long long)val_from_dylib,
                           (unsigned long long)val_from_cache);
                        n_shown_sym++;
                    }
                    patch_add(patch_cache_relative ? use_from_cache : use_from_dylib,
                              patch_cache_relative ? val_from_cache : val_from_dylib);
                }
            }
        }
    }
    printf("patch table: %zu slot(s) to fill\n", n_patches);
}

static uint64_t apply_patches(uint8_t* dst, uint64_t lo, uint64_t size) {
    uint64_t n = 0;
    for (size_t i = 0; i < n_patches; ++i) {
        if (patches[i].addr < lo || patches[i].addr + 8 > lo + size) continue;
        memcpy(dst + (patches[i].addr - lo), &patches[i].value, 8);
        n++;
    }
    return n;
}

// Walk the slide information and collect every rebased page that no image owns.
static void collect_extras(void) {
    build_owned_ranges();
    printf("extracted libraries own %zu merged address range(s)\n", n_owned);
    for (int m = 0; m < C.nslides; ++m) {
        const struct slidemap* sm = &C.slide[m];
        uint32_t version, page_size, page_count;
        memcpy(&version, sm->info, 4);
        memcpy(&page_size, sm->info + 4, 4);
        memcpy(&page_count, sm->info + 8, 4);
        if (version != 3 && version != 5) continue;
        if (!n_refpage) scan_text_for_references(page_size);
        const uint8_t* starts = sm->info + 24;
        if (24 + (size_t)page_count * 2 > sm->info_size) continue;
        for (uint32_t p = 0; p < page_count; ++p) {
            uint16_t start;
            memcpy(&start, starts + (size_t)p * 2, 2);
            if (start == 0xFFFF) continue;
            const uint64_t page_addr = sm->addr + (uint64_t)p * page_size;
            if (page_owned_by_any_image(page_addr, page_size)) continue;
            // The scan above says which outside pages the extracted code reaches. A
            // page it never names belongs to some other library and is 301 MiB of
            // nobody's business.
            if (!page_is_referenced(page_addr)) continue;
            const uint8_t* src = at(page_addr, page_size);
            if (!src) continue;
            uint8_t* tmp = malloc(page_size);
            if (!tmp) die("out of memory");
            memcpy(tmp, src, page_size);
            apply_slide(tmp, page_addr, page_size);
            apply_patches(tmp, page_addr, page_size);
            run_add(page_addr, tmp, page_size);
            free(tmp);
        }
    }

    // And the pages the patch table writes into, which the slide information never
    // mentions -- they are zero in the file, which is the whole reason dyld has to fill
    // them. Without this the GOT island holding `&vm_page_size` is never collected at
    // all, because there is nothing in it to rebase.
    for (size_t i = 0; i < n_patches; ++i) {
        const uint64_t page = patches[i].addr & ~0x3FFFull;
        if (page_owned_by_any_image(page, 0x4000)) continue;
        int already = 0;
        for (int r = 0; r < nruns && !already; ++r)
            if (page >= runs[r].addr && page < runs[r].addr + runs[r].size) already = 1;
        if (already) continue;
        const uint8_t* src = at(page, 0x4000);
        if (!src) continue;
        uint8_t* tmp = malloc(0x4000);
        if (!tmp) die("out of memory");
        memcpy(tmp, src, 0x4000);
        apply_slide(tmp, page, 0x4000);
        apply_patches(tmp, page, 0x4000);
        run_add(page, tmp, 0x4000);
        free(tmp);
    }
}

int main(int argc, char** argv) {
    const char* outdir = NULL;
    int list = 0, i = 1;
    for (; i < argc; ++i) {
        if (strcmp(argv[i], "--list") == 0) list = 1;
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outdir = argv[++i];
        else if (strcmp(argv[i], "--all-deps") == 0) follow_all_kinds = 1;
        else if (strcmp(argv[i], "--patch-sym") == 0 && i + 1 < argc) patch_sym = argv[++i];
        else if (strcmp(argv[i], "--patch-cache-relative") == 0) patch_cache_relative = 1;
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
    // The cache base: the lowest mapping address, which every "cache-relative"
    // offset in the patch table would be measured from.
    cache_base = C.nmaps ? C.map[0].addr : 0;
    for (int m = 1; m < C.nmaps; ++m) if (C.map[m].addr < cache_base) cache_base = C.map[m].addr;
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

    // After the closure, because the table is filtered to the libraries being written
    // out -- and before anything is copied, because a library's own segments can be
    // patch targets too.
    read_patch_table();

    mkdir(outdir, 0755);
    uint64_t total = 0;
    int done = 0;
    for (int k = 0; k < nwant; ++k) done += extract_one(want[k], outdir, &total);
    printf("\n%d of %d written, %.1f MiB total, into %s\n",
           done, nwant, total / 1048576.0, outdir);
    printf("slide info: %d mapping(s), version %d\n", C.nslides, slide_version_seen);
    // Counted, not guessed -- and this is the single most useful line in the output.
    // A heuristic scan cannot find an unpacked slot: an authenticated one hides
    // behind a diversity field, and a *plain* one reads as an ordinary small integer,
    // indistinguishable from data. So the check is how many slots the slide walk
    // actually rewrote. A guest whose pointers were never unpacked links perfectly
    // and then branches to a signature field tens of instructions in, nowhere near
    // the cause.
    printf("unpacked %llu pointer(s) from the slide information\n",
           (unsigned long long)total_slid);
    // The GOT islands. Not optional: without them a stub table loads a null and the
    // guest dies hundreds of instructions away from the cause.
    collect_extras();
    write_extras(outdir, "/usr/lib/dsc_extras.dylib");
    if (libs_without_slide)
        printf("WARNING: %d librar%s with data segments had no pointers unpacked. The "
               "slide information was not applied, and the result will not run.\n",
               libs_without_slide, libs_without_slide == 1 ? "y" : "ies");
    return 0;
}
