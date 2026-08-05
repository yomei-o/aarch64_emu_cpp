#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "memory.h"

namespace a64 {

struct LoadedImage {
    uint64_t base = 0;           // where an ET_DYN image was placed; 0 for ET_EXEC
    uint64_t entry = 0;          // already adjusted by base
    uint64_t phdr_addr = 0;      // where the program headers ended up in guest memory
    uint64_t phent = 0, phnum = 0;
    uint64_t brk = 0;            // first page above the image: where the heap starts
    std::string interp;          // non-empty for a dynamically linked binary
    uint64_t tls_vaddr = 0, tls_filesz = 0, tls_memsz = 0, tls_align = 0;
    // Mach-O only: the image initializers, deepest dependency first. On Darwin the
    // loader must call these before the entry point; on Linux the guest's own ld.so
    // does it, which is why the ELF path leaves this empty.
    std::vector<uint64_t> initializers;
    // Mach-O only: the address of `dyld4::gAPIs` in libdyld, when a cache-derived
    // libdyld is among the images. Real dyld constructs that object; having replaced
    // dyld, the host has to stand in for it.
    uint64_t dyld_gapis = 0;
    uint64_t objc_opt_ro = 0;
    // The guest's own `exit`, for when an LC_MAIN entry point returns — see the note in
    // macho_dyld.cpp. Without calling it, a program that printed and returned prints
    // nothing, because `exit` is what flushes stdio.
    uint64_t exit_fn = 0;
    // The span the cache-derived libraries occupy, for `_dyld_get_shared_cache_range`.
    // They keep the addresses the cache assigned them, so this really is where the cache
    // was mapped — measured from the images rather than written down, because a different
    // extraction or a different OS moves it.
    uint64_t cache_lo = 0, cache_hi = 0;
    // Every loaded image, in load order: the path the guest should see and where its
    // mach_header landed. libobjc's `map_images` wants exactly these two arrays, and
    // nothing else in the emulator has the list.
    std::vector<std::string> image_paths;
    std::vector<uint64_t> image_headers;
    // Every mapped segment, with the image it belongs to, so an address can be attributed
    // to the image containing it. Segments and not [header, end): a cache-extracted library
    // keeps the cache's addresses, and those are *scattered* — libobjc's __TEXT is at
    // 0x180078000 and its __LINKEDIT at 0x1FED6C000, so a range from the header to the
    // highest segment swallows half the address space and every other library in it.
    struct ImageSeg { uint64_t lo = 0, hi = 0, header = 0; };
    std::vector<ImageSeg> image_segs;
    // Where libdyld keeps the crt globals -- `NXArgc`, `NXArgv`, `environ`, `__progname`.
    // Zero when no libdyld is loaded, in which case there is nothing to fill in.
    struct ProgVars { uint64_t argc = 0, argv = 0, env = 0, progname = 0; };
    ProgVars prog_vars;
};

// `base` is where to place an ET_DYN (PIE or shared object) image; ignored for
// ET_EXEC, which says where it wants to live.
bool load_elf(const std::vector<uint8_t>& f, Memory& mem, uint64_t base,
              LoadedImage* out, std::string* err);

// Builds the initial stack Linux hands a new process and returns the SP to start
// with: argc, argv[], NULL, envp[], NULL, then the auxiliary vector.
//
// `interp_base` is AT_BASE — where the dynamic loader was placed, or 0 when there
// is none. The loader reads it to find itself before anything is relocated.
uint64_t build_stack(Memory& mem, uint64_t stack_top, const LoadedImage& img,
                     uint64_t interp_base,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& envp);

// ---- Mach-O, for Apple Silicon guests (macho_loader.cpp) --------------------

bool is_macho(const std::vector<uint8_t>& f);

// `slide` is where to place a position-independent image (MH_PIE); a fixed-address
// executable says where it wants to live and the slide is ignored for it in
// practice, because its __TEXT vmaddr is absolute.
bool load_macho(const std::vector<uint8_t>& f, Memory& mem, uint64_t slide,
                LoadedImage* out, std::string* err);

// Darwin's initial stack: argc, argv[], NULL, envp[], NULL, apple[], NULL. The
// `apple` vector replaces Linux's auxiliary vector and carries the executable path.
uint64_t build_stack_darwin(Memory& mem, uint64_t stack_top, const std::string& exe_path,
                            const std::vector<std::string>& argv,
                            const std::vector<std::string>& envp);

// A parsed Mach-O: headers read, nothing mapped yet. The file bytes are kept
// because the LINKEDIT blobs -- the export trie, the fixup chains, the symbol
// table -- are parsed lazily and live in the file, not in guest memory.
struct MachoImage {
    std::vector<uint8_t> file;
    std::string guest_path;
    uint64_t slide = 0;              // chosen by the loader; 0 for a fixed executable
    uint64_t text_vmaddr = 0;        // the image's preferred base
    uint64_t vm_end = 0;             // highest vmaddr+vmsize, unslid
    uint64_t entry_off = 0;          // LC_MAIN, from text_vmaddr
    uint64_t unixthread_pc = 0;      // LC_UNIXTHREAD, absolute
    bool has_main = false;
    bool needs_dyld = false;         // has imports, not merely an LC_LOAD_DYLINKER
    std::string dylinker, install_name;
    // Every dylib-referencing load command, **in load-command order**, because a
    // chained import's `lib_ordinal` is a 1-based index into exactly that sequence.
    // Leaving LC_REEXPORT_DYLIB or LC_LOAD_UPWARD_DYLIB out of it does not merely
    // lose a dependency, it shifts every later ordinal and binds symbols to the
    // wrong library.
    std::vector<std::string> dylibs;
    enum DylibKind : uint8_t { kLoad, kWeak, kReexport, kUpward };
    std::vector<uint8_t> dylib_kind;      // parallel to `dylibs`
    std::vector<std::string> rpaths;
    struct Seg { std::string name; uint64_t vmaddr, vmsize, fileoff, filesize; };
    std::vector<Seg> segs;
    // Where an image's initializers live. dyld runs these before main, and libSystem's
    // are what create malloc's zones, the stdio streams and the pthread machinery --
    // so a program that skips them reaches printf and branches through a null pointer.
    // Two encodings, both in use: a list of 64-bit pointers (S_MOD_INIT_FUNC_POINTERS,
    // rebased like any other pointer) or a list of 32-bit offsets from the mach_header
    // (S_INIT_FUNC_OFFSETS, which is what the current toolchain emits).
    struct InitSec { uint64_t addr = 0, size = 0; bool offsets = false; };
    std::vector<InitSec> inits;
    uint32_t fixups_off = 0, fixups_size = 0;
    uint32_t exports_off = 0, exports_size = 0;
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    // The pre-chained-fixups tables: byte-code programs for rebasing and binding,
    // which is how everything built for a deployment target older than Big Sur says
    // the same thing chained fixups say. Every third-party macOS binary that was not
    // relinked has these and no chained fixups at all.
    uint32_t rebase_off = 0, rebase_size = 0;
    uint32_t bind_off = 0, bind_size = 0;
    uint32_t weak_bind_off = 0, weak_bind_size = 0;
    uint32_t lazy_bind_off = 0, lazy_bind_size = 0;
    // Every LC_SEGMENT_64's vmaddr **in load-command order, including __PAGEZERO**.
    // The opcode programs address their target as (segment index, offset), and the
    // index counts every segment command -- so `segs`, which drops __PAGEZERO because
    // nothing maps it, is off by one for any executable that has one.
    std::vector<uint64_t> seg_vmaddrs;
    // The classic indirect-symbol machinery, which a *pre-linked* library still needs
    // for one thing: its __got slots for imported data are left null, and this is what
    // says which symbol each null slot wants. `reserved1` on the section is the index
    // where that section's run of indirect symbols begins.
    uint32_t indirect_off = 0, indirect_count = 0;
    struct GotSec { uint64_t addr = 0, size = 0; uint32_t first_indirect = 0; };
    std::vector<GotSec> got_secs;
    // Every __objc_imageinfo section. A cache dylib's has OPTIMIZED_BY_DYLD set, which
    // tells libobjc its classes are already in the shared cache's tables and it need not
    // read the classlist -- true on a Mac, and a dead end here.
    std::vector<uint64_t> objc_imageinfo;
    // libobjc's own `__TEXT,__objc_opt_ro`: the shared cache's ObjC optimisation header,
    // which on this OS lives inside libobjc rather than in a separate cache region.
    // dyld hands its address to libobjc, and libobjc needs it to interpret the
    // preoptimized class layout the cache uses.
    uint64_t objc_opt_ro = 0;

    // Where the mach_header actually landed. Chained rebases in the OFFSET format
    // are measured from here, not from the slide.
    uint64_t load_addr() const { return slide + text_vmaddr; }
};

bool macho_parse(const std::vector<uint8_t>& f, MachoImage* out, std::string* err);
void macho_map(const MachoImage& img, Memory& mem);

// The result of an export-trie lookup. A hit is not always an address: a library can
// export a name by *re-exporting* it from another, which is how libSystem exports
// the whole of libc while containing almost no code. The caller has to follow that
// edge, so the lookup reports it instead of pretending the symbol is absent.
struct MachoExport {
    bool found = false;
    uint64_t offset = 0;          // from the mach_header, not a virtual address
    bool reexport = false;
    unsigned ordinal = 0;         // into the exporting image's `dylibs`
    std::string import_name;      // the name in that library, when renamed
};
MachoExport macho_lookup_export(const MachoImage& img, const std::string& sym);
// The symbol table, whether or not the name is exported. `dyld4::gAPIs` is private, so
// the export trie does not have it and a bind must not look further -- but the host,
// standing in for dyld, has to find it.
uint64_t macho_lookup_symtab(const MachoImage& img, const std::string& sym);

// Loads a dynamically linked Mach-O and everything it needs, then does dyld's job:
// walks LC_DYLD_CHAINED_FIXUPS and writes the rebased and bound pointers. Apple's
// dyld cannot be shipped, so this stands in for it -- unlike the Linux side, where
// the guest's own ld.so runs.
bool macho_link(const std::vector<uint8_t>& main_file, const std::string& exe_path, Memory& mem,
                uint64_t dylib_base,
                const std::function<std::vector<uint8_t>(const std::string&)>& read_file,
                LoadedImage* out, std::string* err);

}  // namespace a64
