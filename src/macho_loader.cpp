// Mach-O arm64 loading — parsing the load commands and placing the segments.
//
// Structurally simpler than ELF: a header, then a list of load commands, of which
// only LC_SEGMENT_64 actually places bytes. The differences that matter:
//
//  - **__PAGEZERO.** The first segment is a 4 GiB hole with no file content and no
//    permissions, there to make a null dereference fault. Mapping it would allocate
//    four billion bytes of nothing; it is skipped.
//  - **LC_MAIN gives an offset, not an address.** `entryoff` is measured from the
//    start of the file, which is the same as the start of __TEXT, which is the
//    image base. LC_UNIXTHREAD (older, and what a hand-linked freestanding binary
//    may carry) gives a whole register state instead, and its PC is absolute.
//  - **The `apple[]` array.** Darwin's stack has a fourth NULL-terminated vector
//    after envp carrying `executable_path=…` and friends. dyld reads it before
//    anything else, so it is not optional for a real binary.
//
// Everything about *linking* — dependencies, chained fixups, symbol binding — is
// in macho_dyld.cpp; this file only reads and places.
#include "loader.h"
#include <cstdio>
#include <cstring>

namespace a64 {

namespace {

constexpr uint32_t kMagic64 = 0xFEEDFACFu;
constexpr int32_t  kCpuArm64 = 0x0100000Cu;
constexpr uint32_t LC_SEGMENT_64 = 0x19, LC_LOAD_DYLINKER = 0x0E, LC_LOAD_DYLIB = 0x0C,
                   LC_ID_DYLIB = 0x0D, LC_SYMTAB = 0x02, LC_DYSYMTAB = 0x0B,
                   LC_MAIN = 0x80000028u, LC_UNIXTHREAD = 0x05,
                   LC_DYLD_INFO_ONLY = 0x80000022u, LC_DYLD_CHAINED_FIXUPS = 0x80000034u,
                   LC_DYLD_EXPORTS_TRIE = 0x80000033u, LC_LOAD_WEAK_DYLIB = 0x80000018u,
                   LC_REEXPORT_DYLIB = 0x8000001Fu, LC_LOAD_UPWARD_DYLIB = 0x80000023u,
                   LC_RPATH = 0x8000001Cu;

struct MachHeader64 {
    uint32_t magic; int32_t cputype, cpusubtype;
    uint32_t filetype, ncmds, sizeofcmds, flags, reserved;
};
struct SegmentCommand64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    int32_t maxprot, initprot;
    uint32_t nsects, flags;
};

// An lc_str is a 32-bit offset from the start of the load command.
std::string lc_string(const uint8_t* f, size_t o, uint32_t cmdsize, size_t at) {
    uint32_t off = 0;
    std::memcpy(&off, f + o + at, 4);
    if (off >= cmdsize) return {};
    const char* p = reinterpret_cast<const char*>(f) + o + off;
    return std::string(p, strnlen(p, cmdsize - off));
}

}  // namespace

bool is_macho(const std::vector<uint8_t>& f) {
    if (f.size() < sizeof(MachHeader64)) return false;
    uint32_t magic;
    std::memcpy(&magic, f.data(), 4);
    return magic == kMagic64;
}

bool macho_parse(const std::vector<uint8_t>& f, MachoImage* out, std::string* err) {
    if (!is_macho(f)) { *err = "not a 64-bit Mach-O"; return false; }
    MachHeader64 mh{};
    std::memcpy(&mh, f.data(), sizeof mh);
    if (mh.cputype != kCpuArm64) { *err = "not an arm64 Mach-O"; return false; }
    // MH_EXECUTE, MH_DYLIB, MH_DYLINKER, MH_BUNDLE.
    if (mh.filetype != 2 && mh.filetype != 6 && mh.filetype != 7 && mh.filetype != 8) {
        *err = "not an executable or library Mach-O"; return false;
    }
    out->file = f;

    size_t o = sizeof mh;
    for (uint32_t i = 0; i < mh.ncmds; ++i) {
        if (o + 8 > f.size()) { *err = "load command out of range"; return false; }
        uint32_t cmd, cmdsize;
        std::memcpy(&cmd, f.data() + o, 4);
        std::memcpy(&cmdsize, f.data() + o + 4, 4);
        if (!cmdsize || o + cmdsize > f.size()) { *err = "bad load command size"; return false; }

        switch (cmd) {
            case LC_SEGMENT_64: {
                SegmentCommand64 sc{};
                std::memcpy(&sc, f.data() + o, sizeof sc);
                const std::string name(sc.segname, strnlen(sc.segname, 16));
                if (sc.fileoff + sc.filesize > f.size()) {
                    *err = "segment extends past the file"; return false;
                }
                if (name != "__PAGEZERO" && sc.vmsize) {
                    out->segs.push_back({name, sc.vmaddr, sc.vmsize, sc.fileoff, sc.filesize});
                    if (sc.vmaddr + sc.vmsize > out->vm_end) out->vm_end = sc.vmaddr + sc.vmsize;
                }
                // Initializer sections, found by section *type* rather than by name:
                // __mod_init_func and __init_offsets are the conventional names but
                // the type is what the loader is specified to look at.
                for (uint32_t s = 0; s < sc.nsects; ++s) {
                    const size_t so = o + sizeof sc + s * 80;
                    if (so + 80 > f.size()) break;
                    uint64_t addr, size;
                    uint32_t sflags;
                    std::memcpy(&addr, f.data() + so + 32, 8);
                    std::memcpy(&size, f.data() + so + 40, 8);
                    std::memcpy(&sflags, f.data() + so + 64, 4);
                    const uint32_t type = sflags & 0xFF;
                    if (type == 0x09) out->inits.push_back({addr, size, false});
                    else if (type == 0x16) out->inits.push_back({addr, size, true});
                    // S_NON_LAZY_SYMBOL_POINTERS / S_LAZY_SYMBOL_POINTERS: the __got
                    // and __auth_got tables. reserved1 is where this section's run of
                    // indirect symbols starts.
                    else if (type == 0x06 || type == 0x07) {
                        uint32_t reserved1 = 0;
                        std::memcpy(&reserved1, f.data() + so + 68, 4);
                        out->got_secs.push_back({addr, size, reserved1});
                    }
                }
                // __TEXT starts at the mach_header, so its vmaddr is the image base.
                if (name == "__TEXT") out->text_vmaddr = sc.vmaddr;
                break;
            }
            case LC_MAIN:
                std::memcpy(&out->entry_off, f.data() + o + 8, 8);
                out->has_main = true;
                break;
            case LC_UNIXTHREAD:
                // arm_thread_state64: 29 x-registers, fp, lr, sp, pc. The pc sits at
                // offset 16 (cmd, cmdsize, flavor, count) + 32 * 8.
                if (cmdsize >= 16 + 33 * 8)
                    std::memcpy(&out->unixthread_pc, f.data() + o + 16 + 32 * 8, 8);
                break;
            case LC_LOAD_DYLINKER:
                out->dylinker = lc_string(f.data(), o, cmdsize, 8);
                break;
            case LC_ID_DYLIB:
                out->install_name = lc_string(f.data(), o, cmdsize, 8);
                break;
            // All four kinds go into one list, in order: `lib_ordinal` in a chained
            // import indexes this sequence, so skipping a kind renumbers the rest.
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
                out->dylibs.push_back(lc_string(f.data(), o, cmdsize, 8));
                out->dylib_kind.push_back(
                    cmd == LC_LOAD_DYLIB ? MachoImage::kLoad :
                    cmd == LC_LOAD_WEAK_DYLIB ? MachoImage::kWeak :
                    cmd == LC_REEXPORT_DYLIB ? MachoImage::kReexport : MachoImage::kUpward);
                out->needs_dyld = true;
                break;
            case LC_RPATH:
                out->rpaths.push_back(lc_string(f.data(), o, cmdsize, 8));
                break;
            case LC_DYSYMTAB:
                if (cmdsize >= 64) {
                    std::memcpy(&out->indirect_off, f.data() + o + 56, 4);
                    std::memcpy(&out->indirect_count, f.data() + o + 60, 4);
                }
                break;
            case LC_SYMTAB:
                std::memcpy(&out->symoff, f.data() + o + 8, 4);
                std::memcpy(&out->nsyms, f.data() + o + 12, 4);
                std::memcpy(&out->stroff, f.data() + o + 16, 4);
                std::memcpy(&out->strsize, f.data() + o + 20, 4);
                break;
            case LC_DYLD_CHAINED_FIXUPS:
                std::memcpy(&out->fixups_off, f.data() + o + 8, 4);
                std::memcpy(&out->fixups_size, f.data() + o + 12, 4);
                if (out->fixups_size) out->needs_dyld = true;
                break;
            case LC_DYLD_EXPORTS_TRIE:
                std::memcpy(&out->exports_off, f.data() + o + 8, 4);
                std::memcpy(&out->exports_size, f.data() + o + 12, 4);
                break;
            case LC_DYLD_INFO_ONLY: {
                if (cmdsize < 48) break;
                std::memcpy(&out->rebase_size, f.data() + o + 12, 4);
                std::memcpy(&out->bind_size, f.data() + o + 20, 4);
                std::memcpy(&out->lazy_bind_size, f.data() + o + 36, 4);
                std::memcpy(&out->exports_off, f.data() + o + 40, 4);
                std::memcpy(&out->exports_size, f.data() + o + 44, 4);
                if (out->bind_size || out->lazy_bind_size) out->needs_dyld = true;
                break;
            }
            default: break;
        }
        o += cmdsize;
    }
    if (out->segs.empty()) { *err = "Mach-O has no loadable segment"; return false; }
    return true;
}

void macho_map(const MachoImage& img, Memory& mem) {
    for (const MachoImage::Seg& s : img.segs) {
        const uint64_t va = img.slide + s.vmaddr;
        if (s.filesize) mem.write_bytes(va, img.file.data() + s.fileoff, s.filesize);
        if (s.vmsize > s.filesize) mem.set(va + s.filesize, 0, s.vmsize - s.filesize);
    }
}

bool load_macho(const std::vector<uint8_t>& f, Memory& mem, uint64_t slide,
                LoadedImage* out, std::string* err) {
    MachoImage img;
    if (!macho_parse(f, &img, err)) return false;
    img.slide = slide;
    macho_map(img, mem);

    // LC_LOAD_DYLINKER is present on *every* MH_EXECUTE, including one linked with
    // -nostdlib that imports nothing at all — the linker emits it unconditionally.
    // So its presence is not the question; whether the image has anything for dyld
    // to do is. That question is answered in macho_parse, as `needs_dyld`.
    out->interp = img.needs_dyld ? (img.dylinker.empty() ? "/usr/lib/dyld" : img.dylinker)
                                 : std::string();
    out->base = slide;
    out->entry = img.has_main ? (slide + img.text_vmaddr + img.entry_off)
                              : (slide + img.unixthread_pc);
    out->brk = (slide + img.vm_end + 0x3FFF) & ~0x3FFFull;   // arm64 macOS pages are 16 KiB
    out->phdr_addr = slide + img.text_vmaddr;
    out->phent = 0;
    out->phnum = 0;
    if (!out->entry) { *err = "Mach-O has no entry point"; return false; }
    return true;
}

// Darwin's initial stack. Same shape as Linux's up to envp, then an `apple[]`
// vector instead of an auxiliary vector — a NULL-terminated list of strings whose
// first entry is the executable path. A statically linked test never looks at it;
// dyld reads it immediately.
uint64_t build_stack_darwin(Memory& mem, uint64_t stack_top, const std::string& exe_path,
                            const std::vector<std::string>& argv,
                            const std::vector<std::string>& envp) {
    uint64_t p = stack_top;
    auto push_str = [&](const std::string& s) {
        p -= s.size() + 1;
        mem.write_bytes(p, s.c_str(), s.size() + 1);
        return p;
    };

    std::vector<uint64_t> argp, envpp, applep;
    for (const std::string& s : argv) argp.push_back(push_str(s));
    for (const std::string& s : envp) envpp.push_back(push_str(s));

    // The `apple[]` vector is not decoration. dyld and the kernel pass real values
    // through it, and libSystem reads them before it will run: libpthread looks for
    // `ptr_munge=` and calls a zero there fatal — "BUG IN LIBPTHREAD: Token from the
    // kernel is 0", which names neither the vector nor the key.
    //
    // The cookies are *fixed* rather than random, deliberately. On a real system they
    // are entropy, and the guest must not depend on their values; here reproducibility
    // is worth more, because a differential test whose output moves between runs cannot
    // be compared against anything.
    auto hex = [](const char* key, uint64_t v) {
        char buf[64];
        std::snprintf(buf, sizeof buf, "%s=0x%llx", key, static_cast<unsigned long long>(v));
        return std::string(buf);
    };
    applep.push_back(push_str("executable_path=" + exe_path));
    applep.push_back(push_str(hex("ptr_munge", 0x0F1E2D3C4B5A6978ull)));
    applep.push_back(push_str(hex("stack_guard", 0x00C0FFEE00C0FFEEull)));
    applep.push_back(push_str(hex("th_port", 0x103)));       // what thread_self_trap returns
    applep.push_back(push_str("malloc_entropy=0x1234567812345678,0x8765432187654321"));
    {
        // main_stack: top, size, then the guard region below it. A guest that trusts
        // these will fault at the guard rather than run off the end quietly.
        constexpr uint64_t kSize = 8ull << 20, kGuard = 4ull << 20;
        char buf[128];
        std::snprintf(buf, sizeof buf, "main_stack=0x%llx,0x%llx,0x%llx,0x%llx",
                      static_cast<unsigned long long>(stack_top),
                      static_cast<unsigned long long>(kSize),
                      static_cast<unsigned long long>(stack_top - kSize),
                      static_cast<unsigned long long>(kGuard));
        applep.push_back(push_str(buf));
    }

    const size_t words = 1 + argp.size() + 1 + envpp.size() + 1 + applep.size() + 1;
    uint64_t sp = (p - words * 8) & ~0xFull;
    uint64_t w = sp;
    auto put = [&](uint64_t v) { mem.write<uint64_t>(w, v); w += 8; };
    put(argp.size());
    for (uint64_t a : argp) put(a);
    put(0);
    for (uint64_t e : envpp) put(e);
    put(0);
    for (uint64_t a : applep) put(a);
    put(0);
    return sp;
}

}  // namespace a64
