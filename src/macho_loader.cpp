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
#include <cstring>

namespace a64 {

namespace {

constexpr uint32_t kMagic64 = 0xFEEDFACFu;
constexpr int32_t  kCpuArm64 = 0x0100000Cu;
constexpr uint32_t LC_SEGMENT_64 = 0x19, LC_LOAD_DYLINKER = 0x0E, LC_LOAD_DYLIB = 0x0C,
                   LC_ID_DYLIB = 0x0D, LC_SYMTAB = 0x02,
                   LC_MAIN = 0x80000028u, LC_UNIXTHREAD = 0x05,
                   LC_DYLD_INFO_ONLY = 0x80000022u, LC_DYLD_CHAINED_FIXUPS = 0x80000034u,
                   LC_DYLD_EXPORTS_TRIE = 0x80000033u, LC_LOAD_WEAK_DYLIB = 0x80000018u,
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
            case LC_LOAD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
                out->dylibs.push_back(lc_string(f.data(), o, cmdsize, 8));
                out->needs_dyld = true;
                break;
            case LC_RPATH:
                out->rpaths.push_back(lc_string(f.data(), o, cmdsize, 8));
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
    applep.push_back(push_str("executable_path=" + exe_path));

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
