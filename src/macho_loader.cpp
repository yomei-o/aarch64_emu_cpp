// Mach-O arm64 loader — Apple Silicon guests.
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
#include "loader.h"
#include <cstring>

namespace a64 {

namespace {

constexpr uint32_t kMagic64 = 0xFEEDFACFu;
constexpr int32_t  kCpuArm64 = 0x0100000Cu;
constexpr uint32_t LC_SEGMENT_64 = 0x19, LC_LOAD_DYLINKER = 0x0E, LC_LOAD_DYLIB = 0x0C,
                   LC_MAIN = 0x80000028u, LC_UNIXTHREAD = 0x05,
                   LC_DYLD_INFO_ONLY = 0x80000022u, LC_DYLD_CHAINED_FIXUPS = 0x80000034u,
                   LC_LOAD_WEAK_DYLIB = 0x80000018u;

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

}  // namespace

bool is_macho(const std::vector<uint8_t>& f) {
    if (f.size() < sizeof(MachHeader64)) return false;
    uint32_t magic;
    std::memcpy(&magic, f.data(), 4);
    return magic == kMagic64;
}

bool load_macho(const std::vector<uint8_t>& f, Memory& mem, uint64_t slide,
                LoadedImage* out, std::string* err) {
    if (!is_macho(f)) { *err = "not a 64-bit Mach-O"; return false; }
    MachHeader64 mh{};
    std::memcpy(&mh, f.data(), sizeof mh);
    if (mh.cputype != kCpuArm64) { *err = "not an arm64 Mach-O"; return false; }
    if (mh.filetype != 2 && mh.filetype != 8) {   // MH_EXECUTE, MH_DYLINKER
        *err = "not an executable Mach-O"; return false;
    }

    out->interp.clear();
    out->base = slide;
    uint64_t text_vmaddr = 0, brk = 0, entry_off = 0, entry_abs = 0;
    bool have_main = false;

    // LC_LOAD_DYLINKER is present on *every* MH_EXECUTE, including one linked with
    // -nostdlib that imports nothing at all — the linker emits it unconditionally.
    // So its presence is not the question; whether the image has anything for dyld
    // to do is. A binary with no dylibs and no bind opcodes needs no loader, and
    // running it directly is exactly what dyld would arrive at after doing nothing.
    std::string dylinker;
    bool needs_dyld = false;

    size_t o = sizeof mh;
    for (uint32_t i = 0; i < mh.ncmds; ++i) {
        if (o + 8 > f.size()) { *err = "load command out of range"; return false; }
        uint32_t cmd, cmdsize;
        std::memcpy(&cmd, f.data() + o, 4);
        std::memcpy(&cmdsize, f.data() + o + 4, 4);
        if (!cmdsize || o + cmdsize > f.size()) { *err = "bad load command size"; return false; }

        if (cmd == LC_SEGMENT_64) {
            SegmentCommand64 sc{};
            std::memcpy(&sc, f.data() + o, sizeof sc);
            const std::string name(sc.segname, strnlen(sc.segname, 16));
            // __PAGEZERO is a 4 GiB guard hole, not memory. Everything else lands.
            if (name != "__PAGEZERO" && sc.vmsize) {
                const uint64_t va = slide + sc.vmaddr;
                if (sc.filesize) {
                    if (sc.fileoff + sc.filesize > f.size()) {
                        *err = "segment extends past the file"; return false;
                    }
                    mem.write_bytes(va, f.data() + sc.fileoff, sc.filesize);
                }
                if (sc.vmsize > sc.filesize) mem.set(va + sc.filesize, 0, sc.vmsize - sc.filesize);
                if (va + sc.vmsize > brk) brk = va + sc.vmsize;
            }
            if (name == "__TEXT") text_vmaddr = sc.vmaddr;
        } else if (cmd == LC_MAIN) {
            std::memcpy(&entry_off, f.data() + o + 8, 8);
            have_main = true;
        } else if (cmd == LC_UNIXTHREAD) {
            // arm_thread_state64: 29 x-registers, fp, lr, sp, pc. The pc sits at
            // offset 16 (cmd, cmdsize, flavor, count) + 32 * 8.
            if (cmdsize >= 16 + 33 * 8) std::memcpy(&entry_abs, f.data() + o + 16 + 32 * 8, 8);
        } else if (cmd == LC_LOAD_DYLINKER) {
            uint32_t name_off = 0;
            std::memcpy(&name_off, f.data() + o + 8, 4);
            if (name_off < cmdsize) {
                const char* p = reinterpret_cast<const char*>(f.data()) + o + name_off;
                dylinker.assign(p, strnlen(p, cmdsize - name_off));
            }
        } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB) {
            needs_dyld = true;
        } else if (cmd == LC_DYLD_INFO_ONLY && cmdsize >= 48) {
            uint32_t bind_size = 0, lazy_bind_size = 0;
            std::memcpy(&bind_size, f.data() + o + 20, 4);
            std::memcpy(&lazy_bind_size, f.data() + o + 36, 4);
            if (bind_size || lazy_bind_size) needs_dyld = true;
        } else if (cmd == LC_DYLD_CHAINED_FIXUPS && cmdsize >= 16) {
            uint32_t data_size = 0;
            std::memcpy(&data_size, f.data() + o + 12, 4);
            if (data_size) needs_dyld = true;
        }
        o += cmdsize;
    }
    if (needs_dyld) out->interp = dylinker.empty() ? "/usr/lib/dyld" : dylinker;

    out->entry = have_main ? (slide + text_vmaddr + entry_off) : (slide + entry_abs);
    out->brk = (brk + 0x3FFF) & ~0x3FFFull;      // Darwin's page is 16 KiB on arm64
    out->phdr_addr = slide + text_vmaddr;        // dyld reads the header from here
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
