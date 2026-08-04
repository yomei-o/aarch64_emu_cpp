// ELF64 loader for AArch64 Linux executables.
//
// Static binaries only for now, which is a deliberate first target rather than a
// limitation to apologise for: a static musl build has no interpreter to find, no
// relocations to apply and no shared objects to resolve, so everything the guest
// does goes through the syscall layer. That makes the kernel interface the only
// surface to get right, which is exactly the surface a Python build exercises.
// Dynamic linking is the next milestone (see resume.md).
//
// The initial process image is laid out the way Linux lays it out, because a libc
// reads all of it before main(): argc/argv/envp on the stack, then the auxiliary
// vector, which is where AT_PHDR, AT_ENTRY, AT_RANDOM and AT_PAGESZ come from. Get
// the auxv wrong and a static musl faults before it prints anything.
#include "loader.h"
#include <cstring>
#include <cstdio>

namespace a64 {

namespace {

struct Ehdr {
    uint8_t ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};
struct Phdr {
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
};

constexpr uint32_t PT_LOAD = 1, PT_INTERP = 3, PT_TLS = 7;

// Auxiliary vector keys a libc startup actually reads.
constexpr uint64_t AT_NULL = 0, AT_PHDR = 3, AT_PHENT = 4, AT_PHNUM = 5,
                   AT_PAGESZ = 6, AT_BASE = 7, AT_ENTRY = 9, AT_UID = 11,
                   AT_EUID = 12, AT_GID = 13, AT_EGID = 14, AT_HWCAP = 16,
                   AT_CLKTCK = 17, AT_RANDOM = 25, AT_SECURE = 23, AT_EXECFN = 31;

}  // namespace

bool load_elf(const std::vector<uint8_t>& f, Memory& mem, LoadedImage* out, std::string* err) {
    if (f.size() < sizeof(Ehdr) || std::memcmp(f.data(), "\x7f" "ELF", 4) != 0) {
        *err = "not an ELF file"; return false;
    }
    Ehdr eh{};
    std::memcpy(&eh, f.data(), sizeof eh);
    if (eh.ident[4] != 2) { *err = "not ELF64"; return false; }
    if (eh.ident[5] != 1) { *err = "not little-endian"; return false; }
    if (eh.machine != 183) { *err = "not an AArch64 image (EM_AARCH64 = 183)"; return false; }
    if (eh.type != 2 && eh.type != 3) { *err = "not an executable"; return false; }

    out->entry = eh.entry;
    out->phdr_addr = 0;
    out->phent = eh.phentsize;
    out->phnum = eh.phnum;
    out->interp.clear();
    uint64_t brk = 0;

    for (unsigned i = 0; i < eh.phnum; ++i) {
        const size_t po = static_cast<size_t>(eh.phoff) + i * eh.phentsize;
        if (po + sizeof(Phdr) > f.size()) { *err = "program header out of range"; return false; }
        Phdr ph{};
        std::memcpy(&ph, f.data() + po, sizeof ph);

        if (ph.type == PT_INTERP && ph.filesz) {
            out->interp.assign(reinterpret_cast<const char*>(f.data() + ph.offset),
                               static_cast<size_t>(ph.filesz - 1));
        }
        if (ph.type == PT_TLS) { out->tls_vaddr = ph.vaddr; out->tls_filesz = ph.filesz;
                                 out->tls_memsz = ph.memsz; out->tls_align = ph.align; }
        if (ph.type != PT_LOAD) continue;
        if (ph.offset + ph.filesz > f.size()) { *err = "PT_LOAD extends past the file"; return false; }
        mem.write_bytes(ph.vaddr, f.data() + ph.offset, ph.filesz);
        if (ph.memsz > ph.filesz) mem.set(ph.vaddr + ph.filesz, 0, ph.memsz - ph.filesz);  // .bss
        if (ph.vaddr + ph.memsz > brk) brk = ph.vaddr + ph.memsz;

        // The program headers are usually inside the first PT_LOAD; a libc finds them
        // through AT_PHDR and walks them to locate its own PT_TLS and PT_DYNAMIC.
        if (!out->phdr_addr && ph.offset <= eh.phoff &&
            eh.phoff + static_cast<uint64_t>(eh.phnum) * eh.phentsize <= ph.offset + ph.filesz) {
            out->phdr_addr = ph.vaddr + (eh.phoff - ph.offset);
        }
    }
    out->brk = (brk + 0xFFF) & ~0xFFFull;
    return true;
}

uint64_t build_stack(Memory& mem, uint64_t stack_top, const LoadedImage& img,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& envp) {
    // Strings first, growing down from the top, then the pointer arrays below them.
    uint64_t p = stack_top;
    auto push_str = [&](const std::string& s) {
        p -= s.size() + 1;
        mem.write_bytes(p, s.c_str(), s.size() + 1);
        return p;
    };

    std::vector<uint64_t> argp, envpp;
    for (const std::string& s : argv) argp.push_back(push_str(s));
    for (const std::string& s : envp) envpp.push_back(push_str(s));

    // AT_RANDOM must point at 16 readable bytes; musl copies them into its stack
    // guard and TLS canary before anything else runs.
    const uint8_t rnd[16] = {0x5a, 0x0f, 0x1c, 0x77, 0x21, 0x93, 0xb4, 0xe6,
                             0x38, 0xd1, 0x4c, 0x0a, 0x95, 0x62, 0xfe, 0x83};
    p -= sizeof rnd;
    const uint64_t random_addr = p;
    mem.write_bytes(p, rnd, sizeof rnd);

    const uint64_t execfn = argp.empty() ? 0 : argp[0];

    std::vector<std::pair<uint64_t, uint64_t>> aux = {
        {AT_PHDR, img.phdr_addr}, {AT_PHENT, img.phent}, {AT_PHNUM, img.phnum},
        {AT_PAGESZ, 4096}, {AT_BASE, 0}, {AT_ENTRY, img.entry},
        {AT_UID, 1000}, {AT_EUID, 1000}, {AT_GID, 1000}, {AT_EGID, 1000},
        {AT_SECURE, 0}, {AT_CLKTCK, 100},
        // FP and ASIMD present. A libc reads this to pick memcpy variants; claiming
        // nothing is not safer, it just selects the byte-at-a-time paths.
        {AT_HWCAP, 0x3}, {AT_RANDOM, random_addr}, {AT_EXECFN, execfn},
        {AT_NULL, 0},
    };

    // The whole block has to leave SP 16-byte aligned, which the ABI requires and
    // which a `stp` in the entry stub will fault on if it is wrong.
    const size_t words = 1 + argp.size() + 1 + envpp.size() + 1 + aux.size() * 2;
    uint64_t sp = p - words * 8;
    sp &= ~0xFull;

    uint64_t w = sp;
    auto put = [&](uint64_t v) { mem.write<uint64_t>(w, v); w += 8; };
    put(argp.size());
    for (uint64_t a : argp) put(a);
    put(0);
    for (uint64_t e : envpp) put(e);
    put(0);
    for (auto& kv : aux) { put(kv.first); put(kv.second); }
    return sp;
}

}  // namespace a64
