// Being dyld.
//
// A macOS binary that imports anything cannot just be mapped and jumped to: its
// calls go through a __got full of placeholders, and something has to load the
// libraries and write the real addresses in. On a Mac that something is
// /usr/lib/dyld, which is not a file you can obtain without a Mac — so this file
// does dyld's job instead.
//
// That is the opposite of the choice made for Linux, where the guest's own musl
// ld.so runs and this emulator stays out of it. The reason for the difference is
// availability, not preference: musl's loader ships inside the guest tree, Apple's
// does not. Where a real dyld can be supplied, running it would still be better.
//
// What dyld actually has to do for a modern arm64 binary is narrower than its
// reputation suggests:
//
//   1. map the dependencies named by LC_LOAD_DYLIB, recursively;
//   2. walk LC_DYLD_CHAINED_FIXUPS — a linked list of pointer slots threaded
//      through each page — and at every slot either add the slide (a *rebase*) or
//      write the address of an imported symbol (a *bind*);
//   3. find those symbols in the exporting image's export trie.
//
// Lazy binding, the old opcode-based LC_DYLD_INFO tables, two-level namespace
// hints and the shared cache are all absent from that list, because a binary built
// with chained fixups does not use them.
#include "loader.h"
#include <cstring>
#include <functional>
#include <algorithm>
#include <map>

namespace a64 {

namespace {

// ---- little readers ---------------------------------------------------------

uint64_t read_uleb(const uint8_t* p, size_t size, size_t* off) {
    uint64_t r = 0;
    unsigned shift = 0;
    while (*off < size) {
        const uint8_t b = p[(*off)++];
        r |= static_cast<uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return r;
}

constexpr uint32_t kImportPlain = 1, kImportAddend = 2;
constexpr uint16_t kPtr64 = 2, kPtr64Offset = 6;
constexpr uint16_t kStartNone = 0xFFFF;

// Export flags that mean the address is not a plain address.
constexpr uint64_t kExportReexport = 0x08, kExportStubResolver = 0x10;

std::string dirname_of(const std::string& p) {
    const size_t s = p.find_last_of('/');
    return s == std::string::npos ? std::string(".") : p.substr(0, s);
}

}  // namespace

// ---- the export trie --------------------------------------------------------
//
// A prefix tree over symbol names, so a lookup walks the name one edge at a time
// rather than scanning a symbol table. Each node carries an optional terminal
// payload followed by its children; the payload's *size* is stored ahead of it so
// a walker can skip a node it does not care about, which is the whole trick.
uint64_t macho_lookup_export(const MachoImage& img, const std::string& sym) {
    if (img.exports_size) {
        const uint8_t* p = img.file.data() + img.exports_off;
        const size_t size = img.exports_size;
        size_t node = 0, matched = 0;
        for (;;) {
            if (node >= size) return 0;
            size_t off = node;
            const uint64_t term = read_uleb(p, size, &off);
            if (matched == sym.size() && term) {
                const uint64_t flags = read_uleb(p, size, &off);
                // A re-export points at another image and a resolver needs to run
                // guest code; neither is a plain address, so refuse rather than
                // return the wrong number.
                if (flags & (kExportReexport | kExportStubResolver)) return 0;
                return read_uleb(p, size, &off);
            }
            const size_t children = off + term;
            if (children >= size) return 0;
            size_t c = children;
            const uint8_t nchild = p[c++];
            bool advanced = false;
            for (uint8_t i = 0; i < nchild && c < size; ++i) {
                const char* edge = reinterpret_cast<const char*>(p) + c;
                const size_t elen = strnlen(edge, size - c);
                c += elen + 1;
                size_t tmp = c;
                const uint64_t child = read_uleb(p, size, &tmp);
                c = tmp;
                if (!advanced && sym.compare(matched, elen, edge, elen) == 0) {
                    matched += elen;
                    node = static_cast<size_t>(child);
                    advanced = true;
                    // Keep scanning the remaining children only to advance `c`
                    // correctly is unnecessary — we jump to the child immediately.
                    break;
                }
            }
            if (!advanced) return 0;
        }
    }
    // No trie: fall back to the symbol table. A stripped dylib has neither, and
    // then the symbol genuinely is not there.
    for (uint32_t i = 0; i < img.nsyms; ++i) {
        const uint8_t* n = img.file.data() + img.symoff + i * 16;
        uint32_t strx;
        std::memcpy(&strx, n, 4);
        const uint8_t type = n[4];
        if (!(type & 0x01)) continue;                      // N_EXT
        if ((type & 0x0E) != 0x0E) continue;               // N_SECT
        const char* name = reinterpret_cast<const char*>(img.file.data()) + img.stroff + strx;
        if (sym == name) {
            uint64_t value;
            std::memcpy(&value, n + 8, 8);
            return value;
        }
    }
    return 0;
}

// ---- chained fixups ---------------------------------------------------------

bool macho_apply_fixups(const MachoImage& img, Memory& mem,
                        const std::function<uint64_t(unsigned ordinal, const std::string& sym,
                                                     bool weak)>& resolve,
                        std::string* err) {
    if (!img.fixups_size) {
        // An image built before chained fixups expresses the same work as byte-code
        // programs under LC_DYLD_INFO. Those are not implemented -- and "not
        // implemented" here has to mean *stop*, because the alternative is loading
        // the image with every pointer left exactly as the linker wrote it: a
        // rebase that never happened reads as a valid pointer to the wrong place,
        // and the guest gets a plausible answer instead of a crash. That cost a
        // debugging cycle the first time, on a dylib built without -fixup_chains.
        if (img.rebase_size || img.bind_size || img.lazy_bind_size) {
            *err = "image uses the pre-chained-fixups LC_DYLD_INFO opcodes, "
                   "which are not implemented (relink with -fixup_chains)";
            return false;
        }
        return true;                                       // genuinely nothing to do
    }
    const uint8_t* base = img.file.data() + img.fixups_off;
    const size_t size = img.fixups_size;
    if (size < 28) { *err = "chained fixups header is truncated"; return false; }

    uint32_t starts_off, imports_off, symbols_off, imports_count, imports_format;
    std::memcpy(&starts_off, base + 4, 4);
    std::memcpy(&imports_off, base + 8, 4);
    std::memcpy(&symbols_off, base + 12, 4);
    std::memcpy(&imports_count, base + 16, 4);
    std::memcpy(&imports_format, base + 20, 4);
    if (imports_format != kImportPlain && imports_format != kImportAddend) {
        *err = "unsupported chained-import format (64-bit addends)";
        return false;
    }

    // Resolve every import once, up front: the same symbol usually appears in more
    // than one chain, and a lookup walks a trie.
    std::vector<uint64_t> import_addr(imports_count, 0);
    const unsigned entry_size = imports_format == kImportPlain ? 4 : 8;
    for (uint32_t i = 0; i < imports_count; ++i) {
        const size_t o = imports_off + static_cast<size_t>(i) * entry_size;
        if (o + entry_size > size) { *err = "chained imports run past the blob"; return false; }
        uint32_t w;
        std::memcpy(&w, base + o, 4);
        const unsigned ordinal = w & 0xFF;
        const bool weak = (w >> 8) & 1;
        const uint32_t name_off = w >> 9;
        const char* name = reinterpret_cast<const char*>(base) + symbols_off + name_off;
        import_addr[i] = resolve(ordinal, std::string(name, strnlen(name, size - symbols_off - name_off)),
                                 weak);
    }

    if (starts_off + 4 > size) { *err = "chained starts run past the blob"; return false; }
    uint32_t seg_count;
    std::memcpy(&seg_count, base + starts_off, 4);
    for (uint32_t s = 0; s < seg_count; ++s) {
        uint32_t seg_info;
        std::memcpy(&seg_info, base + starts_off + 4 + s * 4, 4);
        if (!seg_info) continue;                           // segment has no fixups
        const uint8_t* si = base + starts_off + seg_info;
        uint16_t page_size, ptr_format, page_count;
        uint64_t segment_offset;
        std::memcpy(&page_size, si + 4, 2);
        std::memcpy(&ptr_format, si + 6, 2);
        std::memcpy(&segment_offset, si + 8, 8);
        std::memcpy(&page_count, si + 20, 2);
        if (ptr_format != kPtr64 && ptr_format != kPtr64Offset) {
            *err = "unsupported chained-pointer format (arm64e signed pointers?)";
            return false;
        }

        for (uint16_t pg = 0; pg < page_count; ++pg) {
            uint16_t start;
            std::memcpy(&start, si + 22 + pg * 2, 2);
            if (start == kStartNone) continue;
            // segment_offset is measured from the **mach_header**, not from the
            // slide. For a dylib preferring address 0 the two are the same, so the
            // difference only shows up in an executable -- where it lands the whole
            // chain walk 4 GiB low, in unmapped memory, and every fixup silently
            // does nothing.
            uint64_t addr = img.load_addr() + segment_offset +
                            static_cast<uint64_t>(pg) * page_size + start;
            for (;;) {
                const uint64_t raw = mem.read<uint64_t>(addr);
                const uint64_t next = (raw >> 51) & 0xFFF;
                const bool bind = (raw >> 63) & 1;
                uint64_t value;
                if (bind) {
                    const uint32_t ordinal = static_cast<uint32_t>(raw & 0xFFFFFF);
                    const uint64_t addend = (raw >> 24) & 0xFF;
                    if (ordinal >= imports_count) {
                        *err = "chained bind names an import that does not exist";
                        return false;
                    }
                    value = import_addr[ordinal] ? import_addr[ordinal] + addend : 0;
                } else {
                    const uint64_t target = raw & 0xFFFFFFFFFull;      // 36 bits
                    const uint64_t high8 = (raw >> 36) & 0xFF;
                    // PTR_64 stores the unslid virtual *address*; PTR_64_OFFSET
                    // stores an offset from where the image was loaded. They differ
                    // by exactly the image's preferred base, which is zero for a
                    // dylib and 0x1_0000_0000 for an executable — so reading one as
                    // the other is invisible in a library and four gigabytes out in
                    // a program.
                    value = (ptr_format == kPtr64Offset ? img.load_addr() + target
                                                        : img.slide + target) |
                            (high8 << 56);
                }
                mem.write<uint64_t>(addr, value);
                if (!next) break;
                addr += next * 4;
            }
        }
    }
    return true;
}

// ---- the loader itself ------------------------------------------------------

namespace {

// @rpath, @executable_path and @loader_path: install names are relative to the
// thing doing the loading, not to the filesystem.
std::vector<std::string> expand_path(const std::string& name, const std::string& exe_dir,
                                     const std::string& loader_dir,
                                     const std::vector<std::string>& rpaths) {
    auto sub = [&](const std::string& s) {
        if (s.compare(0, 17, "@executable_path/") == 0) return exe_dir + "/" + s.substr(17);
        if (s.compare(0, 13, "@loader_path/") == 0) return loader_dir + "/" + s.substr(13);
        return s;
    };
    if (name.compare(0, 7, "@rpath/") == 0) {
        std::vector<std::string> out;
        const std::string tail = name.substr(7);
        for (const std::string& r : rpaths) out.push_back(sub(r) + "/" + tail);
        return out;
    }
    return {sub(name)};
}

}  // namespace

bool macho_link(const std::vector<uint8_t>& main_file, const std::string& exe_path, Memory& mem,
                uint64_t dylib_base,
                const std::function<std::vector<uint8_t>(const std::string&)>& read_file,
                LoadedImage* out, std::string* err) {
    std::vector<MachoImage> images;
    std::vector<std::string> missing_libs, unresolved;
    images.reserve(16);

    MachoImage main_img;
    if (!macho_parse(main_file, &main_img, err)) return false;
    main_img.slide = 0;                 // a fixed-address executable says where it goes
    main_img.guest_path = exe_path;
    images.push_back(std::move(main_img));

    const std::string exe_dir = dirname_of(exe_path);
    uint64_t next_base = dylib_base, high = 0;

    // Breadth-first over the dependency graph, deduplicated by install name so a
    // diamond does not map the same library twice at two addresses — which would
    // silently give a library two copies of its own globals.
    std::map<std::string, size_t> by_name;
    for (size_t i = 0; i < images.size(); ++i) {
        // Copies, not references: the push_back below can reallocate the vector out
        // from under anything pointing into it.
        const std::vector<std::string> deps = images[i].dylibs;
        const std::vector<std::string> rpaths = images[i].rpaths;
        const std::string who = images[i].guest_path;
        const std::string loader_dir = dirname_of(who);
        for (const std::string& dep : deps) {
            if (by_name.count(dep)) continue;
            std::vector<uint8_t> bytes;
            std::string found;
            for (const std::string& cand : expand_path(dep, exe_dir, loader_dir, rpaths)) {
                bytes = read_file(cand);
                if (!bytes.empty()) { found = cand; break; }
            }
            if (bytes.empty()) {
                // Not fatal here, deliberately. A guest extracted from a shared cache
                // will be missing whatever the extraction did not follow, and most of
                // it is never called -- so the useful thing is to finish, collect
                // *everything* that is absent, and report the whole list at once.
                // Failing on the first one turns each iteration into a single
                // library, and there are hundreds.
                missing_libs.push_back(dep + "  (needed by " + who + ")");
                by_name[dep] = SIZE_MAX;            // remembered, so it is reported once
                continue;
            }
            MachoImage lib;
            if (!macho_parse(bytes, &lib, err)) { *err = dep + ": " + *err; return false; }
            // A library that prefers address 0 has to be given somewhere to go. One
            // that names a nonzero address has already been placed there and must not
            // move: that is how every library extracted from a shared cache arrives,
            // pre-linked against its neighbours at their cache addresses. Sliding one
            // of those breaks every pointer that already pointed into it.
            lib.guest_path = found;
            if (lib.text_vmaddr) {
                lib.slide = 0;
            } else {
                lib.slide = next_base;
                next_base = (next_base + lib.vm_end + 0xFFFFull) & ~0xFFFFull;
            }
            by_name[dep] = images.size();
            if (!lib.install_name.empty() && lib.install_name != dep)
                by_name[lib.install_name] = images.size();
            images.push_back(std::move(lib));
        }
    }

    // by_name may hold SIZE_MAX for a library that was named but not found; drop
    // those before anything indexes with it.
    for (auto it = by_name.begin(); it != by_name.end();)
        if (it->second == SIZE_MAX) it = by_name.erase(it); else ++it;

    for (const MachoImage& img : images) {
        macho_map(img, mem);
        const uint64_t end = img.slide + img.vm_end;
        if (end > high) high = end;
    }

    // Now the binds. An ordinal is a 1-based index into *this* image's LC_LOAD_DYLIB
    // list, not a global one, so resolution is per-image.
    for (const MachoImage& img : images) {
        auto resolve = [&](unsigned ordinal, const std::string& sym, bool weak) -> uint64_t {
            std::vector<const MachoImage*> search;
            if (ordinal >= 1 && ordinal <= img.dylibs.size()) {
                auto it = by_name.find(img.dylibs[ordinal - 1]);
                if (it != by_name.end()) search.push_back(&images[it->second]);
            } else {
                // 0xFE is a flat lookup and 0xFD the main executable; searching
                // everything covers both without pretending to model two-level
                // namespaces.
                for (const MachoImage& o : images) search.push_back(&o);
            }
            for (const MachoImage* o : search) {
                const uint64_t a = macho_lookup_export(*o, sym);
                // The trie stores an offset from the **mach_header**, not a virtual
                // address. For an ordinary dylib, which prefers address 0, the two
                // are the same number and the distinction is invisible. A library
                // extracted from a shared cache carries its cache address --
                // libsystem_c's __TEXT is at 0x1_8016C000 -- and there `slide + a`
                // resolves every symbol to somewhere in the first megabyte.
                if (a) return o->load_addr() + a;
            }
            // A weak import that is missing is *defined* to be null and the guest
            // checks for it, so that is not worth mentioning. A strong one that is
            // missing means the guest will branch to zero at some point, and which
            // symbol it was is the single most useful thing to know -- it says
            // exactly which library still has to be extracted.
            if (!weak) {
                const std::string lib = (ordinal >= 1 && ordinal <= img.dylibs.size())
                                            ? img.dylibs[ordinal - 1] : std::string("(flat)");
                unresolved.push_back(sym + "  from " + lib);
            }
            return 0;
        };
        if (!macho_apply_fixups(img, mem, resolve, err)) {
            *err = img.guest_path + ": " + *err;
            return false;
        }
    }

    // One report, everything at once. Iterating on which libraries to pull out of a
    // shared cache means running this repeatedly, and a run that names one missing
    // thing per attempt is a run per library.
    if (!missing_libs.empty() || !unresolved.empty()) {
        std::string msg = "the guest is not completely linked:\n";
        if (!missing_libs.empty()) {
            msg += "  " + std::to_string(missing_libs.size()) + " librar" +
                   (missing_libs.size() == 1 ? "y" : "ies") + " not found:\n";
            for (size_t k = 0; k < missing_libs.size() && k < 40; ++k)
                msg += "    " + missing_libs[k] + "\n";
            if (missing_libs.size() > 40) msg += "    ...\n";
        }
        if (!unresolved.empty()) {
            // Deduplicated: one absent library accounts for hundreds of symbols, and
            // the library is the actionable part.
            std::sort(unresolved.begin(), unresolved.end());
            unresolved.erase(std::unique(unresolved.begin(), unresolved.end()),
                             unresolved.end());
            msg += "  " + std::to_string(unresolved.size()) +
                   " unresolved non-weak symbol(s):\n";
            for (size_t k = 0; k < unresolved.size() && k < 40; ++k)
                msg += "    " + unresolved[k] + "\n";
            if (unresolved.size() > 40)
                msg += "    ... and " + std::to_string(unresolved.size() - 40) + " more\n";
        }
        *err = msg;
        return false;
    }

    const MachoImage& m = images[0];
    out->base = 0;
    out->entry = m.has_main ? (m.text_vmaddr + m.entry_off) : m.unixthread_pc;
    out->brk = (high + 0x3FFF) & ~0x3FFFull;
    out->phdr_addr = m.text_vmaddr;
    out->interp.clear();                 // handled: there is nothing left to load
    if (!out->entry) { *err = "Mach-O has no entry point"; return false; }
    return true;
}

}  // namespace a64
