// aarch64emu — run an AArch64 Linux binary on whatever this host happens to be.
//
//   aarch64emu [options] program [args...]
//     --trace-sys      log every syscall
//     --max N          stop after N instructions (a runaway guard)
//     --stats          print instruction count and mapped pages on exit
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "cpu.h"
#include "loader.h"
#include "memory.h"
#include "syscalls.h"

namespace {

std::vector<uint8_t> read_file(const char* path) {
    std::FILE* fp = std::fopen(path, "rb");
    if (!fp) return {};
    std::fseek(fp, 0, SEEK_END);
    const long n = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    std::vector<uint8_t> v(n > 0 ? static_cast<size_t>(n) : 0);
    if (n > 0 && std::fread(v.data(), 1, static_cast<size_t>(n), fp) != static_cast<size_t>(n)) v.clear();
    std::fclose(fp);
    return v;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace a64;

    bool trace_sys = false, stats = false, macho_info = false;
    uint64_t max_insns = 0, sample = 0, watch_lo = 0, watch_hi = 0;
    // The guest sees this directory as "/". Defaulting to the host cwd means a
    // relative path from the guest lands where a user would expect it to.
    std::string root = ".";
    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--trace-sys") trace_sys = true;
        else if (a == "--stats") stats = true;
        else if (a == "--macho-info") macho_info = true;
        // --watch LO:HI — log every guest access in an address range, with the PC that
        // made it. For questions of the form "the guest read a zero, but from where".
        else if (a == "--watch" && i + 1 < argc) {
            const std::string spec = argv[++i];
            const size_t colon = spec.find(':');
            watch_lo = std::strtoull(spec.c_str(), nullptr, 16);
            watch_hi = colon == std::string::npos
                           ? watch_lo + 0x4000
                           : std::strtoull(spec.c_str() + colon + 1, nullptr, 16);
        }
        else if (a == "--max" && i + 1 < argc) max_insns = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--sample" && i + 1 < argc) sample = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--root" && i + 1 < argc) root = argv[++i];
        else break;
    }
    if (i >= argc) {
        std::fprintf(stderr, "usage: aarch64emu [--trace-sys] [--stats] [--max N] program [args...]\n");
        return 2;
    }

    const std::vector<uint8_t> file = read_file(argv[i]);
    if (file.empty()) { std::fprintf(stderr, "aarch64emu: cannot read %s\n", argv[i]); return 1; }

    // --macho-info: read a Mach-O and say what is in it, optionally looking up
    // symbols. Not a debugging convenience but a way to check the export-trie walker
    // against real Apple libraries: a trie walk that goes wrong usually returns
    // "not found" rather than crashing, which is invisible until a bind produces a
    // null pointer somewhere else entirely.
    if (macho_info) {
        MachoImage img;
        std::string perr;
        if (!macho_parse(file, &img, &perr)) {
            std::fprintf(stderr, "aarch64emu: %s\n", perr.c_str());
            return 1;
        }
        std::printf("%s\n  install name: %s\n  entry: %s\n  needs dyld: %s\n",
                    argv[i], img.install_name.empty() ? "(none)" : img.install_name.c_str(),
                    img.has_main ? "LC_MAIN" : (img.unixthread_pc ? "LC_UNIXTHREAD" : "(none)"),
                    img.needs_dyld ? "yes" : "no");
        for (const MachoImage::Seg& s : img.segs)
            std::printf("  segment %-14s vm %012llX + %-10llu file %llu + %llu\n",
                        s.name.c_str(), static_cast<unsigned long long>(s.vmaddr),
                        static_cast<unsigned long long>(s.vmsize),
                        static_cast<unsigned long long>(s.fileoff),
                        static_cast<unsigned long long>(s.filesize));
        std::printf("  exports trie: %u bytes, symtab: %u symbols, chained fixups: %u bytes\n",
                    img.exports_size, img.nsyms, img.fixups_size);
        for (const std::string& d : img.dylibs) std::printf("  needs %s\n", d.c_str());
        for (int k = i + 1; k < argc; ++k) {
            const MachoExport e = macho_lookup_export(img, argv[k]);
            if (e.found && e.reexport)
                std::printf("  %-40s -> re-exported from %s as %s\n", argv[k],
                            e.ordinal >= 1 && e.ordinal <= img.dylibs.size()
                                ? img.dylibs[e.ordinal - 1].c_str() : "?",
                            e.import_name.empty() ? argv[k] : e.import_name.c_str());
            else if (e.found)
                std::printf("  %-40s -> +%llX from the header\n", argv[k],
                            static_cast<unsigned long long>(e.offset));
            else
                std::printf("  %-40s -> not exported\n", argv[k]);
        }
        return 0;
    }

    Memory mem;
    Cpu cpu(mem);
    cpu.max_insns = max_insns;
    cpu.sample_every = sample;
    Syscalls sys(cpu, mem);
    sys.trace = trace_sys;
    if (watch_hi) {
        mem.watch_lo = watch_lo;
        mem.watch_hi = watch_hi;
        mem.on_watch = [&cpu](uint64_t addr, unsigned size, uint64_t value, bool is_write) {
            std::fprintf(stderr, "[watch] %s %u @ %010llX = %llX   from PC %010llX\n",
                         is_write ? "write" : "read ", size,
                         static_cast<unsigned long long>(addr),
                         static_cast<unsigned long long>(value),
                         static_cast<unsigned long long>(cpu.pc));
        };
    }
    // An instruction we do not implement is delivered to the guest as SIGILL when it
    // has a handler. OpenSSL's CPU probes depend on exactly that.
    cpu.on_undefined = [&sys](uint32_t, uint64_t at) { return sys.deliver_signal(4, at); };

    // Where a PIE and the dynamic loader go. Linux picks addresses like these;
    // nothing depends on the exact values, only that the two do not overlap each
    // other, the mmap arena, or the stack.
    constexpr uint64_t kPieBase = 0x0000'5555'5555'0000ull;
    constexpr uint64_t kInterpBase = 0x0000'7F00'0000'0000ull;
    // The mmap arena must not start where the interpreter lands. It did once, and
    // the first library ld.so mapped landed on top of ld.so itself -- which showed
    // up 90,000 instructions later as the loader executing zeroes, nowhere near the
    // mmap that caused it.
    constexpr uint64_t kMmapBase = 0x0000'7F40'0000'0000ull;

    // Two guest personalities, chosen by what the file actually is. A Mach-O takes
    // the Darwin path from here on: a different loader, a different initial stack,
    // and `svc #0x80` instead of `svc #0` at run time.
    const bool darwin = is_macho(file);

    // argv[0] has to be the path *the guest* would see, not the host path we opened.
    // Python finds its standard library by walking up from argv[0]; hand it a host
    // path and it looks for the library in a directory that does not exist inside
    // the guest, then dies with "Failed to import encodings module". A Mach-O needs
    // it even earlier, to resolve @executable_path in an install name.
    auto to_guest_path = [&root](std::string p) {
        auto fwd = [](std::string t) {
            for (char& c : t) if (c == '\\') c = '/';
            return t;
        };
        std::string r = fwd(root);
        p = fwd(p);
        while (!r.empty() && r.back() == '/') r.pop_back();
        if (!r.empty() && r != "." && p.size() > r.size() && p.compare(0, r.size(), r) == 0)
            return p.substr(r.size());
        if (!p.empty() && p[0] != '/') return "/" + p;
        return p;
    };
    const std::string guest_exe = to_guest_path(argv[i]);

    LoadedImage img;
    std::string err;
    if (darwin) {
        // Apple's dyld cannot be supplied from outside a Mac, so when a Mach-O has
        // imports the emulator does dyld's job itself: load the dependencies, walk
        // the chained fixups, bind the symbols. `dylib_base` is just somewhere the
        // libraries can go that is clear of the program, the arena and the stack.
        constexpr uint64_t kDylibBase = 0x0000'0002'0000'0000ull;
        MachoImage probe;
        if (!macho_parse(file, &probe, &err)) {
            std::fprintf(stderr, "aarch64emu: %s\n", err.c_str());
            return 1;
        }
        auto read_guest = [&](const std::string& gp) {
            std::string hp = gp;
            if (!root.empty() && root != "." && !hp.empty() && hp[0] == '/') hp = root + hp;
            return read_file(hp.c_str());
        };
        const bool ok = probe.needs_dyld
            ? macho_link(file, guest_exe, mem, kDylibBase, read_guest, &img, &err)
            : load_macho(file, mem, 0, &img, &err);
        if (!ok) { std::fprintf(stderr, "aarch64emu: %s\n", err.c_str()); return 1; }
    } else if (!load_elf(file, mem, kPieBase, &img, &err)) {
        std::fprintf(stderr, "aarch64emu: %s\n", err.c_str());
        return 1;
    }

    // A dynamically linked program is loaded exactly the way the kernel does it:
    // map the program, map its interpreter, and start at the *interpreter's* entry
    // with AT_BASE saying where it landed and AT_ENTRY where the program's is. The
    // loader does everything after that — relocations, symbol binding, TLS. Writing
    // our own linker instead would mean reimplementing musl's and getting the TLS
    // model wrong in some new way; running the real one is both less work and more
    // faithful.
    uint64_t start_pc = 0, interp_base = 0;
    if (!darwin && !img.interp.empty()) {
        std::string ipath = img.interp;
        if (!root.empty() && root != "." && !ipath.empty() && ipath[0] == '/') ipath = root + ipath;
        const std::vector<uint8_t> ifile = read_file(ipath.c_str());
        if (ifile.empty()) {
            std::fprintf(stderr,
                         "aarch64emu: %s needs the dynamic loader %s,\n"
                         "            which is not under --root %s\n",
                         argv[i], img.interp.c_str(), root.c_str());
            return 1;
        }
        LoadedImage interp;
        if (!load_elf(ifile, mem, kInterpBase, &interp, &err)) {
            std::fprintf(stderr, "aarch64emu: loading %s: %s\n", img.interp.c_str(), err.c_str());
            return 1;
        }
        interp_base = interp.base;
        start_pc = interp.entry;
    }

    std::vector<std::string> guest_argv, guest_env = {
        "PATH=/usr/bin:/bin", "HOME=/", "LANG=C.UTF-8", "TERM=dumb",
        "PYTHONDONTWRITEBYTECODE=1",
    };
    guest_argv.push_back(guest_exe);
    for (int k = i + 1; k < argc; ++k) guest_argv.push_back(argv[k]);

    // The stack sits just below the canonical Linux top. Nothing enforces the
    // address; it only has to be far from the image and the mmap arena.
    constexpr uint64_t kStackTop = 0x0000'7FFF'FFFF'F000ull;
    mem.set(kStackTop - (1u << 20), 0, 1u << 20);           // touch a MiB so it is there
    cpu.sp = darwin ? build_stack_darwin(mem, kStackTop, guest_exe, guest_argv, guest_env)
                    : build_stack(mem, kStackTop, img, interp_base, guest_argv, guest_env);
    cpu.pc = start_pc ? start_pc : img.entry;
    sys.set_brk(img.brk);
    sys.exe_path = guest_exe;
    sys.files.set_root(root);
    sys.set_mmap_base(kMmapBase);
    if (darwin) {
        sys.setup_commpage();
        sys.setup_dyld_apis(img.dyld_gapis);
    }

    int rc = 0;
    try {
        // Darwin: dyld runs every image's initializers before calling main, and
        // libSystem's are what create malloc's zones, the stdio streams and the
        // pthread machinery. Skipping them gets as far as printf and then branches
        // through a null pointer 57 instructions in, which is where this started.
        //
        // Each is called as init(argc, argv, envp, apple) with X30 pointing at an
        // address the guest never executes, so "it returned" is detectable.
        if (!img.initializers.empty()) {
            constexpr uint64_t kInitReturn = 0x0000'0000'DEAD'1000ull;
            const uint64_t sp0 = cpu.sp;
            const uint64_t argc_g = mem.read<uint64_t>(sp0);
            const uint64_t argv_g = sp0 + 8;
            const uint64_t envp_g = argv_g + (argc_g + 1) * 8;
            uint64_t apple_g = envp_g;
            while (mem.read<uint64_t>(apple_g)) apple_g += 8;
            apple_g += 8;
            for (size_t k = 0; k < img.initializers.size(); ++k) {
                cpu.sp = sp0;
                cpu.pc = img.initializers[k];
                cpu.setx(0, argc_g);
                cpu.setx(1, argv_g);
                cpu.setx(2, envp_g);
                cpu.setx(3, apple_g);
                cpu.setx(30, kInitReturn);
                while (!cpu.halted && cpu.pc != kInitReturn) cpu.step();
                if (cpu.halted) break;
            }
            cpu.sp = sp0;
            cpu.pc = start_pc ? start_pc : img.entry;
        }
        cpu.run();
        rc = cpu.exit_code;
    } catch (const CpuError& e) {
        std::fflush(stdout);
        std::fprintf(stderr, "\naarch64emu: %s  [%llu instructions]\n", e.what.c_str(),
                     static_cast<unsigned long long>(cpu.insns));
        rc = 1;
    }
    std::fflush(stdout);
    if (stats)
        std::fprintf(stderr, "[stats] %llu instructions, %llu pages mapped (%llu KiB)\n",
                     static_cast<unsigned long long>(cpu.insns),
                     static_cast<unsigned long long>(mem.mapped_pages()),
                     static_cast<unsigned long long>(mem.mapped_pages() * Memory::kPageSize / 1024));
    return rc;
}
