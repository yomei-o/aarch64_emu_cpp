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
#include "start.h"

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
    // Apple ships clang, ld and much of the toolchain as universal binaries.
    // Thinning here - the one place every image is read, whether it is the
    // program, a dependency or a spawned child - keeps the rest of the loader
    // free of the question.
    a64::macho_thin_fat(v);
    return v;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace a64;

    bool trace_sys = false, stats = false, macho_info = false, strict = false;
    bool dyld_sections = false;
    uint64_t max_insns = 0, sample = 0, watch_lo = 0, watch_hi = 0, pc_watch = 0;
    // --setenv NAME=VALUE, repeatable. It exists for libobjc's OBJC_PRINT_* family:
    // the ObjC runtime will explain its own decisions when asked, which beats
    // reasoning about them from outside. (It parses those through libobjc-env.dylib,
    // which is not in the current extraction -- so today this is set-up, not a tool.)
    std::vector<std::string> extra_env;
    bool list_unresolved = false, list_images = false;
    // The guest sees this directory as "/". Defaulting to the host cwd means a
    // relative path from the guest lands where a user would expect it to.
    std::string root = ".";
    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--trace-sys") trace_sys = true;
        else if (a == "--stats") stats = true;
        else if (a == "--macho-info") macho_info = true;
        // --strict — a guest access to a page nothing mapped stops the run and names the
        // address, instead of reading zero and letting the mistake surface later somewhere
        // else. Off by default: some libc reads speculatively, and refusing to run is worse
        // than being permissive. On, it is the fastest way to find a wild pointer.
        else if (a == "--strict") strict = true;
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
        // --pcwatch ADDR — every time the guest reaches ADDR, print x0..x5 and, for any of
        // them that points at a printable NUL-terminated string, the string. Meant for the
        // entry of a guest function: it answers "what was it asked for", which `--watch`
        // and `--sample` cannot. Use `tools/whichlib.py` backwards -- `--macho-info` prints
        // a symbol's offset from its header, and the header addresses are in `--trace-sys`.
        else if (a == "--pcwatch" && i + 1 < argc) pc_watch = std::strtoull(argv[++i], nullptr, 16);
        // --dyld-sections — answer dyld's section-location API instead of making libobjc
        // walk load commands. See the note in darwin.cpp's slot 111: the answers are right,
        // and they take the guest somewhere it cannot yet finish, so this is off by default.
        else if (a == "--dyld-sections") dyld_sections = true;
        else if (a == "--max" && i + 1 < argc) max_insns = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--sample" && i + 1 < argc) sample = std::strtoull(argv[++i], nullptr, 0);
        else if (a == "--root" && i + 1 < argc) root = argv[++i];
        else if (a == "--setenv" && i + 1 < argc) extra_env.push_back(argv[++i]);
        // --list-unresolved — print every unresolved symbol instead of the first
        // forty. Forty says which library is missing; all of them is what
        // guests/macos/stub_libs.sh needs to generate a stand-in for each one.
        else if (a == "--list-unresolved") list_unresolved = true;
        // --list-images — print every image the loader actually mapped, and stop.
        // The dependency closure is much smaller than an extraction: it is what a
        // shippable guest tree has to contain, and guessing at it by hand means
        // either carrying a hundred megabytes of unused libraries or finding out
        // which one was needed by watching a guest branch into unmapped memory.
        else if (a == "--list-images") list_images = true;
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
    sys.dyld_section_info = dyld_sections;
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
    if (pc_watch) {
        cpu.pc_watch = pc_watch;
        cpu.on_pc_watch = [&cpu, &mem]() {
            std::fprintf(stderr, "[pcwatch] %010llX lr=%010llX",
                         static_cast<unsigned long long>(cpu.pc),
                         static_cast<unsigned long long>(cpu.xr(30)));
            for (unsigned r = 0; r <= 5; ++r) {
                const uint64_t v = cpu.xr(r);
                std::fprintf(stderr, "  x%u=%llX", r, static_cast<unsigned long long>(v));
                // A register that points at a short printable string is almost always the
                // interesting one -- a section name, a path, a symbol. Reading it needs the
                // permissive path: this is a debugging aid and must not itself fault.
                if (v < 0x1000) continue;
                char s[40];
                unsigned n = 0;
                for (; n < sizeof s - 1; ++n) {
                    const uint8_t c = mem.read<uint8_t>(v + n);
                    if (!c) break;
                    if (c < 0x20 || c > 0x7E) { n = 0; break; }
                    s[n] = static_cast<char>(c);
                }
                if (n >= 2) { s[n] = 0; std::fprintf(stderr, "(\"%s\")", s); }
            }
            // The callee-saved half, on a second line. An optimised library keeps the
            // object it is working on in x19..x28 for the whole of a function, so by the
            // time anything interesting happens the answer is usually not in x0..x5 --
            // the XPC pipe that turned out to be null lived in x23, and no amount of
            // looking at argument registers would have said so.
            std::fprintf(stderr, "\n[pcwatch]  ");
            for (unsigned r = 19; r <= 29; ++r)
                std::fprintf(stderr, " x%u=%llX", r,
                             static_cast<unsigned long long>(cpu.xr(r)));
            std::fprintf(stderr, "  sp=%llX\n", static_cast<unsigned long long>(cpu.sp));
        };
    }
    // --strict: report the address and stop. A wild access is not something to hand the
    // guest as a signal — the guest is not what is wrong — so it goes out as a CpuError,
    // which prints the registers and names the PC that made the access.
    if (strict) {
        mem.strict = true;
        mem.on_unmapped = [&cpu](uint64_t addr, bool is_write) {
            char buf[128];
            std::snprintf(buf, sizeof buf, "unmapped %s at %016llX (--strict)",
                          is_write ? "write" : "read",
                          static_cast<unsigned long long>(addr));
            throw CpuError{buf, cpu.pc, 0};
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
            ? macho_link(file, guest_exe, mem, kDylibBase, read_guest, &img, &err,
                         list_unresolved)
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
    guest_env.insert(guest_env.end(), extra_env.begin(), extra_env.end());
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
    if (darwin) darwin_prepare(cpu, mem, sys, img);

    if (list_images) {
        for (const std::string& p : img.image_paths) std::printf("%s\n", p.c_str());
        return 0;
    }

    // Running a child program. `execve` in a vfork child calls this, and what it does
    // is the whole of the compromise described in process.cpp: the child runs here, to
    // completion, in its own Memory and Cpu, and only then does the parent resume.
    //
    // The descriptors are *shared*, not copied, which is what makes a pipe between the
    // two work at all -- the child writes into a buffer the parent still holds.
    //
    // Recursion is expected: gcc's driver execs cc1, and cc1 could exec something else.
    // The depth is capped because a guest that execs itself would otherwise recurse
    // until the host's stack ran out, and a stack overflow says nothing about why.
    static int spawn_depth = 0;
    sys.spawn = [&](const std::string& prog, const std::vector<std::string>& sargv,
                    const std::vector<std::string>& senvp, Files& parent_files) -> int {
        if (spawn_depth >= 8) {
            std::fprintf(stderr, "aarch64emu: refusing to nest more than 8 processes\n");
            return -1;
        }
        std::string host = prog;
        if (!root.empty() && root != "." && !host.empty() && host[0] == '/') host = root + host;
        const std::vector<uint8_t> cfile = read_file(host.c_str());
        if (cfile.empty()) return -1;

        Memory cmem;
        Cpu ccpu(cmem);
        Syscalls csys(ccpu, cmem);
        csys.trace = trace_sys;
        csys.dyld_section_info = dyld_sections;
        csys.files = parent_files;            // descriptors survive exec; that is the point
        csys.files.set_root(root);
        csys.spawn = sys.spawn;               // a child may spawn in turn
        ccpu.on_undefined = [&csys](uint32_t, uint64_t at) { return csys.deliver_signal(4, at); };

        LoadedImage cimg;
        std::string cerr_s;
        const bool cdarwin = is_macho(cfile);
        auto cread = [&](const std::string& gp) {
            std::string hp = gp;
            if (!root.empty() && root != "." && !hp.empty() && hp[0] == '/') hp = root + hp;
            return read_file(hp.c_str());
        };
        bool ok;
        if (cdarwin) {
            MachoImage probe;
            if (!macho_parse(cfile, &probe, &cerr_s)) return -1;
            ok = probe.needs_dyld
                ? macho_link(cfile, prog, cmem, 0x0000'0002'0000'0000ull, cread, &cimg, &cerr_s)
                : load_macho(cfile, cmem, 0, &cimg, &cerr_s);
        } else {
            ok = load_elf(cfile, cmem, kPieBase, &cimg, &cerr_s);
        }
        if (!ok) {
            std::fprintf(stderr, "aarch64emu: cannot run %s: %s\n", prog.c_str(), cerr_s.c_str());
            return -1;
        }
        uint64_t cstart = 0, cinterp = 0;
        if (!cdarwin && !cimg.interp.empty()) {
            const std::vector<uint8_t> ifile = cread(cimg.interp);
            if (ifile.empty()) return -1;
            LoadedImage interp2;
            if (!load_elf(ifile, cmem, kInterpBase, &interp2, &cerr_s)) return -1;
            cinterp = interp2.base;
            cstart = interp2.entry;
        }
        cmem.set(kStackTop - (1u << 20), 0, 1u << 20);
        cmem.map(kStackTop - (1u << 20), 1u << 20);
        ccpu.sp = cdarwin ? build_stack_darwin(cmem, kStackTop, prog, sargv, senvp)
                          : build_stack(cmem, kStackTop, cimg, cinterp, sargv, senvp);
        ccpu.pc = cstart ? cstart : cimg.entry;
        csys.set_brk(cimg.brk);
        csys.set_mmap_base(kMmapBase);
        csys.exe_path = prog;
        if (cdarwin) darwin_prepare(ccpu, cmem, csys, cimg);

        ++spawn_depth;
        int cstatus;
        try {
            cstatus = run_image(ccpu, cmem, csys, cimg, cdarwin, cstart, trace_sys);
        } catch (const CpuError& e) {
            std::fflush(stdout);
            std::fprintf(stderr, "\naarch64emu: in child %s: %s\n", prog.c_str(), e.what.c_str());
            cstatus = 127;
        }
        --spawn_depth;
        // The parent's descriptor table gets the child's back: the child may have
        // written into a pipe, and the buffer lives in the entry.
        parent_files = csys.files;
        return cstatus;
    };

    int rc = 0;
    try {
        rc = run_image(cpu, mem, sys, img, darwin, start_pc, trace_sys);
    } catch (const CpuError& e) {
        std::fflush(stdout);
        std::fprintf(stderr, "\naarch64emu: %s  [%llu instructions]\n", e.what.c_str(),
                     static_cast<unsigned long long>(cpu.insns));
        // The registers, because where a guest stopped is rarely as informative as what it
        // was holding when it did. A branch to zero says nothing on its own; x30 names the
        // caller and x16/x17 hold whatever the PAC-signed indirect branch had just loaded,
        // which is where the zero came from. Printed as one block rather than on request,
        // since by the time the question comes up the run is already over.
        for (int k = 0; k < 32; k += 4) {
            std::fprintf(stderr, "  ");
            for (int j = k; j < k + 4; ++j)
                std::fprintf(stderr, "x%-2d=%016llX ", j,
                             static_cast<unsigned long long>(cpu.xr(j)));
            std::fputc('\n', stderr);
        }
        std::fprintf(stderr, "  sp =%016llX pc =%016llX\n",
                     static_cast<unsigned long long>(cpu.sp),
                     static_cast<unsigned long long>(cpu.pc));
        // The frame chain. AArch64's ABI keeps x29 pointing at { caller's x29,
        // caller's x30 }, so walking it is two loads per frame -- and it is the
        // difference between one command and a dozen. Every wall on the macOS side has
        // been "which library asks for this, and from where", and answering it by
        // watching one stack slot at a time to follow the chain by hand took eight
        // round trips the last time.
        //
        // Permissive reads on purpose: this runs *after* something already went wrong,
        // so a frame pointer that is rubbish must print as rubbish rather than fault
        // again. The walk stops on anything that cannot be a frame.
        std::fprintf(stderr, "  frames (x29 chain):\n");
        uint64_t fp = cpu.xr(29);
        std::fprintf(stderr, "    %012llX  (pc)\n",
                     static_cast<unsigned long long>(cpu.pc));
        std::fprintf(stderr, "    %012llX  (x30)\n",
                     static_cast<unsigned long long>(cpu.xr(30)));
        for (int depth = 0; depth < 24 && fp > 0x1000; ++depth) {
            const uint64_t next = mem.read<uint64_t>(fp);
            const uint64_t ret = mem.read<uint64_t>(fp + 8);
            if (!ret) break;
            std::fprintf(stderr, "    %012llX\n", static_cast<unsigned long long>(ret));
            if (next <= fp) break;              // frames grow upward; anything else is junk
            fp = next;
        }
        std::fprintf(stderr, "  (put these through tools/whichlib.py)\n");
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
