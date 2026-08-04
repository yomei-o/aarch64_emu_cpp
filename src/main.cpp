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

    bool trace_sys = false, stats = false;
    uint64_t max_insns = 0, sample = 0;
    // The guest sees this directory as "/". Defaulting to the host cwd means a
    // relative path from the guest lands where a user would expect it to.
    std::string root = ".";
    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--trace-sys") trace_sys = true;
        else if (a == "--stats") stats = true;
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

    Memory mem;
    Cpu cpu(mem);
    cpu.max_insns = max_insns;
    cpu.sample_every = sample;
    Syscalls sys(cpu, mem);
    sys.trace = trace_sys;

    LoadedImage img;
    std::string err;
    if (!load_elf(file, mem, &img, &err)) {
        std::fprintf(stderr, "aarch64emu: %s\n", err.c_str());
        return 1;
    }
    if (!img.interp.empty()) {
        std::fprintf(stderr,
                     "aarch64emu: %s is dynamically linked (needs %s).\n"
                     "            Only static binaries run today -- see resume.md.\n",
                     argv[i], img.interp.c_str());
        return 1;
    }

    std::vector<std::string> guest_argv, guest_env = {
        "PATH=/usr/bin:/bin", "HOME=/", "LANG=C.UTF-8", "TERM=dumb",
    };
    for (int k = i; k < argc; ++k) guest_argv.push_back(argv[k]);

    // The stack sits just below the canonical Linux top. Nothing enforces the
    // address; it only has to be far from the image and the mmap arena.
    constexpr uint64_t kStackTop = 0x0000'7FFF'FFFF'F000ull;
    mem.set(kStackTop - (1u << 20), 0, 1u << 20);           // touch a MiB so it is there
    cpu.sp = build_stack(mem, kStackTop, img, guest_argv, guest_env);
    cpu.pc = img.entry;
    sys.set_brk(img.brk);
    sys.exe_path = argv[i];
    sys.files.set_root(root);

    int rc = 0;
    try {
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
