#pragma once
#include <cstdint>
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

}  // namespace a64
