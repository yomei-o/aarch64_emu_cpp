#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "memory.h"

namespace a64 {

struct LoadedImage {
    uint64_t entry = 0;
    uint64_t phdr_addr = 0;      // where the program headers ended up in guest memory
    uint64_t phent = 0, phnum = 0;
    uint64_t brk = 0;            // first page above the image: where the heap starts
    std::string interp;          // non-empty for a dynamically linked binary
    uint64_t tls_vaddr = 0, tls_filesz = 0, tls_memsz = 0, tls_align = 0;
};

bool load_elf(const std::vector<uint8_t>& f, Memory& mem, LoadedImage* out, std::string* err);

// Builds the initial stack Linux hands a new process and returns the SP to start
// with: argc, argv[], NULL, envp[], NULL, then the auxiliary vector.
uint64_t build_stack(Memory& mem, uint64_t stack_top, const LoadedImage& img,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& envp);

}  // namespace a64
