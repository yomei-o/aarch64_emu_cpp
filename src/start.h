#pragma once
#include "cpu.h"
#include "loader.h"
#include "memory.h"
#include "syscalls.h"

namespace a64 {

// Everything that must be true before a Darwin guest's first instruction: the
// commpage, the main thread's pointer, dyld's API object, the ObjC image list,
// thread-local storage and the bootstrap port. Harmless to skip for an ELF guest,
// which is why the caller decides rather than this.
void darwin_prepare(Cpu& cpu, Memory& mem, Syscalls& sys, const LoadedImage& img);

// Run the loaded image: its initializers in dyld's order, then every image's
// `+load`, then `main`, then the guest's own `exit` -- which is what flushes
// stdio, and without which a program that printed and returned printed nothing.
// Returns the guest's exit code. Throws CpuError, like `Cpu::run`.
int run_image(Cpu& cpu, Memory& mem, Syscalls& sys, const LoadedImage& img,
              bool darwin, uint64_t start_pc, bool trace);

}  // namespace a64
