#pragma once
#include <cstdint>
#include <functional>
#include "cpu.h"
#include "memory.h"
#include "files.h"

namespace a64 {

class Syscalls {
public:
    Syscalls(Cpu& cpu, Memory& mem);

    // Where the heap and the mmap arena live. Set by the host after loading, so the
    // break starts just above the image.
    void set_brk(uint64_t addr) { brk_ = brk_start_ = addr; }
    void set_mmap_base(uint64_t addr) { mmap_next_ = addr; }

    Files files;
    // What /proc/self/exe should report; a libc reads it to find its own prefix.
    std::string exe_path;
    bool trace = false;
    std::function<void(int fd, const char* data, uint64_t len)> output;
    std::function<int64_t(char* dst, uint64_t len)> input;
    std::function<int64_t(int fd, void* dst, uint64_t len, uint64_t off)> file_read;
    std::function<void(uint64_t nr)> unknown;

private:
    bool svc(uint32_t imm);
    int64_t sys_write(int fd, uint64_t buf, uint64_t len);
    int64_t sys_read(int fd, uint64_t buf, uint64_t len);
    int64_t sys_writev(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_readv(int fd, uint64_t iov, uint64_t cnt);
    int64_t sys_brk(uint64_t addr);
    std::string guest_str(uint64_t addr) { return mem_.read_cstr(addr); }
    int64_t sys_mmap(uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags, int fd, uint64_t off);
    static uint64_t host_nanos();

    Cpu& cpu_;
    Memory& mem_;
    uint64_t brk_ = 0, brk_start_ = 0;
    uint64_t mmap_next_ = 0x0000'7F00'0000'0000ull;
    uint64_t tid_address_ = 0;
};

}  // namespace a64
