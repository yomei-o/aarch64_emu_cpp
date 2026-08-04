#include "files.h"
#include <cstring>
#include <filesystem>
#include <system_error>

namespace a64 {

namespace {
constexpr int64_t kENOENT = -2, kEBADF = -9, kEACCES = -13, kEINVAL = -22, kEISDIR = -21;

// Linux open() flags, which are not the host's. O_WRONLY/O_RDWR are the low two
// bits; the rest have to be matched by value, not by the host's <fcntl.h>.
constexpr int kO_WRONLY = 01, kO_RDWR = 02, kO_CREAT = 0100, kO_TRUNC = 01000,
              kO_APPEND = 02000, kO_DIRECTORY = 0200000;
}  // namespace

std::string Files::host_path(const std::string& guest) const {
    std::string p = guest;
    if (!p.empty() && p[0] != '/') {                       // relative to the guest cwd
        p = cwd == "/" ? "/" + p : cwd + "/" + p;
    }
    if (root_.empty()) return p;
    std::string r = root_;
    while (!r.empty() && (r.back() == '/' || r.back() == '\\')) r.pop_back();
    return r + p;
}

bool Files::is_dir(const std::string& path) const {
    std::error_code ec;
    return std::filesystem::is_directory(host_path(path), ec);
}

int64_t Files::open(const std::string& path, int flags, int mode) {
    (void)mode;
    const std::string hp = host_path(path);
    // A directory open has to be refused with the error the guest expects rather
    // than by fopen quietly failing: opendir() asks for O_DIRECTORY and treats an
    // ordinary failure as "no such file".
    std::error_code ec;
    if (std::filesystem::is_directory(hp, ec)) {
        // A directory descriptor: snapshot the listing now and serve it from
        // getdents64. Refusing this is what stopped CPython — importlib opens every
        // package directory with O_DIRECTORY before it tries to open a single
        // module, so "cannot list a directory" reads as "no such module".
        const int fd = next_fd_++;
        Entry e;
        e.used = true; e.is_directory = true; e.path = hp;
        e.entries.emplace_back(".", true);
        e.entries.emplace_back("..", true);
        for (const auto& d : std::filesystem::directory_iterator(hp, ec))
            e.entries.emplace_back(d.path().filename().string(), d.is_directory(ec));
        open_[fd] = std::move(e);
        return fd;
    }
    const char* m = "rb";
    if (flags & kO_APPEND) m = (flags & kO_RDWR) ? "a+b" : "ab";
    else if (flags & kO_TRUNC) m = (flags & kO_RDWR) ? "w+b" : "wb";
    else if ((flags & 3) == kO_WRONLY) m = (flags & kO_CREAT) ? "wb" : "r+b";
    else if ((flags & 3) == kO_RDWR) m = (flags & kO_CREAT) ? "w+b" : "r+b";

    std::FILE* fp = std::fopen(hp.c_str(), m);
    if (!fp && (flags & kO_CREAT)) fp = std::fopen(hp.c_str(), "w+b");
    if (!fp) return kENOENT;
    const int fd = next_fd_++;
    open_[fd] = {fp, hp, true};
    return fd;
}

int64_t Files::close(int fd) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.fp) std::fclose(it->second.fp);
    open_.erase(it);
    return 0;
}

// getdents64: pack linux_dirent64 records until the buffer is full.
//   struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
// Records are 8-byte aligned and the name is NUL-terminated. Returning 0 means end
// of directory, which is how the caller's loop stops.
int64_t Files::getdents64(int fd, void* buf, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    Entry& e = it->second;
    if (!e.is_directory) return -20;                       // ENOTDIR
    auto* out = static_cast<uint8_t*>(buf);
    uint64_t used = 0;
    while (e.pos < e.entries.size()) {
        const std::string& name = e.entries[e.pos].first;
        const uint64_t reclen = (19 + name.size() + 1 + 7) & ~7ull;
        if (used + reclen > len) break;
        std::memset(out + used, 0, reclen);
        const uint64_t ino = e.pos + 1;
        const int64_t off = static_cast<int64_t>(e.pos + 1);
        const uint16_t rl = static_cast<uint16_t>(reclen);
        const uint8_t type = e.entries[e.pos].second ? 4 : 8;   // DT_DIR : DT_REG
        std::memcpy(out + used + 0, &ino, 8);
        std::memcpy(out + used + 8, &off, 8);
        std::memcpy(out + used + 16, &rl, 2);
        out[used + 18] = type;
        std::memcpy(out + used + 19, name.c_str(), name.size() + 1);
        used += reclen;
        ++e.pos;
    }
    return static_cast<int64_t>(used);
}

int64_t Files::read(int fd, void* dst, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    return static_cast<int64_t>(std::fread(dst, 1, len, it->second.fp));
}

int64_t Files::write(int fd, const void* src, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    return static_cast<int64_t>(std::fwrite(src, 1, len, it->second.fp));
}

int64_t Files::lseek(int fd, int64_t off, int whence) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (std::fseek(it->second.fp, static_cast<long>(off),
                   whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : SEEK_SET) != 0)
        return kEINVAL;
    return std::ftell(it->second.fp);
}

int64_t Files::pread(int fd, void* dst, uint64_t len, uint64_t off) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    const long save = std::ftell(it->second.fp);
    std::fseek(it->second.fp, static_cast<long>(off), SEEK_SET);
    const size_t got = std::fread(dst, 1, len, it->second.fp);
    std::fseek(it->second.fp, save, SEEK_SET);
    return static_cast<int64_t>(got);
}

namespace {
// The AArch64 `struct stat` is 128 bytes with a fixed layout; a guest libc reads it
// by offset, so the offsets are what matter, not any host struct.
void fill_stat(void* buf, uint64_t size, bool dir) {
    std::memset(buf, 0, 128);
    auto* p = static_cast<uint8_t*>(buf);
    auto put64 = [&](size_t off, uint64_t v) { std::memcpy(p + off, &v, 8); };
    auto put32 = [&](size_t off, uint32_t v) { std::memcpy(p + off, &v, 4); };
    put64(0, 1);                                       // st_dev
    put64(8, 1);                                       // st_ino
    put32(16, dir ? 0040755u : 0100644u);              // st_mode
    put32(20, 1);                                      // st_nlink
    put32(24, 1000); put32(28, 1000);                  // st_uid, st_gid
    put64(48, size);                                   // st_size
    put32(56, 4096);                                   // st_blksize
    put64(64, (size + 511) / 512);                     // st_blocks
}
}  // namespace

int64_t Files::fstat(int fd, void* statbuf) {
    // The three standard descriptors are not in the table and never will be, but a
    // program still stats them: CPython calls fstat on 0/1/2 while setting up
    // sys.stdin/stdout/stderr, and a zeroed struct reads back as a *directory* --
    // whereupon it refuses to start with "<stdin> is a directory, cannot continue".
    if (fd >= 0 && fd <= 2) {
        std::memset(statbuf, 0, 128);
        auto* p = static_cast<uint8_t*>(statbuf);
        const uint32_t mode = 0020620u;                // S_IFCHR | rw--w----, like a tty
        const uint32_t nlink = 1;
        std::memcpy(p + 16, &mode, 4);
        std::memcpy(p + 20, &nlink, 4);
        const uint32_t blksz = 4096;
        std::memcpy(p + 56, &blksz, 4);
        return 0;
    }
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.is_directory) {
        std::memset(statbuf, 0, 128);
        auto* p = static_cast<uint8_t*>(statbuf);
        const uint32_t mode = 0040755u;
        std::memcpy(p + 16, &mode, 4);
        return 0;
    }
    std::error_code ec;
    const auto sz = std::filesystem::file_size(it->second.path, ec);
    fill_stat(statbuf, ec ? 0 : static_cast<uint64_t>(sz), false);
    return 0;
}

int64_t Files::stat_path(const std::string& path, void* statbuf) {
    const std::string hp = host_path(path);
    std::error_code ec;
    if (std::filesystem::is_directory(hp, ec)) { fill_stat(statbuf, 4096, true); return 0; }
    const auto sz = std::filesystem::file_size(hp, ec);
    if (ec) return kENOENT;
    fill_stat(statbuf, static_cast<uint64_t>(sz), false);
    return 0;
}

int64_t Files::access(const std::string& path) {
    std::error_code ec;
    return std::filesystem::exists(host_path(path), ec) ? 0 : kEACCES;
}

}  // namespace a64
