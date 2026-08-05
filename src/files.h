// The guest's view of the filesystem.
//
// Guest descriptors are small integers the guest chooses nothing about, so they are
// allocated here and mapped to host handles. 0/1/2 are the console and never touch
// the host filesystem layer.
//
// Paths are passed through with only separator normalisation: the guest is a Linux
// program and will say "/usr/lib/python3.12/os.py", so a root directory maps that
// onto the host. Without a root, absolute guest paths are used as-is, which is what
// you want when the host *is* Linux.
#pragma once
#include <cstdint>
#include <cstdio>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace a64 {

class Files {
public:
    void set_root(const std::string& r) { root_ = r; }

    // Returns a guest fd, or a negative errno.
    int64_t open(const std::string& path, int flags, int mode);
    int64_t close(int fd);
    int64_t read(int fd, void* dst, uint64_t len);
    int64_t write(int fd, const void* src, uint64_t len);
    int64_t lseek(int fd, int64_t off, int whence);
    int64_t pread(int fd, void* dst, uint64_t len, uint64_t off);
    // Fills a Linux AArch64 `struct stat` (128 bytes). Returns 0 or -errno.
    int64_t fstat(int fd, void* statbuf);
    // Emits linux_dirent64 records into a host buffer; returns bytes written, 0 at
    // end of directory, or -errno.
    int64_t getdents64(int fd, void* buf, uint64_t len);
    // The same walk, in Darwin's record layout. Kept as a second function rather than
    // a flag because the two structures share no field offsets and the name does not
    // start 8-aligned in Darwin's -- a shared body with an `if` would be a worse lie
    // than two short ones.
    int64_t getdirentries64(int fd, void* buf, uint64_t len);
    int64_t stat_path(const std::string& path, void* statbuf);
    int64_t access(const std::string& path);
    bool is_dir(const std::string& path) const;

    std::string host_path(const std::string& guest) const;
    std::string cwd = "/";

private:
    struct Entry {
        std::FILE* fp = nullptr;
        std::string path;
        bool used = false;
        // A directory descriptor holds its listing instead of a file handle. Python's
        // importlib opens every package directory with O_DIRECTORY and reads it with
        // getdents64 to cache what is there before it tries to open any module, so a
        // guest that cannot list a directory cannot import anything.
        bool is_directory = false;
        std::vector<std::pair<std::string, bool>> entries;   // name, is_dir
        size_t pos = 0;
    };
    std::map<int, Entry> open_;
    std::string root_;
    int next_fd_ = 3;
};

}  // namespace a64
