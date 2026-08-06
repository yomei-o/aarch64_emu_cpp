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
#include <memory>
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
    // Has this descriptor been opened or redirected here? Descriptors 0..2 are the
    // console by default and are not in the table; a `dup2` onto one puts it there.
    bool is_open(int fd) const { return open_.count(fd) != 0; }
    // Remove a file. Returns 0 or -errno.
    int64_t unlink(const std::string& path);
    int64_t mkdir(const std::string& path);
    int64_t rename(const std::string& from, const std::string& to);
    // A pipe. Writes the two descriptors into `fds` and returns 0.
    int64_t pipe2(int fds[2]);
    // dup/dup2. `newfd` of -1 means "the lowest free one", which is dup(2).
    int64_t dup(int oldfd, int newfd);
    // Move an entry to a specific descriptor, ownership and all. What a spawn
    // file-action's open wants: `dup` leaves the FILE* owned by the old fd, so
    // dup-then-close closes the file that was just opened.
    int64_t move_fd(int oldfd, int newfd);
    // Everything an `execve` should keep. Descriptors survive it -- that is how a
    // shell redirects -- so this is what a spawned child inherits.
    Files clone_for_exec() const { return *this; }
    int64_t pread(int fd, void* dst, uint64_t len, uint64_t off);
    int64_t pwrite(int fd, const void* src, uint64_t len, uint64_t off);
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
    // One absolute, canonical guest path -- see the note in files.cpp. Public
    // because a syscall layer that composes paths itself (the *at family) has to
    // compose them in the spelling the inode hash will see.
    std::string normalize(const std::string& guest) const;
    // The path a descriptor was opened with, **as the guest spelled it**, or
    // empty.  Two callers need it and both need the guest's spelling rather than
    // the host's: fcntl(F_GETPATH), which is how macOS's realpath(3) works and
    // which hands the answer straight back to the guest, and the *at family, which
    // feeds it back into open() -- where host_path() would otherwise prepend the
    // root a second time and look for guests/macos/guests/macos/...
    std::string fd_path(int fd) const {
        auto it = open_.find(fd);
        return it == open_.end() ? std::string() : it->second.guest_path;
    }
    std::string cwd = "/";

private:
    // A pipe: one buffer, two descriptors. Shared between the two ends and, because
    // descriptors survive `execve`, between a parent and the child it spawned -- which
    // is the whole point of having one.
    //
    // The buffer grows without limit, and that is a decision rather than an oversight.
    // A real pipe blocks the writer at 64 KiB and expects the reader to be running
    // concurrently; nothing here runs two processes at once (see `sys_fork`), so a
    // bounded buffer would be a deadlock rather than back-pressure. The cost is memory
    // for output nobody has read yet.
    struct Pipe {
        std::vector<uint8_t> buf;
        size_t pos = 0;              // how much the reader has taken
        int readers = 0, writers = 0;
        bool empty() const { return pos >= buf.size(); }
    };

    struct Entry {
        std::FILE* fp = nullptr;
        // Non-null for a pipe end; `writable` says which end this descriptor is.
        std::shared_ptr<Pipe> pipe;
        bool writable = false;
        std::string path;            // the host path, for the host's own calls
        std::string guest_path;      // what the guest asked for; see fd_path()
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
