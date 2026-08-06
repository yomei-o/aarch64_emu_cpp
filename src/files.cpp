#include "files.h"
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <system_error>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

namespace a64 {

namespace {
constexpr int64_t kENOENT = -2, kEBADF = -9, kEACCES = -13, kEINVAL = -22, kEISDIR = -21;

// Linux open() flags, which are not the host's. O_WRONLY/O_RDWR are the low two
// bits; the rest have to be matched by value, not by the host's <fcntl.h>.
constexpr int kO_WRONLY = 01, kO_RDWR = 02, kO_CREAT = 0100, kO_TRUNC = 01000,
              kO_APPEND = 02000, kO_DIRECTORY = 0200000;

// Defined further down with fill_stat, which is its other caller.  A directory
// listing and a stat of the same file have to agree about the inode, so both go
// through this.
uint64_t path_ino(const std::string& path);
}  // namespace

// Turn whatever the guest said into one absolute, canonical guest path: relative to
// the cwd if it was relative, with "." dropped and ".." resolved -- and **clamped at
// the guest root**, because `--root` is a chroot and "/.." is "/" inside one.
//
// The lexical resolution is not tidiness. `stat(".")` against `stat("..")` is how
// libc's getcwd(3) recognises that it has reached the root: it walks upward
// comparing (st_dev, st_ino) and stops when the two name the same file. Those
// inodes are hashed from the path here, so without this "guests/macos/." and
// "guests/macos/.." hash differently, the two are never equal, and getcwd walks out
// of the sysroot looking for a root it will never reach.
std::string Files::normalize(const std::string& guest) const {
    std::string p = guest;
    if (p.empty() || p[0] != '/') p = (cwd == "/" ? std::string("/") : cwd + "/") + p;
    std::vector<std::string> parts;
    size_t i = 1;
    while (i <= p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        const std::string c = p.substr(i, j - i);
        if (c == "..") { if (!parts.empty()) parts.pop_back(); }
        else if (!c.empty() && c != ".") parts.push_back(c);
        i = j + 1;
    }
    std::string out;
    for (const std::string& c : parts) { out += '/'; out += c; }
    return out.empty() ? "/" : out;
}

std::string Files::host_path(const std::string& guest) const {
    const std::string p = normalize(guest);
    if (root_.empty()) return p;
    std::string r = root_;
    while (!r.empty() && (r.back() == '/' || r.back() == '\\')) r.pop_back();
    // "/" under a root is the root directory itself, not "root/".
    return p == "/" ? r : r + p;
}

bool Files::is_dir(const std::string& path) const {
    std::error_code ec;
    return std::filesystem::is_directory(host_path(path), ec);
}

int64_t Files::open(const std::string& path, int flags, int mode) {
    (void)mode;
    if (std::getenv("A64EMU_TRACE_OPEN"))
        std::fprintf(stderr, "[open] %s flags=%o\n", path.c_str(), flags);
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
        e.used = true; e.is_directory = true; e.path = hp; e.guest_path = normalize(path);
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
    Entry e;
    e.fp = fp;
    e.path = hp;
    e.guest_path = normalize(path);
    e.used = true;
    open_[fd] = std::move(e);
    return fd;
}

int64_t Files::close(int fd) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.fp) std::fclose(it->second.fp);
    if (it->second.pipe) {
        // Which end is closing matters: a reader that sees no writers left is at end
        // of file, and a reader that sees one is merely waiting. Getting this wrong
        // makes `cat` in a pipeline either stop early or never stop at all.
        if (it->second.writable) --it->second.pipe->writers;
        else --it->second.pipe->readers;
    }
    open_.erase(it);
    return 0;
}

int64_t Files::pipe2(int fds[2]) {
    auto p = std::make_shared<Pipe>();
    p->readers = 1;
    p->writers = 1;
    const int r = next_fd_++, w = next_fd_++;
    Entry re; re.used = true; re.pipe = p; re.writable = false;
    Entry we; we.used = true; we.pipe = p; we.writable = true;
    open_[r] = std::move(re);
    open_[w] = std::move(we);
    fds[0] = r;
    fds[1] = w;
    return 0;
}

int64_t Files::dup(int oldfd, int newfd) {
    auto it = open_.find(oldfd);
    if (it == open_.end()) return kEBADF;
    if (newfd < 0) newfd = next_fd_++;
    else if (newfd != oldfd) close(newfd);          // dup2 silently replaces
    else return newfd;                              // dup2(fd, fd) is a no-op
    Entry e = it->second;
    // A duplicated descriptor is another *reference*, so the end counts go up. The
    // std::FILE* is shared rather than reopened, which means closing either one closes
    // the file -- wrong in general, right for the only thing that duplicates a file
    // descriptor here, which is a child redirecting its own standard streams.
    if (e.pipe) { if (e.writable) ++e.pipe->writers; else ++e.pipe->readers; }
    e.fp = nullptr;                                 // only the original owns it
    e.path = it->second.path;
    open_[newfd] = std::move(e);
    if (newfd >= next_fd_) next_fd_ = newfd + 1;
    return newfd;
}

int64_t Files::move_fd(int oldfd, int newfd) {
    auto it = open_.find(oldfd);
    if (it == open_.end()) return kEBADF;
    if (newfd == oldfd) return newfd;
    close(newfd);                                   // silently replaces, like dup2
    open_[newfd] = std::move(open_[oldfd]);
    open_.erase(oldfd);
    if (newfd >= next_fd_) next_fd_ = newfd + 1;
    return newfd;
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
        // The same inode stat would report, not a sequence number.  getcwd(3)'s
        // fallback walk finds a directory's name by listing its parent and
        // matching inodes, so a listing that invents them cannot be walked.
        const uint64_t ino = path_ino(e.path + "/" + name);
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

// getdirentries64: the same walk, packing Darwin's `struct dirent`.
//
//   ino:8  seekoff:8  reclen:2  namlen:2  type:1  name[]
//
// The name therefore begins at offset **21**, which is not 8-aligned. Rounding that
// up to 24 -- which is what the Linux layout trains the fingers to do -- shifts every
// name three bytes and reads as a corrupted filesystem rather than a struct mistake.
// The record as a whole is padded to 8.
int64_t Files::getdirentries64(int fd, void* buf, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    Entry& e = it->second;
    if (!e.is_directory) return -20;                       // ENOTDIR
    auto* out = static_cast<uint8_t*>(buf);
    uint64_t used = 0;
    while (e.pos < e.entries.size()) {
        const std::string& name = e.entries[e.pos].first;
        const uint64_t reclen = (21 + name.size() + 1 + 7) & ~7ull;
        if (used + reclen > len) break;
        std::memset(out + used, 0, reclen);
        const uint64_t ino = path_ino(e.path + "/" + name), seekoff = e.pos + 1;
        const uint16_t rl = static_cast<uint16_t>(reclen);
        const uint16_t nl = static_cast<uint16_t>(name.size());
        std::memcpy(out + used + 0, &ino, 8);
        std::memcpy(out + used + 8, &seekoff, 8);
        std::memcpy(out + used + 16, &rl, 2);
        std::memcpy(out + used + 18, &nl, 2);
        out[used + 20] = e.entries[e.pos].second ? 4 : 8;  // DT_DIR : DT_REG
        std::memcpy(out + used + 21, name.c_str(), name.size() + 1);
        used += reclen;
        ++e.pos;
    }
    return static_cast<int64_t>(used);
}

int64_t Files::read(int fd, void* dst, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.pipe) {
        Pipe& p = *it->second.pipe;
        const size_t have = p.buf.size() - p.pos;
        if (!have) {
            // No data. With writers still open a real kernel would block; nothing here
            // can run the writer while this call is in progress, so returning 0 -- end
            // of file -- is the honest answer for this design and the caller stops
            // rather than spinning. See the note on Pipe.
            return 0;
        }
        const size_t n = have < len ? have : static_cast<size_t>(len);
        std::memcpy(dst, p.buf.data() + p.pos, n);
        p.pos += n;
        return static_cast<int64_t>(n);
    }
    if (!it->second.fp) return kEBADF;
    return static_cast<int64_t>(std::fread(dst, 1, len, it->second.fp));
}

int64_t Files::write(int fd, const void* src, uint64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.pipe) {
        Pipe& p = *it->second.pipe;
        const auto* b = static_cast<const uint8_t*>(src);
        p.buf.insert(p.buf.end(), b, b + len);
        return static_cast<int64_t>(len);
    }
    if (!it->second.fp) return kEBADF;
    const size_t n = std::fwrite(src, 1, len, it->second.fp);
    // Flushed now, not at fclose -- because for a spawned child's descriptor there
    // *is* no fclose: the Files copies holding the FILE* go away without one (they
    // cannot close it; another copy may live on). A child that wrote its output
    // through stdio buffering that nobody drains looks like a child that wrote
    // nothing. The guest's own libc buffers upstream of this call, so these writes
    // arrive in big chunks and the flush costs little.
    std::fflush(it->second.fp);
    return static_cast<int64_t>(n);
}

int64_t Files::ftruncate(int fd, int64_t len) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.pipe || it->second.is_directory || !it->second.fp) return kEINVAL;
    // Through the FILE* rather than around it: anything already buffered belongs
    // before the new end of file, and on Windows the two layers do not share a
    // position.
    std::fflush(it->second.fp);
#ifdef _WIN32
    if (_chsize_s(_fileno(it->second.fp), len) != 0) return kEINVAL;
#else
    if (::ftruncate(fileno(it->second.fp), static_cast<off_t>(len)) != 0)
        return kEINVAL;
#endif
    return 0;
}

int64_t Files::lseek(int fd, int64_t off, int whence) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    // A pipe cannot seek, and saying so matters twice over: ESPIPE is what a
    // guest's "is this seekable?" probe expects (CPython asks before wrapping a
    // subprocess pipe in a file object), and fseek(nullptr) - a pipe entry has
    // no FILE* - is instant process death under MSVC's CRT, with no message.
    if (it->second.pipe) return -29;                   // ESPIPE
    if (it->second.is_directory || !it->second.fp) return -29;
    if (std::fseek(it->second.fp, static_cast<long>(off),
                   whence == 1 ? SEEK_CUR : whence == 2 ? SEEK_END : SEEK_SET) != 0)
        return kEINVAL;
    return std::ftell(it->second.fp);
}

int64_t Files::pread(int fd, void* dst, uint64_t len, uint64_t off) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.pipe || !it->second.fp) return -29;  // ESPIPE (see lseek)
    const long save = std::ftell(it->second.fp);
    std::fseek(it->second.fp, static_cast<long>(off), SEEK_SET);
    const size_t got = std::fread(dst, 1, len, it->second.fp);
    std::fseek(it->second.fp, save, SEEK_SET);
    return static_cast<int64_t>(got);
}

// The counterpart to pread, and the one a shared file mapping needs: the pages
// are written back at an offset without disturbing wherever the descriptor's own
// cursor happens to be.
int64_t Files::pwrite(int fd, const void* src, uint64_t len, uint64_t off) {
    auto it = open_.find(fd);
    if (it == open_.end()) return kEBADF;
    if (it->second.pipe || !it->second.fp) return -29;  // ESPIPE (see lseek)
    const long save = std::ftell(it->second.fp);
    std::fseek(it->second.fp, static_cast<long>(off), SEEK_SET);
    const size_t put = std::fwrite(src, 1, len, it->second.fp);
    std::fflush(it->second.fp);
    std::fseek(it->second.fp, save, SEEK_SET);
    return static_cast<int64_t>(put);
}

namespace {
// The AArch64 `struct stat` is 128 bytes with a fixed layout; a guest libc reads it
// by offset, so the offsets are what matter, not any host struct.
//
// The inode is an FNV hash of the host path rather than a constant, and this is not
// cosmetic: musl's ld.so decides "is this library already loaded?" by comparing
// st_dev/st_ino. With every file answering (1,1), the first library loaded stood in
// for all of them -- cc1 loaded libisl, then libmpc/libmpfr/libgmp/libz each
// "matched" it and were silently skipped, and relocation failed with
// "__gmpz_get_si: symbol not found" against a libgmp that was sitting right there.
// Normalised first, because the hash *is* the identity: "root/" and "root/."
// name one directory and have to answer one inode.  getcwd(3) is what insists on
// it - the fallback walk compares the cwd's (dev,ino) against the root's to know
// when to stop, and two spellings of the same directory made it walk forever.
// Textual normalisation only: the guest trees are extracted, so no path in them
// is a symlink.
uint64_t path_ino(const std::string& path) {
    std::string p = std::filesystem::path(path).lexically_normal().generic_string();
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : p) { h ^= c; h *= 1099511628211ull; }
    return h ? h : 1;                                  // 0 reads as "no file"
}

void fill_stat(void* buf, uint64_t size, bool dir, const std::string& path) {
    std::memset(buf, 0, 128);
    auto* p = static_cast<uint8_t*>(buf);
    auto put64 = [&](size_t off, uint64_t v) { std::memcpy(p + off, &v, 8); };
    auto put32 = [&](size_t off, uint32_t v) { std::memcpy(p + off, &v, 4); };
    put64(0, 1);                                       // st_dev
    put64(8, path_ino(path));                          // st_ino
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
    fill_stat(statbuf, ec ? 0 : static_cast<uint64_t>(sz), false, it->second.path);
    return 0;
}

int64_t Files::stat_path(const std::string& path, void* statbuf) {
    const std::string hp = host_path(path);
    std::error_code ec;
    if (std::filesystem::is_directory(hp, ec)) { fill_stat(statbuf, 4096, true, hp); return 0; }
    const auto sz = std::filesystem::file_size(hp, ec);
    if (ec) return kENOENT;
    fill_stat(statbuf, static_cast<uint64_t>(sz), false, hp);
    return 0;
}

int64_t Files::unlink(const std::string& path) {
    std::error_code ec;
    const bool gone = std::filesystem::remove(host_path(path), ec);
    if (ec) return kEACCES;
    return gone ? 0 : kENOENT;
}

int64_t Files::mkdir(const std::string& path) {
    const std::string hp = host_path(path);
    std::error_code ec;
    if (std::filesystem::exists(hp, ec)) return -17;   // EEXIST, same number both sides
    return std::filesystem::create_directory(hp, ec) && !ec ? 0 : kEACCES;
}

int64_t Files::rename(const std::string& from, const std::string& to) {
    std::error_code ec;
    // POSIX rename replaces an existing target; std::filesystem::rename does too on
    // POSIX hosts but refuses on Windows, so clear the way first.
    std::filesystem::remove(host_path(to), ec);
    ec.clear();
    std::filesystem::rename(host_path(from), host_path(to), ec);
    return ec ? kENOENT : 0;
}

// symlink(target, linkpath).  `ld` reaches this on the `-lto_library` path through
// std::filesystem::create_symlink, which throws when it fails -- and ld does not
// catch, so a refusal here is not an error the guest reports, it is `abort()`.
//
// Windows will not make a symlink without Developer Mode or elevation, and this
// emulator should not need either.  So: try a real symlink, then a hard link, then
// a copy.  All three leave the *contents* reachable at `linkpath`, which is the
// whole of what a toolchain does with one -- it opens it and reads it.  What a copy
// does not preserve is aliasing (a later write to one is not seen through the other)
// and lstat saying "this is a link".  Nothing in a compile or a link does either,
// and the alternative is not working at all.
int64_t Files::symlink(const std::string& target, const std::string& linkpath) {
    const std::filesystem::path from = host_path(target), to = host_path(linkpath);
    std::error_code ec;
    std::filesystem::create_symlink(from, to, ec);
    if (!ec) return 0;
    ec.clear();
    std::filesystem::create_hard_link(from, to, ec);
    if (!ec) return 0;
    ec.clear();
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
    return ec ? kENOENT : 0;
}

int64_t Files::access(const std::string& path) {
    // A missing file is ENOENT, not EACCES: a guest distinguishes "not there"
    // from "forbidden" - gcc probes its search path with access() and treats
    // the two differently.
    std::error_code ec;
    return std::filesystem::exists(host_path(path), ec) ? 0 : kENOENT;
}

}  // namespace a64
