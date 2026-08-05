// A macOS guest that uses the filesystem through Apple's own libc.
//
// `tests/file.c` already covers open/read/write, but it is freestanding: it makes
// the syscalls itself, so it exercises the emulator's syscall table and nothing
// else. This one goes through libsystem_c -- opendir/readdir, stat, fopen/fgets,
// getcwd, realpath -- which is what CPython does when it hunts for its standard
// library, and which reaches several syscalls the freestanding path never touches.
//
// The answer is checkable without a Mac and without the emulator: it counts entries
// in a directory this repository controls and hashes the names, so the host can
// compute the same number from the same tree.
//
// No headers, on purpose: there is no Apple SDK on the machines this is built on.
// The struct layouts below are Darwin's, and the ones that matter are marked.
extern int printf(const char*, ...);
extern void* opendir(const char*);
extern void* readdir(void*);
extern int closedir(void*);
extern char* getcwd(char*, unsigned long);
extern void* fopen(const char*, const char*);
extern char* fgets(char*, int, void*);
extern int fclose(void*);
extern int access(const char*, int);

// struct dirent on Darwin (64-bit inode form): ino:8, seekoff:8, reclen:2,
// namlen:2, type:1, name[1024]. The name therefore starts at offset 21, which is
// *not* 8-aligned -- reading it at a rounded-up offset gives a name shifted by
// three characters, which looks like a corrupted filesystem rather than a struct
// mistake.
#define DIRENT_NAME(d) ((const char*)(d) + 21)

static unsigned long hash(const char* s) {
    unsigned long h = 1469598103934665603UL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211UL; }
    return h;
}

int main(void) {
    char buf[4096];
    if (!getcwd(buf, sizeof buf)) { printf("getcwd failed\n"); return 1; }
    printf("cwd ok: %d\n", buf[0] == '/');

    // The directory the guest itself lives in, which always has at least the
    // libraries under it. Counting and hashing rather than printing names, because
    // the order readdir returns them in is not something to depend on.
    void* d = opendir("/usr/lib/system");
    if (!d) { printf("opendir failed\n"); return 1; }
    unsigned long names = 0;
    int n = 0;
    for (;;) {
        void* e = readdir(d);
        if (!e) break;
        const char* nm = DIRENT_NAME(e);
        if (nm[0] == '.') continue;                  // . and ..
        names ^= hash(nm);
        ++n;
    }
    closedir(d);
    printf("entries %d\n", n);
    printf("names %lx\n", names);

    printf("access libsystem_c %d\n", access("/usr/lib/system/libsystem_c.dylib", 0));
    printf("access nonesuch %d\n", access("/usr/lib/system/nonesuch.dylib", 0));
    printf("access hello %d\n", access("/hello.txt", 0));

    // fopen/fgets: stdio's read path, which is a different set of syscalls from
    // open/read -- it stats the file to size its buffer.
    void* f = fopen("/hello.txt", "r");
    if (f) {
        char line[256];
        if (fgets(line, sizeof line, f)) printf("line %lx\n", hash(line));
        fclose(f);
    } else {
        printf("line none\n");
    }
    return 0;
}
