#pragma once
#include <cstdint>
#include <functional>
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

// A parsed Mach-O: headers read, nothing mapped yet. The file bytes are kept
// because the LINKEDIT blobs -- the export trie, the fixup chains, the symbol
// table -- are parsed lazily and live in the file, not in guest memory.
struct MachoImage {
    std::vector<uint8_t> file;
    std::string guest_path;
    uint64_t slide = 0;              // chosen by the loader; 0 for a fixed executable
    uint64_t text_vmaddr = 0;        // the image's preferred base
    uint64_t vm_end = 0;             // highest vmaddr+vmsize, unslid
    uint64_t entry_off = 0;          // LC_MAIN, from text_vmaddr
    uint64_t unixthread_pc = 0;      // LC_UNIXTHREAD, absolute
    bool has_main = false;
    bool needs_dyld = false;         // has imports, not merely an LC_LOAD_DYLINKER
    std::string dylinker, install_name;
    std::vector<std::string> dylibs, rpaths;
    struct Seg { std::string name; uint64_t vmaddr, vmsize, fileoff, filesize; };
    std::vector<Seg> segs;
    uint32_t fixups_off = 0, fixups_size = 0;
    uint32_t exports_off = 0, exports_size = 0;
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    // The pre-chained-fixups tables: byte-code programs for rebasing and binding.
    // Only their sizes are kept, because they are not implemented -- but an image
    // that has them must be *refused*, not quietly loaded with its pointers left
    // as written, which looks like a successful load and is not one.
    uint32_t rebase_size = 0, bind_size = 0, lazy_bind_size = 0;

    // Where the mach_header actually landed. Chained rebases in the OFFSET format
    // are measured from here, not from the slide.
    uint64_t load_addr() const { return slide + text_vmaddr; }
};

bool macho_parse(const std::vector<uint8_t>& f, MachoImage* out, std::string* err);
void macho_map(const MachoImage& img, Memory& mem);
uint64_t macho_lookup_export(const MachoImage& img, const std::string& sym);

// Loads a dynamically linked Mach-O and everything it needs, then does dyld's job:
// walks LC_DYLD_CHAINED_FIXUPS and writes the rebased and bound pointers. Apple's
// dyld cannot be shipped, so this stands in for it -- unlike the Linux side, where
// the guest's own ld.so runs.
bool macho_link(const std::vector<uint8_t>& main_file, const std::string& exe_path, Memory& mem,
                uint64_t dylib_base,
                const std::function<std::vector<uint8_t>(const std::string&)>& read_file,
                LoadedImage* out, std::string* err);

}  // namespace a64
