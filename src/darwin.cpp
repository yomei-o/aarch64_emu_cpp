// The Darwin (macOS/Apple Silicon) kernel interface.
//
// A second personality alongside the Linux one, not a fork of it: the same `Files`
// layer, the same memory, the same CPU. Three things differ, and all three are
// load-bearing.
//
//  1. **`svc #0x80`, not `svc #0`.** Darwin uses a non-zero immediate, so the two
//     personalities can coexist in one build and be told apart at the trap itself
//     rather than by a mode flag. `svc()` routes on the immediate.
//  2. **The number is in x16, not x8**, and it is BSD numbering — write is 4, exit
//     is 1. Negative numbers are Mach traps, a completely separate table.
//  3. **Errors come back in the carry flag.** Success clears C and returns the
//     value in x0; failure *sets* C and puts a *positive* errno in x0. A Linux-style
//     negative return would be read as a huge successful result — a pointer, a
//     length — so getting this wrong is not a failed call, it is a wrong answer.
//
// The errno numbers themselves are mostly shared with Linux (both descend from
// the same BSD table), so `Files` results pass through with two exceptions, fixed
// up in `bsd_errno`.
#include <ctime>
#include "syscalls.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace a64 {

namespace {

// Darwin errno values that disagree with Linux's. Everything from 1..34 that we
// can actually produce is identical in both tables; these two are not.
int bsd_errno(int64_t linux_errno) {
    const int e = static_cast<int>(-linux_errno);
    if (e == 38) return 78;    // ENOSYS
    if (e == 11) return 35;    // EAGAIN
    return e;
}

constexpr int kBsdENOSYS = 78, kBsdEINVAL = 22, kBsdENOENT = 2;

// Find a section by name in a mach_header that is already in guest memory, by walking its
// load commands the way the guest itself would. Deliberately not by consulting the host's
// parsed copy: this answers a question *about the guest's address space*, and the segments
// there are where they actually landed.
//
// By section name only, ignoring the segment. These names are unique within an image, and
// matching on the segment as well would need the right answer to a question with several
// plausible ones -- `__objc_selrefs` lives in `__DATA` on one OS, `__DATA_CONST` on
// another and `__AUTH_CONST` on a third.
bool guest_find_section(Memory& mem, uint64_t mh, const char* name,
                        uint64_t* addr, uint64_t* size) {
    if (!mh || mem.read<uint32_t>(mh) != 0xFEEDFACFu) return false;   // MH_MAGIC_64
    const uint32_t ncmds = mem.read<uint32_t>(mh + 16);
    uint64_t lc = mh + 32;
    // A cap, because a header that is not one -- or one whose ncmds is garbage -- must not
    // walk the whole address space. No real image has thousands.
    for (uint32_t i = 0; i < ncmds && i < 4096; ++i) {
        const uint32_t cmd = mem.read<uint32_t>(lc);
        const uint32_t cmdsize = mem.read<uint32_t>(lc + 4);
        if (cmdsize < 8) return false;
        if (cmd == 0x19) {                                           // LC_SEGMENT_64
            const uint32_t nsects = mem.read<uint32_t>(lc + 64);
            for (uint32_t s = 0; s < nsects; ++s) {
                const uint64_t sec = lc + 72 + s * 80;
                char sn[17];
                for (unsigned k = 0; k < 16; ++k) sn[k] = static_cast<char>(mem.read<uint8_t>(sec + k));
                sn[16] = 0;                    // the field is not NUL-terminated when full
                if (std::strncmp(sn, name, 16) != 0) continue;
                *addr = mem.read<uint64_t>(sec + 32);
                *size = mem.read<uint64_t>(sec + 40);
                return true;
            }
        }
        lc += cmdsize;
    }
    return false;
}

// Darwin's `struct stat64` is 144 bytes and laid out nothing like Linux's, so the
// Linux buffer `Files` fills is translated rather than copied. Only the fields a
// program actually branches on are carried across: the type bits, the permission
// bits and the size.
void linux_stat_to_darwin(const uint8_t* lin, uint8_t* dar) {
    uint32_t mode;
    int64_t size;
    std::memcpy(&mode, lin + 16, 4);
    std::memcpy(&size, lin + 48, 8);
    std::memset(dar, 0, 144);
    const uint16_t mode16 = static_cast<uint16_t>(mode);
    std::memcpy(dar + 4, &mode16, 2);            // st_mode
    const uint16_t nlink = 1;
    std::memcpy(dar + 6, &nlink, 2);             // st_nlink
    std::memcpy(dar + 96, &size, 8);             // st_size
    const int64_t blocks = (size + 511) / 512;
    std::memcpy(dar + 104, &blocks, 8);          // st_blocks
    const int32_t blksize = 4096;
    std::memcpy(dar + 112, &blksize, 4);         // st_blksize
}

// Darwin's open(2) flags. O_CREAT and above differ from Linux's, so a guest asking
// for O_CREAT|O_TRUNC (0x0600 on Darwin) would be read as something else entirely.
int darwin_oflags_to_linux(int f) {
    int out = f & 3;                             // O_RDONLY/WRONLY/RDWR agree
    if (f & 0x0008) out |= 02000;                // O_APPEND
    if (f & 0x0200) out |= 0100;                 // O_CREAT
    if (f & 0x0400) out |= 01000;                // O_TRUNC
    if (f & 0x0800) out |= 0200;                 // O_EXCL
    if (f & 0x100000) out |= 0200000;            // O_DIRECTORY
    return out;
}

}  // namespace

// The commpage: a read-only page the Darwin kernel maps at a fixed address so that
// userland can read machine properties without a syscall. libsyscall builds
// `vm_page_size` from the page shift found here, and libplatform sizes its
// allocations in pages -- so an all-zero commpage means a page size of one byte, a
// rounded-up allocation of zero bytes, and `BUG IN LIBPLATFORM: Failed to allocate in
// os_alloc_once` from a kernel interface that looked like it was working.
//
// The offsets are xnu's `cpu_capabilities.h`. Filling in only the fields a userland
// libc reads is deliberate: an invented value in an unread field is harmless, but an
// invented value in a read one is a wrong answer that looks like a working guest.
void Syscalls::setup_commpage() {
    // Two base addresses, both filled identically.
    //
    // 0xF_FFFFC000 is _COMM_PAGE64_BASE_ADDRESS (nine hex digits, not eight -- writing
    // 0xFFFFC000 puts the page four bits low, where nothing reads it, and the guest
    // then computes a page size of zero). macOS 13 split the commpage in two, moving
    // the constant fields to a read-only page 32 KiB below, and libsystem_kernel on
    // Sequoia reads its page shift from *there*: a watch on the range showed a byte
    // read at 0xF_FFFF4037, which is KERNEL_PAGE_SHIFT's offset.
    //
    // Which field lives on which page is not something to guess at, so both get the
    // same layout. A duplicated field costs nothing; a missing one is read as zero and
    // turns into a wrong answer several hundred instructions away.
    auto fill = [this](uint64_t base) {
        mem_.set(base, 0, 0x4000);
        const char sig[] = "commpage 64-bit";
        mem_.write_bytes(base + 0x000, sig, sizeof sig);
        mem_.write<uint64_t>(base + 0x010, 0);          // CPU_CAPABILITIES64: claim nothing
        mem_.write<uint16_t>(base + 0x01E, 3);          // VERSION
        mem_.write<uint16_t>(base + 0x020, 0);          // CPU_CAPABILITIES
        mem_.write<uint8_t>(base + 0x022, 1);           // NCPUS
        mem_.write<uint8_t>(base + 0x024, 14);          // USER_PAGE_SHIFT_32: 16 KiB
        mem_.write<uint8_t>(base + 0x025, 14);          // USER_PAGE_SHIFT_64: 16 KiB
        mem_.write<uint8_t>(base + 0x026, 6);           // CACHE_LINESIZE shift (64 bytes)
        mem_.write<uint32_t>(base + 0x028, 1);          // SCHED_GEN
        mem_.write<uint32_t>(base + 0x02C, 0);          // MEMORY_PRESSURE
        mem_.write<uint32_t>(base + 0x030, 100);        // SPIN_COUNT
        mem_.write<uint8_t>(base + 0x034, 1);           // ACTIVE_CPUS
        mem_.write<uint8_t>(base + 0x035, 1);           // PHYSICAL_CPUS
        mem_.write<uint8_t>(base + 0x036, 1);           // LOGICAL_CPUS
        mem_.write<uint8_t>(base + 0x037, 14);          // KERNEL_PAGE_SHIFT: 16 KiB
        mem_.write<uint64_t>(base + 0x038, 8ull << 30); // MEMORY_SIZE: 8 GiB
        mem_.write<uint32_t>(base + 0x040, 0x1B588BB3); // CPUFAMILY: an Apple M-series
        mem_.write<uint32_t>(base + 0x044, 0);          // KDEBUG_ENABLE
        // The timebase, matched to what mach_timebase_info_trap reports: 1/1, so
        // mach_absolute_time is nanoseconds.
        mem_.write<uint32_t>(base + 0x0C0, 1);          // numer
        mem_.write<uint32_t>(base + 0x0C4, 1);          // denom
    };
    fill(0x0000'000F'FFFF'C000ull);
    fill(0x0000'000F'FFFF'4000ull);
}

// The guest-visible path of an image, by mach_header, copied into guest memory the
// first time it is asked for. The host holds the image list as std::strings and the
// dyld APIs hand paths to the guest as `const char*`, so somebody has to put the bytes
// where the guest can read them. Returns 0 for an image that is not in the list, which
// is what a caller asking about an address in host-invented memory should get.
uint64_t Syscalls::image_path_addr(uint64_t header) {
    const auto it = path_addr_.find(header);
    if (it != path_addr_.end()) return it->second;
    if (!path_next_) {
        mem_.map(kPathArena, kPathArenaSize);
        mem_.set(kPathArena, 0, kPathArenaSize);
        path_next_ = kPathArena;
    }
    std::string path;
    for (size_t j = 0; j < objc_image_headers_.size() && j < objc_image_paths_.size(); ++j)
        if (objc_image_headers_[j] == header) { path = objc_image_paths_[j]; break; }
    uint64_t addr = 0;
    if (!path.empty() && path_next_ + path.size() + 1 <= kPathArena + kPathArenaSize) {
        addr = path_next_;
        mem_.write_bytes(addr, path.c_str(), path.size() + 1);
        path_next_ += path.size() + 1;
    }
    path_addr_[header] = addr;
    return addr;
}

// A stand-in for `dyld4::gAPIs`, the object real dyld constructs to answer questions
// about itself.
//
// libdyld.dylib is a thin shim: `_dyld_get_active_platform()` is a C++ virtual call
// through a global whose vtable only dyld ever fills in. Having replaced dyld, this
// emulator has to fill it in too, or the guest loads a null vtable pointer and branches
// to zero -- which is what it did.
//
// So the vtable is synthesised, with every slot pointing at its own three-instruction
// stub: load the slot number, trap, return. `svc #0x81` is a third personality on the
// same instruction that already distinguishes Linux from Darwin, and its handler looks
// the slot up in a table of answers. An unknown slot prints its own index and returns
// zero, which is how the next one gets identified -- the same bargain the MIG routines
// make, and the reason neither needs guessing at in advance.
void Syscalls::setup_dyld_apis(uint64_t gapis_addr) {
    if (!gapis_addr) return;
    // Declare the region first. Nothing maps it -- it is invented by the host, not part of
    // any image -- and with permissive memory the writes below created it as a side effect.
    // Under `--strict` a side effect is exactly what stops the run, and rightly: the host
    // should say where it is putting things.
    mem_.map(kDyldStubBase, 0x10000 + kDyldSlots * 16);
    dyld_vtable_ = kDyldStubBase;
    // The stubs go a clear 64 KiB past the table, so an off-the-end slot reads zero and
    // faults at zero rather than executing whatever happened to follow.
    const uint64_t stubs = kDyldStubBase + 0x10000;
    for (uint32_t k = 0; k < kDyldSlots; ++k) {
        const uint64_t stub = stubs + k * 16;
        mem_.write<uint64_t>(dyld_vtable_ + k * 8, stub);
        // movz w16, #k  /  svc #0x81  /  ret
        mem_.write<uint32_t>(stub + 0, 0x52800010u | ((k & 0xFFFF) << 5));
        mem_.write<uint32_t>(stub + 4, 0xD4001021u);        // svc #0x81
        mem_.write<uint32_t>(stub + 8, 0xD65F03C0u);        // ret
        mem_.write<uint32_t>(stub + 12, 0xD503201Fu);       // nop, to pad the slot
    }
    // `gAPIs` is a *pointer to* the object, not the object. So there are three levels,
    // and the first version collapsed two of them:
    //
    //     gAPIs        -> the object
    //     object[0]    -> the vtable
    //     vtable[slot] -> the method
    //
    // Writing the vtable address into gAPIs made the guest read vtable[0] as the object's
    // vtable pointer, add the method offset to *that*, and land in the stubs -- where it
    // read three instructions as a function pointer and branched to them. The symptom
    // named neither the missing level nor the object.
    const uint64_t object = kDyldStubBase + 0x8000;
    mem_.write<uint64_t>(object, dyld_vtable_);
    // Nothing else about the object is filled in, because nothing that reads a field can
    // be answered without knowing which field it is -- and a field that is read shows up
    // as a read of zero, which `--watch` finds the same way it found this.
    mem_.write<uint64_t>(gapis_addr, object);
}

// Call a guest function from the host, from inside a trap handler, and come back.
//
// Needed because some of what dyld does is *re-entrant*: libobjc registers its callbacks
// and dyld calls one of them before the registration returns. Deferring the call until
// the initializer finishes does not work, because the initializer depends on it having
// happened.
//
// The whole context is saved and restored, so the interrupted instruction can finish
// afterwards as if nothing happened -- the PC has already advanced past the SVC by the
// time a handler runs, and restoring it puts that back. The guest's own stack is used,
// which is right: the frame the call lands on top of is the one dyld would have used.
void Syscalls::call_guest(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    constexpr uint64_t kReturnMagic = 0x0000'0000'DEAD'2000ull;
    const uint64_t insns0 = cpu_.insns;
    const Cpu::Context saved = cpu_.save_context();
    cpu_.pc = fn;
    cpu_.setx(0, a0);
    cpu_.setx(1, a1);
    cpu_.setx(2, a2);
    cpu_.setx(3, a3);
    cpu_.setx(30, kReturnMagic);
    while (!cpu_.halted && cpu_.pc != kReturnMagic) cpu_.step();
    const bool died = cpu_.halted;
    if (trace)
        std::fprintf(stderr, "[call] %012llX ran %llu instruction(s)%s\n",
                     static_cast<unsigned long long>(fn),
                     static_cast<unsigned long long>(cpu_.insns - insns0),
                     died ? " and did not return" : "");
    cpu_.load_context(saved);
    cpu_.halted = died;
}

// Darwin thread-local storage.
//
// A reference to a `_Thread_local` variable does not compile to an address. It
// compiles to a *call*:
//
//     adrp x0, descriptor@page ; add x0, x0, descriptor@pageoff
//     ldr  x1, [x0]            ; the descriptor's first word: a function pointer
//     blr  x1                  ; -> the address of this thread's copy
//
// where the descriptor is `{ thunk, key, offset }` in `__DATA,__thread_vars`. The
// static linker leaves `thunk` for the loader to fill in, and on a Mac dyld fills it
// with its own `tlv_get_addr`. Nobody filled it here, which is why the stock macOS
// CPython aborted 203,172 instructions in, before printing anything, with a message
// from libsystem_c that named the problem exactly:
//
//     thread locals not initialized
//
// The thunk points at two host instructions instead, and the work happens on this
// side: one allocation per (image, thread), made on first use and seeded from the
// image's `__thread_data`/`__thread_bss` template. That is simpler than emulating
// dyld's version, which does the same thing through a pthread key.
void Syscalls::setup_tlv(const std::vector<LoadedImage::TlvImage>& images) {
    if (images.empty()) return;
    tlv_images_ = images;
    mem_.map(kTlvBase, kTlvSize);
    // svc #0x82 / ret. x0 arrives holding the descriptor and leaves holding the
    // address, which is the whole ABI: everything else is caller-saved.
    tlv_thunk_ = kTlvBase;
    mem_.write<uint32_t>(tlv_thunk_ + 0, 0xD4001041u);        // svc #0x82
    mem_.write<uint32_t>(tlv_thunk_ + 4, 0xD65F03C0u);        // ret
    tlv_next_ = kTlvBase + 0x1000;

    for (uint32_t i = 0; i < tlv_images_.size(); ++i) {
        const LoadedImage::TlvImage& t = tlv_images_[i];
        // Each descriptor is three words. `offset` is already right -- the linker
        // wrote it -- so only the thunk and the key are the loader's business, and
        // the key here is just "which image", because that is all it has to select.
        for (uint64_t o = 0; o + 24 <= t.vars_size; o += 24) {
            mem_.write<uint64_t>(t.vars + o + 0, tlv_thunk_);
            mem_.write<uint64_t>(t.vars + o + 8, i);
        }
        if (trace)
            std::fprintf(stderr, "[tlv] image %u: %llu descriptor(s), template %llu "
                                 "bytes (%llu initialised)\n",
                         i, static_cast<unsigned long long>(t.vars_size / 24),
                         static_cast<unsigned long long>(t.tmpl_size),
                         static_cast<unsigned long long>(t.tmpl_init));
    }
}

uint64_t Syscalls::tlv_addr(uint64_t descriptor) {
    const uint32_t key = static_cast<uint32_t>(mem_.read<uint64_t>(descriptor + 8));
    const uint64_t offset = mem_.read<uint64_t>(descriptor + 16);
    if (key >= tlv_images_.size()) return 0;
    const LoadedImage::TlvImage& t = tlv_images_[key];
    const auto id = std::make_pair(key, cur_thread_);
    auto it = tlv_blocks_.find(id);
    if (it == tlv_blocks_.end()) {
        const uint64_t size = (t.tmpl_size + 15) & ~15ull;
        const uint64_t block = tlv_next_;
        tlv_next_ += size ? size : 16;
        // The initialised half is copied and the rest zeroed, which is what makes a
        // second thread's copy start from the declared initial values rather than
        // from whatever the first thread left behind.
        mem_.set(block, 0, t.tmpl_size);
        for (uint64_t k = 0; k < t.tmpl_init; ++k)
            mem_.write<uint8_t>(block + k, mem_.read<uint8_t>(t.tmpl + k));
        it = tlv_blocks_.emplace(id, block).first;
        if (trace)
            std::fprintf(stderr, "[tlv] image %u, thread %zu -> %012llX\n", key,
                         cur_thread_, static_cast<unsigned long long>(block));
    }
    return it->second + offset;
}

// The deferred half of the ObjC registration: every image's `+load` methods, run
// once the libraries are actually up. See `case 107` for why it is not done there.
void Syscalls::run_objc_load_images() {
    if (!objc_load_images_ || cpu_.halted) return;
    constexpr uint64_t kInfoSize = 32;
    if (trace)
        std::fprintf(stderr, "[objc] load_images x%zu at %012llX\n", objc_info_count_,
                     static_cast<unsigned long long>(objc_load_images_));
    for (size_t j = 0; j < objc_info_count_ && !cpu_.halted; ++j)
        call_guest(objc_load_images_, objc_infos_ + j * kInfoSize, 0, 0);
    objc_load_images_ = 0;
}

// The handler for those stubs. `w16` holds the vtable slot index.
int64_t Syscalls::dyld_api_stub(uint32_t slot) {
    switch (slot) {
        // _dyld_get_active_platform. PLATFORM_MACOS is 1; returning 0 would be
        // PLATFORM_UNKNOWN, and libSystem branches on it.
        case 66: return 1;
        // _dyld_get_prog_image_header: the main executable's mach_header. Zero is simply
        // wrong -- it is the one image whose address is never in doubt. (Nothing in this
        // guest calls it; the slot below is what libsystem_c uses instead.)
        case 94: return static_cast<int64_t>(prog_header_);
        // The mach_header of the image *containing an address*, which is how libsystem_c's
        // `_os_log_redirect` finds out whether its caller's image defines a
        // `__DATA,__os_assumes_log` section. `tools/dyld_slots.py` does not name this slot,
        // so it was identified by what it is handed and what happens to the answer: an
        // address inside libxpc or libsystem_trace goes in, and the result goes straight to
        // `getsectiondata(mh, "__DATA", "__os_assumes_log", &size)`. Answering zero made
        // that a `getsectiondata(NULL, …)`, which `--strict` reported as a read of address
        // 0x10 — benign in permissive mode, which is exactly why it needed --strict to see.
        // `_dyld_lookup_section_info`: where a well-known ObjC or Swift section is in an
        // image. dyld precomputes these so libobjc need not walk load commands, and it is
        // the hottest slot in the run -- 186 calls, and the fallback costs 16% of it.
        //
        // Three things had to be measured rather than recalled, and the third is the one
        // that would have gone wrong quietly.
        //
        // 1. **x3 is the `_dyld_section_location_kind`.** A number, and a wrong mapping
        //    returns some *other* section's contents, which looks like nothing at all. It
        //    is measured because **the caller names the kind**: libobjc has a separate
        //    method per section, so x30 through `tools/whichlib.py` reads the name out of a
        //    trace. Seven are pinned down below, each with what proved it, and they
        //    cross-check -- 13 arrives from two unrelated callers, and the Swift one turns
        //    up as a template argument in its own mangled name.
        // 2. **Only three arguments.** x4 and x5 look like out-parameters and are not:
        //    they hold this slot's own stub and vtable-entry addresses, left by the
        //    caller's dispatch (`stubs + 111*16` and `vtable + 111*8`). The caller
        //    clobbered them getting here, so nothing can be passed in them.
        // 3. **So the answer is a 16-byte return in x0:x1** -- the section's address and
        //    its size -- and an address is what x0 must be, because a *zero* x0 is what
        //    made libobjc fall back for the whole of this project's history. An offset
        //    from the header would make zero mean "the header", and there is no section
        //    there.
        case 111: {
            // Off unless asked for -- see the note at the end of this case.
            if (!dyld_section_info) return 0;
            static const struct { unsigned kind; const char* sect; } kKinds[] = {
                { 3, "__swift5_replace"},  // libswiftCore addImageCallback2Sections<…,Li3E,…>
                { 6, "__objc_imageinfo"},  // _map_images_nolock, for every image
                { 7, "__objc_selrefs"},    // header_info::selrefs
                {12, "__objc_classlist"},  // header_info::classlist
                {13, "__objc_nlclslist"},  // header_info::nlclslist, and _load_images+76
                {17, "__objc_nlcatlist"},  // _load_images+104, after the non-lazy classes
                {18, "__objc_protolist"},  // header_info::protocollist
            };
            const uint64_t mh = cpu_.xr(1), kind = cpu_.xr(3);
            const char* want = nullptr;
            for (const auto& k : kKinds)
                if (k.kind == kind) { want = k.sect; break; }
            // An unmeasured kind gets the honest answer, which is also a *correct* one:
            // libobjc walks the image itself when this returns nothing. Guessing at the
            // rest of the enum to save a walk is how a wrong section gets read silently.
            if (!want) {
                if (trace)
                    std::fprintf(stderr, "[mac] section info: kind %llu is not one of the "
                                         "measured ones, falling back\n",
                                 static_cast<unsigned long long>(kind));
                return 0;
            }
            uint64_t addr = 0, size = 0;
            if (!guest_find_section(mem_, mh, want, &addr, &size)) return 0;
            if (trace)
                std::fprintf(stderr, "[mac] section info: %012llX %s -> %012llX + %llu\n",
                             static_cast<unsigned long long>(mh), want,
                             static_cast<unsigned long long>(addr),
                             static_cast<unsigned long long>(size));
            cpu_.setx(1, size);            // x0 is written by the caller from the return
            return static_cast<int64_t>(addr);
            // Why this is behind a flag, since the answers above are demonstrably right:
            // with it on, libobjc stops falling back and starts *using* the shared cache's
            // preoptimized class layout for real -- and gets 86,000 instructions further
            // before branching through a null function pointer (PC 0 at 285,669
            // instructions, where the whole run is 199,279 with the fallback). That is
            // progress into new territory, not a regression in this slot, but it is a run
            // that does not finish, so it cannot be the default. It also uncovered PACGA,
            // which libobjc uses on its method caches and which is now implemented.
            //
            // Next session: run with --dyld-sections and find what the null pointer is.
        }
        case 12: {
            const uint64_t addr = cpu_.xr(1);          // x0 is `this`
            uint64_t hdr = 0;
            for (const LoadedImage::ImageSeg& sg : image_segs_)
                if (addr >= sg.lo && addr < sg.hi) { hdr = sg.header; break; }
            // Not in a library: the main executable, or genuinely nowhere.
            if (!hdr && addr && prog_header_ && addr >= prog_header_) hdr = prog_header_;
            // The answer does not come back in x0 alone: the caller also passes a buffer
            // and reads two things out of it afterwards. libsystem_c's `_os_assumes_log`
            // does `add x1, sp, #0x30` before the call, then hands `[sp, #0x38]` to
            // `_os_get_image_uuid` as a mach_header and `[sp, #0x30]` to `strrchr(…, '/')`
            // -- so x0 is a success flag and the pair at x2 is `{path, header}`. Filling
            // in x0 alone left both words zero; that was the null mach_header, and behind
            // it a null path.
            if (hdr && cpu_.xr(2) && mem_.is_mapped(cpu_.xr(2))) {
                mem_.write<uint64_t>(cpu_.xr(2) + 0, image_path_addr(hdr));
                mem_.write<uint64_t>(cpu_.xr(2) + 8, hdr);
            }
            if (trace)
                std::fprintf(stderr, "[mac] image containing %012llX -> %012llX"
                             " (x2=%llX lr=%llX)\n",
                             static_cast<unsigned long long>(addr),
                             static_cast<unsigned long long>(hdr),
                             static_cast<unsigned long long>(cpu_.xr(2)),
                             static_cast<unsigned long long>(cpu_.xr(30)));
            return static_cast<int64_t>(hdr);
        }
        // _dyld_for_objc_header_opt_ro. On this OS the shared cache's ObjC optimisation
        // header lives inside libobjc itself, in `__TEXT,__objc_opt_ro` -- so unlike the
        // rest of the cache's tables, it is *present* in an extracted library and only
        // needs pointing at. libobjc uses it to interpret the preoptimized class layout,
        // which is what `OBJC_METACLASS_$_NSObject`'s data field is in: its `bits` field
        // decodes to nonsense read as an ordinary pointer, and only four slots in the
        // whole of libobjc's data have the top bit set, so it is not an unpacked pointer.
        // _dyld_for_objc_header_opt_ro. The name means what it says and it took a while to
        // hear: the **header**-opt table, not the `objc_opt_t` header. libobjc binary-searches
        // what it gets back — `map_images_nolock` loads a count and an entry size from the
        // first two words and bisects on a mach_header address — so handing it the opt header
        // made it read version 16 as a count of 16 and flags 6 as an entry size of 6, and
        // search a table that does not exist. `headeropt_ro` is at the opt header's +12
        // offset, holds 2,799 entries of 24 bytes, and entry 0 is libobjc at 0x180078000,
        // which is exactly where the loader put it.
        case 118: {
            if (!objc_opt_ro_) return 0;
            const int32_t off = static_cast<int32_t>(mem_.read<uint32_t>(objc_opt_ro_ + 12));
            const uint64_t hdr = off ? objc_opt_ro_ + static_cast<uint64_t>(static_cast<int64_t>(off)) : 0;
            if (trace)
                std::fprintf(stderr, "[objc] headeropt_ro -> %012llX (count=%u entsize=%u)\n",
                             static_cast<unsigned long long>(hdr),
                             hdr ? mem_.read<uint32_t>(hdr) : 0,
                             hdr ? mem_.read<uint32_t>(hdr + 4) : 0);
            return static_cast<int64_t>(hdr);
        }
        // _dyld_get_objc_selector(const char* name) -> SEL, or 0 if the cache has no such
        // selector. This is how libobjc uniques a selector when it believes it is running
        // against a shared cache — and having told it that (slot 63), the host owes it a
        // real answer: the method lists in these libraries name their selectors as offsets
        // into the cache's own coalesced string pool, so a selector libobjc registers for
        // itself is a *different pointer* for the same name, and a message send comparing
        // the two finds nothing. That is what `unrecognized selector` was.
        //
        // The pool is right there. `objc_opt_t`'s last member,
        // relativeMethodSelectorBaseAddress at offset 40, points into libobjc's `__OBJC_RO`
        // segment at the start of it — 57,221 strings, 1.58 MiB, ending well before selopt.
        // So the map is built by walking the pool rather than by reimplementing Apple's
        // perfect hash over selopt: the addresses the pool contains are, by construction,
        // exactly the ones the method lists mean, and a walk cannot be subtly wrong about
        // the hash function.
        //
        // Note x1: these slots are virtual methods, so x0 is `this`.
        case 84: {
            if (!objc_opt_ro_) return 0;
            if (!sel_pool_built_) {
                sel_pool_built_ = true;                 // once, even if it comes up empty
                const int64_t off = static_cast<int64_t>(mem_.read<uint64_t>(objc_opt_ro_ + 40));
                const uint64_t pool = objc_opt_ro_ + static_cast<uint64_t>(off);
                // Walk it in chunks. The end is a run of NULs: the pool is one string after
                // another, and what follows is a different table entirely.
                constexpr uint64_t kChunk = 64 * 1024, kLimit = 32ull << 20;
                std::vector<uint8_t> buf(kChunk);
                std::string cur;
                uint64_t at = pool, run = 0;
                bool done = false;
                for (uint64_t base = pool; !done && base < pool + kLimit; base += kChunk) {
                    mem_.read_bytes(base, buf.data(), kChunk);
                    for (uint64_t k = 0; k < kChunk; ++k) {
                        const uint8_t c = buf[k];
                        // A selector is printable — an ObjC method name cannot contain a
                        // control character — and the pool's first entry is a UTF-8 marker,
                        // so "printable" has to mean 0x20 and up rather than plain ASCII.
                        // Without that test the walk runs off the end of the pool into the
                        // next table and reports a million "names" instead of 57,221.
                        // ...and it is short. What follows the pool inside `__OBJC_RO` is
                        // more tables, many of which are also printable and NUL-separated,
                        // so a NUL run is not what ends the pool: 62 MB of segment gave a
                        // million "names". A "name" past a thousand characters is not one.
                        if (c && c < 0x20) { done = true; break; }
                        if (cur.size() > 1000) { done = true; break; }   // Swift-mangled names get long
                        if (c) {
                            if (cur.empty()) at = base + k;
                            cur += static_cast<char>(c);
                            run = 0;
                            continue;
                        }
                        if (!cur.empty()) { sel_map_.emplace(cur, at); cur.clear(); run = 1; }
                        else if (++run >= 8) { done = true; break; }
                    }
                }
                if (trace)
                    std::fprintf(stderr, "[objc] selector pool at %012llX: %zu names\n",
                                 static_cast<unsigned long long>(pool), sel_map_.size());
            }
            const std::string name = mem_.read_cstr(cpu_.xr(1));
            const auto it = sel_map_.find(name);
            if (trace)
                std::fprintf(stderr, "[objc] selector \"%s\" -> %012llX\n", name.c_str(),
                             static_cast<unsigned long long>(it == sel_map_.end() ? 0 : it->second));
            return it == sel_map_.end() ? 0 : static_cast<int64_t>(it->second);
        }
        // _dyld_get_shared_cache_range(size_t* length) -> const void* base.
        //
        // Answering zero here said "this process has no shared cache" while slot 118 was
        // handing libobjc the cache's own optimisation table, and the class objects it
        // reads *are* in cache form. That contradiction is the reason this is the first
        // slot to fill: libobjc asks whether an address is in the cache before it will
        // treat the data at that address as preoptimized.
        //
        // The range is measured, not written down. Cache libraries keep the addresses the
        // cache gave them, so the span the loader mapped them into is the span the cache
        // occupied; a different extraction or OS moves it, and hardcoding 0x180000000
        // would be right until it silently was not.
        // The out-pointer is in **x1**, not x0: these slots are virtual methods on dyld's
        // APIs object, so x0 is `this` and the arguments start one register along. Writing
        // the length through x0 overwrites the object's vtable pointer with it, and the
        // next dispatch through that object branches to a length — which lands at PC 0 and
        // says "unimplemented FP/SIMD instruction" 50,000 instructions before the real
        // problem. Slot 107 reads x1 for the same reason.
        case 63: {
            if (!cache_hi_) return 0;                     // no cache libraries: honest zero
            const uint64_t p = cpu_.xr(1);
            if (p) mem_.write<uint64_t>(p, cache_hi_ - cache_lo_);
            if (trace)
                std::fprintf(stderr, "[mac] shared cache range %012llX..%012llX (%llu MiB)\n",
                             static_cast<unsigned long long>(cache_lo_),
                             static_cast<unsigned long long>(cache_hi_),
                             static_cast<unsigned long long>((cache_hi_ - cache_lo_) >> 20));
            return static_cast<int64_t>(cache_lo_);
        }
        // _dyld_for_objc_header_opt_rw. The writable half of the same pair: dyld allocates
        // it and libobjc writes its per-launch state there. A zeroed region is the honest
        // starting state -- dyld's is fresh too -- and it has to be *somewhere*, because
        // returning null makes libobjc conclude there is no optimisation data at all after
        // it has already been told there is.
        case 117: {
            if (!objc_opt_rw_ && objc_opt_ro_) {
                // The *real* table, not an invented one. `objc_opt_t`'s headeropt_rw_offset
                // (at +24) points into libobjc's `__OBJC_RW` segment, which dsc_extract
                // copies out like any other — 0x1EE1B4000 on this OS, holding version 0x0AEF
                // and a count of 8 where a zeroed region holds nothing.
                //
                // Handing over a zeroed 1 MiB was the second half of a half-truth: the host
                // says there is a shared cache, so libobjc reads the cache's *preoptimized*
                // class data — and this is where it lives. `OS_xpc_bundle` has
                // `ro->baseMethods == 0`, because in a cache the class's methods have been
                // merged into its preoptimized `class_rw_t` by the cache builder rather than
                // left in the image; with the table zeroed there is nowhere for `dealloc` to
                // be, which is exactly what `unrecognized selector` said.
                const int32_t off = static_cast<int32_t>(mem_.read<uint32_t>(objc_opt_ro_ + 24));
                if (off) objc_opt_rw_ = objc_opt_ro_ + static_cast<uint64_t>(static_cast<int64_t>(off));
            }
            if (!objc_opt_rw_) {                    // no header at all: a region of our own
                objc_opt_rw_ = kObjcOptRw;
                mem_.set(objc_opt_rw_, 0, kObjcOptRwSize);
            }
            if (trace)
                std::fprintf(stderr, "[objc] headeropt_rw -> %012llX\n",
                             static_cast<unsigned long long>(objc_opt_rw_));
            return static_cast<int64_t>(objc_opt_rw_);
        }
        // _dyld_objc_register_callbacks. libobjc hands dyld the functions it wants called
        // when images are mapped -- `map_images` is what registers every class in every
        // loaded image, so without it the first `objc_msgSend` finds an unknown class:
        //
        //     objc[1000]: Attempt to use unknown class 0x1ee40b2e0.
        //
        // The struct's shape has changed across releases (there are v1, v2 and v3
        // layouts), so it is dumped rather than assumed. x1 still holds the pointer: the
        // stub is three instructions and touches nothing but w16.
        case 107: {
            const uint64_t p = cpu_.xr(1);
            objc_callbacks_ = p;
            // The struct is { version, map_images, load_images, unmap_image,
            // patch_root_of_class } -- version 4 on Sequoia.
            const uint64_t map_images = mem_.read<uint64_t>(p + 8);
            if (!map_images || objc_image_paths_.empty()) return 0;

            // Called *here*, inside the registration, because that is where dyld calls
            // it -- and libobjc depends on that: `_objc_init` goes on to use classes
            // before it returns, so deferring the call until the initializer finishes
            // means the initializer never finishes.
            //
            //     objc[1000]: Attempt to use unknown class 0x1ee40b2e0.
            //
            // A callbacks struct at version 4 means the modern `mapped` shape,
            // (count, infos[]), rather than the older (count, paths[], mach_headers[]).
            // Passing the two-array form makes libobjc read a *path pointer* where a
            // mach_header belongs, fail its magic check, and skip every image -- which
            // looks like success: the call runs, returns, and registers nothing. The
            // giveaway is that no image's `__objc_imageinfo` is ever read.
            //
            //     struct _dyld_objc_notify_mapped_info {
            //         const mach_header* mh; const char* path;
            //         const void* sectionsBase; uint32_t refsOffset, unused;
            //     };   // 32 bytes
            constexpr uint64_t kInfoSize = 32;
            const size_t n = objc_image_paths_.size();
            const uint64_t infos = kObjcArena;
            // Another host-invented region: the info array and the path strings after it.
            mem_.map(kObjcArena, n * kInfoSize + 64 * 1024);
            uint64_t strp = infos + n * kInfoSize;
            for (size_t j = 0; j < n; ++j) {
                const std::string& s = objc_image_paths_[j];
                mem_.write_bytes(strp, s.c_str(), s.size() + 1);
                mem_.write<uint64_t>(infos + j * kInfoSize + 0, objc_image_headers_[j]);
                mem_.write<uint64_t>(infos + j * kInfoSize + 8, strp);
                mem_.write<uint64_t>(infos + j * kInfoSize + 16, 0);   // sectionsBase: unread
                mem_.write<uint64_t>(infos + j * kInfoSize + 24, 0);
                strp += s.size() + 1;
            }
            // The third argument is a **block**, and leaving it zero is fatal further in.
            //
            // dyld hands libobjc a `_dyld_objc_mark_image_mutable` block so libobjc can
            // say "I am about to write to image N's read-only data, make it writable".
            // libobjc calls it the way every block is called -- `invoke(block, index)`,
            // through the pointer at offset 0x10, signed with address diversity:
            //
            //     ldur x0, [x29, #-0xd0]     ; the block, straight from x3
            //     ldr  x8, [x0, #0x10]       ; -> invoke
            //     add  x1, w9, w10           ; -> the image index
            //     blraa x8, x9               ; x9 = &block->invoke, the modifier
            //
            // With x3 zero that reads a function pointer from address 0x10 and branches
            // to it. Nothing here enforces page permissions, so the block only has to
            // *return* -- but it has to exist, and its `invoke` has to point at a real
            // instruction. This one is a bare `ret` in the stub arena.
            const uint64_t block = kObjcBlock, invoke = kObjcBlock + 0x40;
            mem_.map(kObjcBlock, kObjcBlockSize);
            mem_.write<uint64_t>(block + 0, 0);            // isa: never read here
            mem_.write<uint32_t>(block + 8, 1u << 28);     // flags: BLOCK_IS_GLOBAL
            mem_.write<uint32_t>(block + 12, 0);           // reserved
            mem_.write<uint64_t>(block + 16, invoke);
            mem_.write<uint64_t>(block + 24, 0);           // descriptor: never read here
            mem_.write<uint32_t>(invoke, 0xD65F03C0u);     // ret
            if (trace)
                std::fprintf(stderr, "[objc] map_images(%zu) at %012llX\n", n,
                             static_cast<unsigned long long>(map_images));
            call_guest(map_images, n, infos, block);

            // The `init` callback -- each image's `+load` methods -- is **remembered,
            // not called**. That is the difference between the two halves of this
            // registration, and it took a backtrace to see.
            //
            // `map_images` really does have to run here, re-entrantly, because
            // `_objc_init` uses classes before it returns. `load_images` does not, and
            // running it here runs arbitrary `+load` methods while libSystem's own
            // initializer is still part-way through -- which reached, in order:
            //
            //     Foundation +load -> _NSInitializePlatform -> __CFInitialize
            //       -> __CFStringGetUserDefaultEncoding -> getpwuid_r
            //       -> libsystem_info's module search -> notify_register_check
            //       -> bootstrap_look_up3 -> libxpc, whose bootstrap pipe its own
            //          initializer has not created yet -> a null pipe
            //
            // dyld runs `+load` after the libraries are up, and so does this now:
            // main.cpp calls `run_objc_load_images()` once the initializer list is done.
            objc_load_images_ = mem_.read<uint64_t>(p + 16);
            objc_infos_ = infos;
            objc_info_count_ = n;
            return 0;
        }
        default:
            // The return address, because the stub is three instructions and says nothing
            // about which API it stands for. x30 names the caller, and the caller's symbol
            // names the method.
            // x1 and x2, not x0: these are virtual methods, so x0 is `this` and the
            // arguments start one along. Printing them is what identifies a slot whose name
            // `tools/dyld_slots.py` did not find — an unnamed slot handed an address is a
            // different question from one handed nothing.
            std::fprintf(stderr,
                         "[mac] dyld API vtable slot %u (+0x%X) is not implemented, "
                         "returning 0; called from %012llX "
                         "(x1=%llX x2=%llX x3=%llX x4=%llX x5=%llX)\n",
                         slot, slot * 8, static_cast<unsigned long long>(cpu_.xr(30)),
                         static_cast<unsigned long long>(cpu_.xr(1)),
                         static_cast<unsigned long long>(cpu_.xr(2)),
                         static_cast<unsigned long long>(cpu_.xr(3)),
                         static_cast<unsigned long long>(cpu_.xr(4)),
                         static_cast<unsigned long long>(cpu_.xr(5)));
            return 0;
    }
}

// Mach IPC, enough of it to answer the kernel RPCs a libSystem startup makes.
//
// `mach_msg2_trap` passes the message *header* in registers rather than reading it from
// the buffer — that is the point of the "2" — and packs two 32-bit fields into each
// 64-bit argument:
//
//   x2 = msgh_bits        | send_size << 32
//   x3 = msgh_remote_port | msgh_local_port << 32
//   x4 = msgh_voucher     | msgh_id << 32
//   x5 = desc_count       | rcv_name << 32
//   x6 = rcv_size         | priority << 32
//
// With MACH64_SEND_MSG|MACH64_RCV_MSG set it is a synchronous RPC: the reply goes back
// into the same buffer. Everything past the header is MIG — a generated protocol whose
// request and reply layouts are fixed per routine, identified by `msgh_id`, with the
// reply id being the request's plus 100.
//
// Only the routines that actually get called are answered. An unknown `msgh_id` prints
// itself and fails, which is how the next one gets found: the guest's own libraries say
// what they wanted, in their own words, as `BUG IN LIBPTHREAD: host_info() failed` did.
int64_t Syscalls::mach_msg2(uint64_t data, uint64_t options, uint64_t bits_size,
                            uint64_t remote_local, uint64_t voucher_id,
                            uint64_t desc_rcvname, uint64_t rcv_size) {
    constexpr int64_t kKernSuccess = 0, kKernFailure = 5;
    const uint32_t msgh_id = static_cast<uint32_t>(voucher_id >> 32);
    const uint32_t remote = static_cast<uint32_t>(remote_local & 0xFFFFFFFF);
    const uint32_t send_size = static_cast<uint32_t>(bits_size >> 32);
    const uint32_t reply_cap = static_cast<uint32_t>(rcv_size & 0xFFFFFFFF);
    (void)options; (void)desc_rcvname; (void)send_size;

    // A send to the null port is `MACH_SEND_INVALID_DEST`, not a failed routine.
    //
    // This is the difference between "the service said no" and "there is nobody to
    // ask", and libxpc treats them differently. With no launchd here, libxpc's
    // bootstrap pipe ends up holding port 0 and sends its XPC messages there --
    // ordinary XPC traffic, not MIG at all, which is why the routine numbers look
    // absurd (0x4000020F). Reporting them as unimplemented MIG routines was both
    // wrong and noisy; a real kernel answers exactly this, and a caller that gets it
    // knows the destination is gone rather than that its request was malformed.
    constexpr int64_t kMachSendInvalidDest = 0x1000'0003;
    if (remote == 0) return kMachSendInvalidDest;

    // Every MIG reply starts the same way. `size` is the whole reply including this
    // header, which MIG checks, so it is a parameter rather than a constant.
    auto reply_header = [&](uint32_t size) {
        mem_.write<uint32_t>(data + 0, 0);              // msgh_bits: simple, not complex
        mem_.write<uint32_t>(data + 4, size);
        mem_.write<uint32_t>(data + 8, 0);              // msgh_remote_port
        mem_.write<uint32_t>(data + 12, 0);             // msgh_local_port
        mem_.write<uint32_t>(data + 16, 0);             // msgh_voucher_port
        mem_.write<uint32_t>(data + 20, msgh_id + 100); // the reply id, by MIG convention
        // The NDR record is copied from the request rather than invented: it describes
        // the caller's own byte order and it is right there.
        uint8_t ndr[8];
        mem_.read_bytes(data + 24, ndr, 8);
        mem_.write_bytes(data + 24, ndr, 8);
    };

    switch (msgh_id) {
        // host_info(host, flavor, out, &outCnt). libpthread asks for HOST_BASIC_INFO to
        // learn the CPU count before it will start.
        case 200: {
            const uint32_t flavor = mem_.read<uint32_t>(data + 32);
            // Every flavour answers with a run of 32-bit words, so one shape serves all
            // of them: write the words, then the size MIG will check, which is the fixed
            // reply struct minus the unused tail of its 15-word array.
            uint32_t w[15] = {0};
            uint32_t count = 0;
            if (flavor == 1) {                           // HOST_BASIC_INFO
                // host_basic_info_data_t. The last two words are one 64-bit max_mem,
                // which lands 8-aligned because the array starts at data+40.
                count = 12;
                w[0] = 1;                                // max_cpus
                w[1] = 1;                                // avail_cpus
                w[2] = 0x80000000u;                      // memory_size (natural_t: 2 GiB)
                w[3] = 0x0100000Cu;                      // cpu_type: CPU_TYPE_ARM64
                w[4] = 0;                                // cpu_subtype: ARM64_ALL
                w[5] = 0;                                // cpu_threadtype
                w[6] = 1;                                // physical_cpu
                w[7] = 1;                                // physical_cpu_max
                w[8] = 1;                                // logical_cpu
                w[9] = 1;                                // logical_cpu_max
                w[10] = 0x00000000u;                     // max_mem, low half  (8 GiB)
                w[11] = 0x00000002u;                     // max_mem, high half
            } else if (flavor == 5) {                    // HOST_PRIORITY_INFO
                // libpthread reads this to build its priority mapping, so the numbers
                // are xnu's own bands rather than anything invented: a made-up maximum
                // would silently rescale every thread priority the guest computes.
                count = 8;
                w[0] = 80;                               // kernel_priority  (MINPRI_KERNEL)
                w[1] = 80;                               // system_priority
                w[2] = 96;                               // server_priority  (MINPRI_RESERVED)
                w[3] = 31;                               // user_priority    (BASEPRI_DEFAULT)
                w[4] = 0;                                // depress_priority
                w[5] = 0;                                // idle_priority
                w[6] = 0;                                // minimum_priority (MINPRI_USER)
                w[7] = 127;                              // maximum_priority (MAXPRI_RESERVED)
            } else {
                std::fprintf(stderr, "[mac] host_info flavor %u is not implemented\n", flavor);
                return kKernFailure;
            }
            const uint32_t size = 24 + 8 + 4 + 4 + 15 * 4 - (15 - count) * 4;
            if (reply_cap && size > reply_cap) return kKernFailure;
            reply_header(size);
            mem_.write<uint32_t>(data + 32, 0);          // RetCode
            mem_.write<uint32_t>(data + 36, count);
            for (uint32_t k = 0; k < count; ++k) mem_.write<uint32_t>(data + 40 + k * 4, w[k]);
            return kKernSuccess;
        }
        // Routines whose reply carries a *port*. That makes the message "complex": the
        // COMPLEX bit in msgh_bits, a descriptor count, and a 12-byte port descriptor
        // where a simple reply would have had its NDR record.
        //
        //   206  host_get_clock_service(host, id, &port)
        //   3418 semaphore_create(task, &sem, policy, value)
        //
        // Nothing here delivers a message or counts a semaphore, so the port only has to
        // be distinct and non-zero -- and it is handed out from the same counter as every
        // other port, so two of them never compare equal.
        case 206:
        case 3418:
        // task_get_special_port(task, which_port, &special_port) — same reply shape, since
        // what comes back is also a port right. libxpc's initializer asks for
        // TASK_BOOTSTRAP_PORT (4) and aborts without one:
        //
        //     Kernel bug: Could not obtain task bootstrap port.
        //
        // That message never reaches the terminal — the abort is a BRK in
        // `_libxpc_initializer.cold.1` — so it was read out of the library, from the string
        // the ADRP/ADD pair two instructions earlier points at. The guest names its own
        // problem even when it does not get to say so.
        case 3409: {
            const uint32_t size = 24 + 4 + 12;
            if (reply_cap && size > reply_cap) return kKernFailure;
            // A task's special ports are the *same* ports each time it asks, and a client
            // keeps the one it gets in a global and compares it later, so the name has to
            // be remembered rather than handed out fresh. The other two routines here
            // genuinely do create something new every call.
            uint32_t name;
            if (msgh_id == 3409) {
                const uint32_t which = mem_.read<uint32_t>(data + 32);
                uint32_t& slot = special_ports_[which];
                // TASK_BOOTSTRAP_PORT is not invented here: the host has already
                // written it into the guest's `bootstrap_port` global, the way the
                // kernel does at exec, and the two have to be the same number.
                if (!slot) slot = (which == 4) ? kBootstrapPort : next_port_++;
                name = slot;
            } else {
                name = next_port_++;
            }
            mem_.write<uint32_t>(data + 0, 0x80000000u);     // msgh_bits: COMPLEX
            mem_.write<uint32_t>(data + 4, size);
            mem_.write<uint32_t>(data + 8, 0);
            mem_.write<uint32_t>(data + 12, 0);
            mem_.write<uint32_t>(data + 16, 0);
            mem_.write<uint32_t>(data + 20, msgh_id + 100);
            mem_.write<uint32_t>(data + 24, 1);              // msgh_descriptor_count
            mem_.write<uint32_t>(data + 28, name);           // the port's name
            mem_.write<uint32_t>(data + 32, 0);              // pad1
            // pad2:16, disposition:8, type:8 — MOVE_SEND (17), PORT_DESCRIPTOR (0).
            mem_.write<uint32_t>(data + 36, 17u << 16);
            return kKernSuccess;
        }
        // Replies that are only a return code: semaphore_destroy, and the restartable
        // range registration libobjc also reaches through MIG rather than the trap.
        // 3410 is task_set_special_port: libxpc stores the bootstrap port back after
        // adding a send right to it. Only the return code is read, and refusing it
        // sends libxpc down a path that ends in "API Misuse" several thousand
        // instructions later, naming nothing.
        case 8000: case 8001:
        case 3410:
        case 3419: {
            const uint32_t size = 24 + 8 + 4;
            if (reply_cap && size > reply_cap) return kKernFailure;
            reply_header(size);
            mem_.write<uint32_t>(data + 32, 0);              // RetCode
            return kKernSuccess;
        }
        // task_info(task, flavor, out, &outCnt). libxpc's `bootstrap_look_up3` asks for the
        // **audit token** and aborts without one, in `_bootstrap_look_up3.cold.1`, with
        // another message that never reaches the terminal:
        //
        //     Configuration error: failed to fetch our own audit token
        //
        // An `audit_token_t` is eight words identifying who the process is, and the values
        // are the ones the syscall layer already answers with (pid and uid 1000) rather than
        // new inventions — a token that disagrees with `getpid()` would be worse than none.
        // Unknown flavours are refused rather than answered with zeros: a caller told
        // "success, here is nothing" has no way to notice.
        case 3405: {
            const uint32_t flavor = mem_.read<uint32_t>(data + 32);
            constexpr uint32_t kTaskAuditToken = 15;
            if (flavor != kTaskAuditToken) {
                const uint32_t size = 24 + 8 + 4;
                if (reply_cap && size > reply_cap) return kKernFailure;
                reply_header(size);
                mem_.write<uint32_t>(data + 32, 4);          // KERN_INVALID_ARGUMENT
                if (trace)
                    std::fprintf(stderr, "[mac] task_info flavor %u refused (only the audit "
                                         "token is answered)\n", flavor);
                return kKernSuccess;
            }
            //   val[0] auid  [1] euid  [2] egid  [3] ruid  [4] rgid
            //   val[5] pid   [6] asid  [7] pidversion
            const uint32_t tok[8] = { 1000, 1000, 1000, 1000, 1000, 1000, 1, 1 };
            const uint32_t size = 24 + 8 + 4 + 4 + sizeof tok;
            if (reply_cap && size > reply_cap) return kKernFailure;
            reply_header(size);
            mem_.write<uint32_t>(data + 32, 0);              // RetCode
            mem_.write<uint32_t>(data + 36, 8);              // task_info_outCnt
            for (int k = 0; k < 8; ++k) mem_.write<uint32_t>(data + 40 + k * 4, tok[k]);
            return kKernSuccess;
        }
        // _host_page_size(host, &out).
        case 202: {
            const uint32_t size = 24 + 8 + 4 + 4;
            if (reply_cap && size > reply_cap) return kKernFailure;
            reply_header(size);
            mem_.write<uint32_t>(data + 32, 0);          // RetCode
            mem_.write<uint32_t>(data + 36, 16384);      // out_page_size
            return kKernSuccess;
        }
        default:
            std::fprintf(stderr,
                         "[mac] MIG routine %u (to port %X) is not implemented, at PC %016llX\n",
                         msgh_id, remote, static_cast<unsigned long long>(cpu_.pc - 4));
            return kKernFailure;
    }
}

// posix_spawn(pid*, path, adesc, argv, envp) -- Darwin syscall 244.
//
// This is *simpler* than fork+exec in this emulator, not harder, because the
// parent is suspended while a child runs anyway: there is no moment between the
// fork and the exec for a guest to do anything. So there is no saved context, no
// memory journal, no vfork depth. Decode the arguments, run the child to
// completion against a **copied** descriptor table, record the status for wait4,
// write the pid back, done. The child never touches the parent's memory at all --
// `spawn` gives it its own.
//
// The layouts are Apple Libc's (posix_spawn.c), and one of them is deliberately
// *measured* rather than trusted: the file-actions array is `count` fixed-size
// records after an 8-byte header, and the record stride is computed as
// (file_actions_size - 8) / count instead of hard-coding a sizeof. The fields
// read from each record are at the front, so a stride that is merely *bigger*
// than expected (a new union member in some future Libc) still decodes.
int64_t Syscalls::sys_posix_spawn(uint64_t pid_addr, uint64_t path_addr, uint64_t adesc,
                                  uint64_t argv_addr, uint64_t envp_addr) {
    const std::string path = guest_str(path_addr);
    auto read_strv = [&](uint64_t addr) {
        std::vector<std::string> v;
        for (size_t i = 0; addr && i < 4096; ++i) {
            const uint64_t p = mem_.read<uint64_t>(addr + i * 8);
            if (!p) break;
            v.push_back(mem_.read_cstr(p));
        }
        return v;
    };
    std::vector<std::string> argv = read_strv(argv_addr);
    const std::vector<std::string> envp = read_strv(envp_addr);
    if (argv.empty()) argv.push_back(path);
    if (!spawn) {
        std::fprintf(stderr, "[proc] posix_spawn(%s) but this front end cannot spawn\n",
                     path.c_str());
        return -38;                                    // ENOSYS, mapped by bsd_errno
    }

    // The args-desc struct: {attr_size, attrp, file_actions_size, file_actions, ...}.
    uint16_t psa_flags = 0;
    Files child_files = files;                         // the child's, never the parent's
    if (adesc) {
        const uint64_t attr = mem_.read<uint64_t>(adesc + 8);
        if (mem_.read<uint64_t>(adesc + 0) >= 2 && attr)
            psa_flags = mem_.read<uint16_t>(attr);     // short psa_flags, field one
        const uint64_t fa_size = mem_.read<uint64_t>(adesc + 16);
        const uint64_t fa = mem_.read<uint64_t>(adesc + 24);
        const uint32_t count = (fa && fa_size > 8) ? mem_.read<uint32_t>(fa + 4) : 0;
        const uint64_t stride = count ? (fa_size - 8) / count : 0;
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t a = fa + 8 + i * stride;
            const uint32_t type = mem_.read<uint32_t>(a + 0);
            const int fd = static_cast<int>(mem_.read<uint32_t>(a + 4));
            switch (type) {
                case 0: {                              // PSFA_OPEN: oflag, u16 mode, path
                    const int oflag = static_cast<int>(mem_.read<uint32_t>(a + 8));
                    const std::string p = mem_.read_cstr(a + 14);
                    const int64_t nf = child_files.open(p, darwin_oflags_to_linux(oflag),
                                                        0644);
                    if (nf < 0) return nf;
                    child_files.move_fd(static_cast<int>(nf), fd);
                    if (trace)
                        std::fprintf(stderr, "[proc]   spawn open %s -> fd %d\n",
                                     p.c_str(), fd);
                    break;
                }
                case 1: child_files.close(fd); break;  // PSFA_CLOSE
                case 2: {                              // PSFA_DUP2: dst in the union
                    const int dst = static_cast<int>(mem_.read<uint32_t>(a + 8));
                    child_files.dup(fd, dst);
                    if (trace)
                        std::fprintf(stderr, "[proc]   spawn dup2 %d -> %d\n", fd, dst);
                    break;
                }
                case 3: break;                         // PSFA_INHERIT: already will
                case 5: child_files.cwd = mem_.read_cstr(a + 8); break;  // PSFA_CHDIR
                default:
                    std::fprintf(stderr, "[proc] posix_spawn file action %u ignored\n",
                                 type);
                    break;
            }
        }
    }

    if (trace)
        std::fprintf(stderr, "[proc] posix_spawn %s (%zu args, flags %04X)\n",
                     path.c_str(), argv.size(), psa_flags);

    const int st = spawn(path, argv, envp, child_files);

    // POSIX_SPAWN_SETEXEC: "replace me" -- the caller does not continue.
    if (psa_flags & 0x40) {
        cpu_.exit_code = st < 0 ? 127 : st;
        cpu_.halted = true;
        return 0;
    }
    // A program that could not be started is posix_spawn's *return value* -- unlike
    // fork+exec there is a live caller to tell, which is the whole point of the API.
    if (st < 0) return -2;                             // ENOENT
    const int pid = next_pid_++;
    child_status_[pid] = st << 8;
    if (pid_addr) mem_.write<uint32_t>(pid_addr, static_cast<uint32_t>(pid));
    return 0;
}

// Returns false to stop the machine (only for exit).
bool Syscalls::svc_darwin() {
    // The number is a *32-bit* value, sign-extended. Reading the whole of x16 turns a
    // `mov w16, #-3` -- which is how the guest selects Mach trap 3 -- into 4294967293,
    // a positive number that goes down the BSD path and reports an absurd syscall.
    const int64_t nr = static_cast<int32_t>(cpu_.wr(16));
    const uint64_t a0 = cpu_.xr(0), a1 = cpu_.xr(1), a2 = cpu_.xr(2);
    const uint64_t a3 = cpu_.xr(3);

    if (trace) {
        // All six, because a Mach trap's arguments are positional and getting the
        // layout wrong looks exactly like the guest passing nonsense.
        // x30 as well: these trap stubs are three instructions long, so the return
        // address is the only way to see which library asked.
        std::fprintf(stderr, "[mac] %lld(%llX, %llX, %llX, %llX, %llX, %llX)  lr=%llX\n",
                     static_cast<long long>(nr), static_cast<unsigned long long>(a0),
                     static_cast<unsigned long long>(a1), static_cast<unsigned long long>(a2),
                     static_cast<unsigned long long>(a3),
                     static_cast<unsigned long long>(cpu_.xr(4)),
                     static_cast<unsigned long long>(cpu_.xr(5)),
                     static_cast<unsigned long long>(cpu_.xr(30)));
    }

    int64_t r = 0;          // the success value
    int err = 0;            // non-zero means "set carry, return this in x0"

    // A Mach trap, not a BSD syscall: a different table reached through the same
    // instruction, distinguished only by the sign of x16.
    //
    // The return convention differs too. A Mach trap returns a `kern_return_t` in x0
    // and leaves the carry flag alone -- there is no errno and no flag. Reporting
    // failure the BSD way here would make a successful allocation look like an error
    // and vice versa.
    if (nr < 0) {
        const uint64_t a4 = cpu_.xr(4), a5 = cpu_.xr(5);
        constexpr int64_t kKernSuccess = 0, kKernFailure = 5, kKernInvalidArgument = 4;
        // A Mach VM allocation, from the same arena BSD mmap uses. Honours the
        // alignment mask and VM_FLAGS_ANYWHERE, and writes the address back through
        // the pointer the caller passed -- which is the part that matters: libmalloc
        // reads its zone address from there and does not check it against anything.
        auto vm_alloc = [&](uint64_t addr_ptr, uint64_t size, uint64_t mask,
                            uint64_t flags) -> int64_t {
            if (!size) return kKernInvalidArgument;
            const bool anywhere = (flags & 1) != 0;        // VM_FLAGS_ANYWHERE
            if (!anywhere) {
                // A fixed request: the address is already what the caller wants, and
                // memory here is allocated on touch, so honouring it is just zeroing.
                const uint64_t want = mem_.read<uint64_t>(addr_ptr);
                mem_.set(want, 0, size);
                return kKernSuccess;
            }
            const int64_t got = sys_mmap(0, size + mask, 0, 0x20 /*MAP_ANON*/, -1, 0);
            if (got < 0) return kKernFailure;
            const uint64_t aligned = (static_cast<uint64_t>(got) + mask) & ~mask;
            mem_.set(aligned, 0, size);
            mem_.write<uint64_t>(addr_ptr, aligned);
            return kKernSuccess;
        };

        switch (-nr) {
            // task_restartable_ranges_register / _synchronize. libobjc marks the ranges
            // of its method-cache lookup so the kernel can rewind a thread preempted
            // inside one, and says so out loud when it fails:
            //
            //     objc[1000]: task_restartable_ranges_register failed
            //
            // Succeeding is honest for the kernel's part -- nothing here preempts the
            // guest from outside. It is *not* honest once this emulator's own scheduler
            // preempts a guest thread mid-range, which it will: that thread would need
            // its PC rewound to the range's recovery point, and it will not be.
            case 3: case 4: r = kKernSuccess; break;
            // ---- Mach VM. libmalloc builds its zones through these, so a guest that
            // reaches malloc reaches here.
            case 10: r = vm_alloc(a1, a2, 0, a3); break;   // mach_vm_allocate_trap
            case 15: r = vm_alloc(a1, a2, a3, a4); break;  // mach_vm_map_trap
            case 12: r = kKernSuccess; break;              // mach_vm_deallocate: arena only grows
            case 14: r = kKernSuccess; break;              // mach_vm_protect: nothing modelled
            case 11: r = kKernSuccess; break;              // mach_vm_purgable_control
            // ---- Mach ports. Nothing here delivers messages, so a port is a number
            // that has to be non-zero and distinct; the guest stores it and compares
            // it, and only fails if it is zero.
            case 16: mem_.write<uint32_t>(a2, next_port_++); r = kKernSuccess; break;
            case 24: mem_.write<uint32_t>(a3, next_port_++); r = kKernSuccess; break;
            case 18: case 19: case 21: case 22: r = kKernSuccess; break;
            case 26: r = next_port_++; break;              // mach_reply_port
            case 27: r = 0x103; break;                     // thread_self_trap
            case 28: r = 0x107; break;                     // task_self_trap
            case 29: r = 0x10B; break;                     // host_self_trap
            case 47: r = mach_msg2(a0, a1, a2, a3, a4, a5, cpu_.xr(6)); break;   // mach_msg2
            case 61: case 62: r = kKernSuccess; break;     // swtch_pri, thread_switch
            // host_create_mach_voucher_trap(host, recipes, size, &voucher).
            //
            // libdispatch makes one for the task while it starts up, and treats a
            // failure as fatal rather than as "no vouchers here":
            //
            //     _voucher_task_mach_voucher_init: Could not create task mach voucher
            //
            // A voucher carries QoS and activity attributes between threads and
            // processes. Nothing here schedules, so the attributes have no effect and
            // the voucher only has to be a distinct non-zero port -- which is the same
            // bargain every other port in this file makes.
            case 70: mem_.write<uint32_t>(a3, next_port_++); r = kKernSuccess; break;
            // mach_voucher_extract_attr_recipe_trap: what is *in* a voucher. libxpc
            // asks so it can copy the caller's attributes into a message. Answering
            // "the recipe is empty" is true here -- nothing ever put anything in one.
            case 72: if (a4) mem_.write<uint32_t>(a4, 0); r = kKernSuccess; break;
            // thread_get_special_reply_port(). No arguments; the port comes back in
            // x0. libxpc needs one per thread to receive an XPC reply on.
            //
            // This was guessed at as `mach_generate_activity_id` first, which takes
            // an out-parameter -- so the handler wrote a fresh id through whatever
            // happened to be in x2, which was the thread port 0x103, and `--strict`
            // reported an unmapped write to address 0x103. A trap number is worth
            // reading out of the library rather than recalling: `mov x16, #-0x32`
            // sits two instructions above the symbol.
            case 50: {
                uint32_t& slot = special_reply_ports_[cur_thread_];
                if (!slot) slot = next_port_++;
                r = slot;
                break;
            }
            case 89: {                                     // mach_timebase_info_trap
                // numer/denom of 1/1 makes mach_absolute_time() nanoseconds, which
                // is what the host clock already hands back.
                mem_.write<uint32_t>(a0, 1);
                mem_.write<uint32_t>(a0 + 4, 1);
                r = kKernSuccess;
                break;
            }
            default:
                std::fprintf(stderr, "[mac] unimplemented Mach trap %lld at PC %016llX\n",
                             static_cast<long long>(nr),
                             static_cast<unsigned long long>(cpu_.pc - 4));
                r = kKernFailure;
                break;
        }
        cpu_.setx(0, static_cast<uint64_t>(r));
        cpu_.c = false;
        return true;
    }

    switch (nr) {
        case 1:                                            // exit
            // A vfork child exiting before it execs -- the `_exit(127)` after a failed
            // exec. The parent has to come back rather than the whole run ending.
            if (in_vfork_child()) {
                vfork_child_status_ = static_cast<int>(a0 & 0xFF) << 8;
                vfork_returning_ = true;
                cpu_.stop_requested = true;
                return true;
            }
            cpu_.exit_code = static_cast<int>(a0 & 0xFF);
            cpu_.halted = true;
            return true;
        case 3: case 396: r = sys_read(static_cast<int>(a0), a1, a2); break;   // read[_nocancel]
        case 4: case 397: r = sys_write(static_cast<int>(a0), a1, a2); break;  // write[_nocancel]
        case 120: r = sys_readv(static_cast<int>(a0), a1, a2); break;
        case 121: r = sys_writev(static_cast<int>(a0), a1, a2); break;
        case 5: case 398:                                  // open[_nocancel]
            r = files.open(guest_str(a0), darwin_oflags_to_linux(static_cast<int>(a1)),
                           static_cast<int>(a2));
            break;
        case 6: case 399: r = files.close(static_cast<int>(a0)); break;
        case 199: r = files.lseek(static_cast<int>(a0), static_cast<int64_t>(a1),
                                  static_cast<int>(a2)); break;
        case 33: r = files.access(guest_str(a0)); break;
        case 136: r = files.mkdir(guest_str(a0)); break;
        case 137: case 10: r = files.unlink(guest_str(a0)); break;   // rmdir, unlink
        case 128: r = files.rename(guest_str(a0), guest_str(a1)); break;
        // ---- child processes. The numbers are read out of libsystem_kernel, one
        // `movz x16, #N` per stub, for the same reason the psynch ones are: a wrong
        // number is a syscall that quietly fails.
        //
        //   2  fork      41 dup       42 pipe      90 dup2
        //   7  wait4     59 execve   230 poll
        //
        // `fork` is the odd one: Darwin returns the pid in x0 *and* a flag in x1 --
        // 1 in the child, 0 in the parent -- because the child and parent otherwise
        // cannot be told apart when the pid is 0. libsyscall's wrapper reads x1.
        // fork. Darwin returns the pid in x0 *and* a flag in x1 -- 1 in the child,
        // 0 in the parent -- because with a pid of 0 the two are otherwise
        // indistinguishable, and libsyscall's wrapper reads x1.
        //
        // This was refused for a while, and what made it possible is the memory
        // journal in Memory::begin_journal(). Darwin's `fork()` wrapper is not the
        // bare `clone` musl's is: it runs `_libSystem_atfork_child()`, which
        // reinitialises malloc's zones, libdispatch's queues and libnotify's state.
        // With the parent's address space merely *shared*, that reinitialised the
        // parent's heap and the parent limped on to die half a billion instructions
        // later. With every page the child writes recorded and put back, it does not.
        case 2:
            r = sys_fork();
            cpu_.setx(1, 1);                 // this return is the child's
            break;
        case 42: {                                         // pipe: fds come back in
            int fds[2];                                    // x0 and x1, not a buffer
            const int64_t rc = files.pipe2(fds);
            if (rc < 0) { err = bsd_errno(rc); r = 0; break; }
            cpu_.setx(1, static_cast<uint64_t>(fds[1]));
            r = fds[0];
            break;
        }
        case 41: r = files.dup(static_cast<int>(a0), -1); break;
        case 90: r = files.dup(static_cast<int>(a0), static_cast<int>(a1)); break;
        // posix_spawn(pid*, path, adesc, argv, envp): the path a guest that avoids
        // fork takes -- Apple's clang driver runs ld through it.
        case 244: {
            const int64_t rc = sys_posix_spawn(a0, a1, a2, a3, cpu_.xr(4));
            if (cpu_.halted) return true;              // POSIX_SPAWN_SETEXEC
            if (rc < 0) { err = bsd_errno(rc); r = 0; break; }
            r = rc;
            break;
        }
        // execve is **59**, the classic BSD number. 147 is `setsid`, and the scan
        // that produced 147 for execve had over-run into the next stub: `_execve`
        // begins with a branch through an interposable slot rather than with
        // `movz x16`. What the guest actually issues is the number to trust.
        case 59: r = sys_execve(a0, a1, a2); return true;
        case 147: r = 1000; break;                         // setsid: one session here
        case 362: r = 0; break;                            // kqueue: no events, ever
        case 7: r = sys_wait4(static_cast<int64_t>(a0), a1); break;
        // poll(fds, n, timeout). Same answer as the Linux ppoll and for the same
        // reason: nothing here runs two processes at once, so by the time a parent
        // polls, the child has finished and everything it wrote is in the buffer.
        case 230: {
            int64_t ready = 0;
            for (uint64_t i = 0; i < a1 && i < 64; ++i) {
                const uint64_t e = a0 + i * 8;
                mem_.write<uint16_t>(e + 6, mem_.read<uint16_t>(e + 4));
                ++ready;
            }
            r = ready;
            break;
        }
        // readlink(path, buf, size). Nothing in this filesystem is a symbolic link --
        // the guest trees are extracted, not mounted -- so EINVAL ("not a link") is
        // the truthful answer for a path that exists, and ENOENT for one that does
        // not. Returning ENOSYS instead made CPython's `os.path.realpath` give up on
        // resolving its own executable.
        case 58: {
            uint8_t lin[128];
            r = files.stat_path(guest_str(a0), lin);
            err = (r == 0) ? kBsdEINVAL : kBsdENOENT;
            r = 0;
            break;
        }
        case 339: case 189: {                              // fstat64, fstat
            uint8_t lin[128], dar[144];
            r = files.fstat(static_cast<int>(a0), lin);
            if (r == 0) { linux_stat_to_darwin(lin, dar); mem_.write_bytes(a1, dar, sizeof dar); }
            break;
        }
        case 338: case 188: case 340: {                    // stat64, stat, lstat64
            uint8_t lin[128], dar[144];
            r = files.stat_path(guest_str(a0), lin);
            if (r == 0) { linux_stat_to_darwin(lin, dar); mem_.write_bytes(a1, dar, sizeof dar); }
            break;
        }
        // getdirentries64(fd, buf, bufsize, &position). Darwin's readdir. The fourth
        // argument is an in/out file position the caller keeps across calls; the
        // directory's own cursor lives in `Files`, so it only has to be written back
        // -- but it does have to be, because libc compares it to detect a rewind.
        case 344: {
            std::vector<uint8_t> tmp(a2 > (1u << 20) ? (1u << 20) : a2);
            r = files.getdirentries64(static_cast<int>(a0), tmp.data(), tmp.size());
            if (r < 0) { err = bsd_errno(r); r = 0; break; }
            if (r > 0) mem_.write_bytes(a1, tmp.data(), static_cast<size_t>(r));
            if (a3) mem_.write<uint64_t>(a3, mem_.read<uint64_t>(a3) + static_cast<uint64_t>(r));
            break;
        }
        // getrlimit(resource, &rlp). Only the descriptor and stack limits are ever
        // read by the guests here, and both answers are the host's own arrangement
        // rather than a constant: the stack is where main.cpp put it.
        case 194: {
            constexpr uint64_t kInfinity = ~0ull;
            uint64_t cur = kInfinity, max = kInfinity;
            // Darwin ORs `_RLIMIT_POSIX_FLAG` (0x1000) into the resource number to ask
            // for the per-process limit rather than the per-user one. Matching on the
            // raw value therefore never matches: the guest asks for 0x1008, falls to
            // the default, and gets RLIM_INFINITY for RLIMIT_NOFILE -- whereupon
            // sysconf(_SC_OPEN_MAX) has no number, `__sfp` decides every FILE slot is
            // taken, and **fopen returns NULL without ever calling open**. Which is
            // why the trace showed no failing syscall at all.
            switch (a0 & 0xFFF) {
                case 3: cur = 8u << 20; max = 64u << 20; break;      // RLIMIT_STACK
                case 8: cur = 256; max = 4096; break;                // RLIMIT_NOFILE
                default: break;                                      // the rest: no limit
            }
            mem_.write<uint64_t>(a1, cur);
            mem_.write<uint64_t>(a1 + 8, max);
            r = 0;
            break;
        }
        // statfs64 / fstatfs64. `opendir` calls fstatfs before it reads anything, to
        // learn the filesystem's block size and whether it is one of the types it has
        // to work around -- so failing this is not a missing feature, it is `opendir`
        // returning null and a guest that cannot list a directory at all.
        //
        // struct statfs (the 64-bit-inode form) is 2168 bytes and mostly names. The
        // fields a caller branches on are the block size, the type name, and the two
        // paths; the free-space numbers only have to be self-consistent, because
        // nothing here can run out of space in a way the guest could observe.
        case 345: case 346: {                              // statfs64, fstatfs64
            const uint64_t out = (nr == 345) ? a1 : a1;
            // The path argument only has to exist -- an fd or a name that does not
            // resolve should still fail, so both are checked the ordinary way first.
            if (nr == 345) {
                uint8_t lin[128];
                r = files.stat_path(guest_str(a0), lin);
            } else {
                uint8_t lin[128];
                r = files.fstat(static_cast<int>(a0), lin);
            }
            if (r != 0) { err = bsd_errno(r); r = 0; break; }
            std::vector<uint8_t> sfs(2168, 0);
            auto put32 = [&](size_t o, uint32_t v) { std::memcpy(sfs.data() + o, &v, 4); };
            auto put64 = [&](size_t o, uint64_t v) { std::memcpy(sfs.data() + o, &v, 8); };
            put32(0, 4096);                                // f_bsize
            put32(4, 1 << 20);                             // f_iosize
            put64(8, 1ull << 26);                          // f_blocks: 256 GiB of 4 KiB
            put64(16, 1ull << 25);                         // f_bfree
            put64(24, 1ull << 25);                         // f_bavail
            put64(32, 1ull << 20);                         // f_files
            put64(40, 1ull << 19);                         // f_ffree
            put32(60, 26);                                 // f_type: APFS
            std::memcpy(sfs.data() + 72, "apfs", 5);       // f_fstypename
            std::memcpy(sfs.data() + 88, "/", 2);          // f_mntonname
            std::memcpy(sfs.data() + 1112, "/dev/disk1s1", 13);   // f_mntfromname
            mem_.write_bytes(out, sfs.data(), sfs.size());
            r = 0;
            break;
        }
        // Darwin's mmap has the same argument order as Linux's, but MAP_ANON is
        // 0x1000 rather than 0x20, so the flag is translated before it is used.
        case 197: {
            const uint64_t dflags = a3;
            uint64_t lflags = 0;
            if (dflags & 0x0010) lflags |= 0x10;           // MAP_FIXED
            if (dflags & 0x1000) lflags |= 0x20;           // MAP_ANON -> MAP_ANONYMOUS
            r = sys_mmap(a0, a1, a2, lflags, static_cast<int>(cpu_.xr(4)), cpu_.xr(5));
            break;
        }
        case 73: r = 0; break;                             // munmap: the arena never shrinks
        case 74: r = 0; break;                             // mprotect: no protection modelled
        case 75: case 232: r = 0; break;                   // madvise, posix_madvise
        case 20: r = 1000; break;                          // getpid
        case 24: case 25: case 43: case 47: r = 1000; break;  // getuid/geteuid/getgid/getegid
        // gettid(&uid, &gid): the *audit* identity, which is the one a process had
        // before it changed identity. CoreFoundation's `__CFGetUGIDs` calls it first
        // and, when it fails, falls back to asking opendirectoryd over XPC -- which
        // on a machine with no launchd cannot work, and which ends thousands of
        // instructions later in libxpc's "API Misuse: Messages must be dictionaries."
        // Answering here is what keeps CF off that road entirely.
        case 286:
            mem_.write<uint32_t>(a0, 1000);
            mem_.write<uint32_t>(a1, 1000);
            r = 0;
            break;
        case 327: r = 0; break;                            // issetugid
        // Signals, and the thread calls that go with them. These *must* succeed: the
        // Linux side learned the same lesson, where refusing rt_sigprocmask took musl's
        // startup apart a few instructions later. Nothing here installs a handler, which
        // is honest for a guest that never raises one -- and a guest that does will fault
        // rather than run a handler that was never registered.
        case 46: r = 0; break;                             // sigaction
        case 48: r = 0; break;                             // sigprocmask
        case 329: r = 0; break;                            // __pthread_sigmask
        case 328: r = 0; break;                            // __pthread_kill
        // bsdthread_ctl(cmd, ...): the QoS and priority knobs. Claimed as supported in
        // bsdthread_register's feature word, so they have to answer; there is one thread
        // and no scheduler to inform, which makes success the truth.
        case 478: r = 0; break;                            // bsdthread_ctl
        // __semwait_signal[_nocancel](cond, mutex, timeout, relative, sec, nsec). With
        // one thread there is nothing that could ever signal, so blocking would be a
        // deadlock and returning success is "it was already signalled". Written down
        // because it is a real simplification: a guest that depends on the *ordering* a
        // semaphore gives will not get it, and threads will need this to block properly.
        case 423: case 334: r = 0; break;                  // __semwait_signal[_nocancel]
        case 372: r = 1000; break;                         // thread_selfid
        // bsdthread_register returns the set of thread features the kernel supports, and
        // libpthread treats zero as fatal: "Token from the kernel is 0". These are the
        // bits a real xnu returns -- DISPATCHFUNC, FINEPRIO, BSDTHREADCTL, SETSELF,
        // QOS_MAINTENANCE, QOS_DEFAULT.
        //
        // Claiming the real set rather than a smaller one is deliberate. A reduced set
        // sends libpthread down legacy paths that Apple no longer exercises, which is a
        // worse place to be than on the modern path missing a syscall -- and the missing
        // syscall announces itself, where a legacy path just behaves oddly.
        // x0 is `threadstart`, the address a new thread begins at. Remembering it is
        // what makes bsdthread_create possible at all: the start routine the guest
        // passed to pthread_create is an *argument* to that trampoline, not the entry.
        case 366:
            bsdthread_entry_ = a0;
            r = 0x4000001F;
            break;                                         // bsdthread_register
        case 360:                                          // bsdthread_create
            r = sys_bsdthread_create(a0, a1, a2, a3, cpu_.xr(4));
            if (r < 0) { err = kBsdEINVAL; r = 0; }
            break;
        // bsdthread_terminate(stackaddr, size, port, sem). Darwin's thread exit: the
        // stack is handed back to the kernel to free, which is why it is not freed by
        // the thread itself. Nothing here unmaps, so only the exit matters.
        case 361:
            thread_exit(0);
            return true;
        // __disable_threadsignal(0). A thread on its way out tells the kernel to stop
        // delivering signals to it. Nothing here delivers a signal to a specific
        // thread, so agreeing costs nothing -- and refusing does not: libpthread calls
        // it on every exit, so an error is three lines of noise per thread.
        case 331: r = 0; break;
        // __ulock_wait / __ulock_wake: Darwin's futex. Both write x0 and the carry
        // flag themselves and return here without falling into the shared tail,
        // because a wait switches threads and the tail would land in whichever
        // thread happens to be running afterwards.
        case 515:
            sys_ulock_wait(static_cast<uint32_t>(a0), a1, a2);
            return true;
        case 516:
            sys_ulock_wake(static_cast<uint32_t>(a0), a1);
            return true;
        // The psynch family: condition variables. Same rule as ulock -- these write
        // x0 and the carry flag themselves and do not fall into the shared tail,
        // because a wait switches threads.
        //
        //   305 __psynch_cvwait(cv, cvlsgen, cvugen, mutex, mugen, flags, sec, nsec)
        //   304 __psynch_cvsignal, 303 __psynch_cvbroad -- same first arguments
        //   301 __psynch_mutexwait, 302 __psynch_mutexdrop
        //
        // The numbers are read out of libsystem_kernel rather than recalled: each stub
        // begins `movz x16, #N`, and getting one wrong is a syscall that silently
        // fails and a thread that is never woken. 304 was 303 here for a while, and
        // the symptom was `threading.Thread.join()` hanging with no diagnostic at all.
        //
        // "Timed" is decided by the seconds/nanoseconds pair, not by a flag: a zero
        // deadline is an untimed wait. The difference matters at the end of the run,
        // where a timed wait nobody can satisfy is a timeout the caller retries and an
        // untimed one is a deadlock worth reporting.
        case 305: {
            const bool timed = cpu_.xr(6) || cpu_.xr(7);
            sys_psynch_cvwait(a0, a3, timed);
            return true;
        }
        case 304: sys_psynch_cvsignal(a0, false); return true;
        case 303: sys_psynch_cvsignal(a0, true); return true;
        // __psynch_mutexwait(mutex, mgen, ugen, tid, flags) and __psynch_mutexdrop.
        // The same wait machinery as the condition variables: one CPU, one thread at a
        // time, so "who is waiting on this address" is the whole of the state.
        case 301: sys_psynch_cvwait(a0, 0, false); return true;
        case 302: sys_psynch_cvsignal(a0, true); return true;
        case 116: {                                        // gettimeofday
            const uint64_t ns = host_nanos();
            mem_.write<uint64_t>(a0, ns / 1000000000ull);
            mem_.write<uint32_t>(a0 + 8, static_cast<uint32_t>((ns % 1000000000ull) / 1000));
            r = 0;
            break;
        }
        case 500: {                                        // getentropy
            for (uint64_t i = 0; i < a1; ++i)
                mem_.write<uint8_t>(a0 + i, static_cast<uint8_t>(0x9E * (i + 1) + 0x37));
            r = 0;
            break;
        }
        // __sysctl(name, namelen, oldp, oldlenp, newp, newlen). A libSystem startup asks
        // for a handful of machine properties this way, and answering with ENOENT is not
        // neutral: libpthread reads its stack bounds through it and treats a failure as a
        // zero token, then aborts with "Token from the kernel is 0" -- a message about
        // something else entirely.
        //
        // Unknown MIBs print themselves rather than failing quietly, because the number
        // is the whole question and guessing at which one a library wanted is how this
        // took a detour through bsdthread_register.
        case 202: {
            const uint32_t namelen = static_cast<uint32_t>(a1);
            uint32_t mib[8] = {0};
            for (uint32_t k = 0; k < namelen && k < 8; ++k)
                mib[k] = mem_.read<uint32_t>(a0 + k * 4);
            const uint64_t oldp = a2, oldlenp = a3;
            auto give_int = [&](uint64_t v, unsigned width) -> int64_t {
                if (trace)
                    std::fprintf(stderr, "[mac]   sysctl -> %llX (%u bytes) into %llX\n",
                                 static_cast<unsigned long long>(v), width,
                                 static_cast<unsigned long long>(oldp));
                if (oldlenp) {
                    const uint64_t have = mem_.read<uint64_t>(oldlenp);
                    if (oldp && have < width) {
                        if (trace)
                            std::fprintf(stderr, "[mac]   ...but the caller's buffer is "
                                                 "%llu bytes\n",
                                         static_cast<unsigned long long>(have));
                        return -22;                               // EINVAL
                    }
                    mem_.write<uint64_t>(oldlenp, width);
                }
                if (oldp) {
                    if (width == 8) mem_.write<uint64_t>(oldp, v);
                    else mem_.write<uint32_t>(oldp, static_cast<uint32_t>(v));
                }
                return 0;
            };
            auto give_str = [&](const char* s) -> int64_t {
                const uint64_t n = std::strlen(s) + 1;
                if (oldlenp) mem_.write<uint64_t>(oldlenp, n);
                if (oldp) mem_.write_bytes(oldp, s, n);
                return 0;
            };
            constexpr uint32_t CTL_KERN = 1, CTL_HW = 6;
            // Where main.cpp actually put the stack, so the answer is the truth rather
            // than a plausible constant. Declared before the first `goto sysctl_unknown`,
            // because g++ refuses a jump across an initialization that clang lets pass.
            constexpr uint64_t kStackTop = 0x0000'7FFF'FFFF'F000ull;
            // Some of the sysctls a libSystem startup reads are *dynamically registered*
            // nodes: they have no fixed MIB even on a real kernel, which assigns a number
            // when the node registers and hands it out through sysctlbyname(3). So this
            // assigns them too, out of a private range. Which numbers they are does not
            // matter; that name2oid and the numeric lookup below agree does.
            enum : uint32_t { kOidBootargs = 0x101, kOidOsVariant = 0x102,
                              kOidEphemeral = 0x103, kOidProductVersion = 0x104,
                              kOidSha512 = 0x105, kOidSha3 = 0x106,
                              kOidSecureKernel = 0x107 };
            static const struct { const char* name; uint32_t mib[2]; } kNamed[] = {
                {"kern.boottime",         {CTL_KERN, 21}},   // these two have real MIBs
                {"kern.osversion",        {CTL_KERN, 65}},
                {"kern.bootargs",         {0, kOidBootargs}},
                {"kern.osvariant_status", {0, kOidOsVariant}},
                {"hw.ephemeral_storage",  {0, kOidEphemeral}},
                // CPython reads the product version for `platform.mac_ver()`, and
                // libcorecrypto asks about the SHA extensions before choosing an
                // implementation. Both are answered rather than refused because a
                // refusal is not neutral: corecrypto's fallback for an *unknown*
                // answer is not the same code as its fallback for "no".
                {"kern.osproductversion", {0, kOidProductVersion}},
                {"kern.secure_kernel",    {0, kOidSecureKernel}},
                {"hw.optional.armv8_2_sha512", {0, kOidSha512}},
                {"hw.optional.armv8_2_sha3",   {0, kOidSha3}},
            };
            // {0, 3} is name2oid, which is what sysctlbyname(3) is built on: the name
            // comes in as a string in `newp` and the MIB goes back into `oldp`.
            if (namelen == 2 && mib[0] == 0 && mib[1] == 3) {
                const std::string want = guest_str(cpu_.xr(4));
                const uint32_t* found = nullptr;
                for (const auto& e : kNamed)
                    if (want == e.name) { found = e.mib; break; }
                if (!found) goto sysctl_unknown;
                if (oldlenp) mem_.write<uint64_t>(oldlenp, 8);
                if (oldp) {
                    mem_.write<uint32_t>(oldp, found[0]);
                    mem_.write<uint32_t>(oldp + 4, found[1]);
                }
                if (trace)
                    std::fprintf(stderr, "[mac]   name2oid(\"%s\") -> {%u, %u}\n",
                                 want.c_str(), found[0], found[1]);
                r = 0;
                break;
            }
            if (namelen == 2 && mib[0] == 0) {
                switch (mib[1]) {
                    // No boot arguments, which is also what a machine nobody has
                    // reconfigured reports.
                    case kOidBootargs: r = give_str(""); break;
                    // os_variant(3)'s cache: two bits per property, 2 meaning "no". All
                    // "no" is a stock customer machine -- no internal content, no internal
                    // diagnostics, not a recovery or DarwinOS system. Failing the call
                    // instead is survivable, because os_variant then goes and looks for
                    // /AppleInternal itself and this filesystem does not have one, but the
                    // answer is the same and this way it does not have to.
                    case kOidOsVariant: r = give_int(0xAAAA'AAAA'AAAA'AAAAull, 8); break;
                    case kOidEphemeral: r = give_int(0, 4); break;
                    case kOidProductVersion: r = give_str("15.7.4"); break;
                    // SHA-512 and SHA-3 are *not* implemented in crypto.cpp -- only
                    // SHA-1 and SHA-256 are -- so saying no is the truthful answer
                    // and it keeps corecrypto on the code this emulator can run.
                    case kOidSha512: case kOidSha3: r = give_int(0, 4); break;
                    case kOidSecureKernel: r = give_int(0, 4); break;
                    default: goto sysctl_unknown;
                }
                break;
            }
            if (namelen == 2 && mib[0] == CTL_KERN) {
                switch (mib[1]) {
                    case 2:  r = give_str("24.6.0"); break;        // KERN_OSRELEASE
                    case 1:  r = give_str("Darwin"); break;        // KERN_OSTYPE
                    case 8:  r = give_int(1024 * 1024, 4); break;  // KERN_ARGMAX
                    case 10: r = give_str("aarch64emu"); break;    // KERN_HOSTNAME
                    // KERN_USRSTACK64: where the main thread's stack *top* is. libpthread
                    // derives the main thread's bounds from this, and a zero here is the
                    // zero token it complains about.
                    // KERN_USRSTACK64: the top of the main thread's stack. libpthread
                    // derives the main thread's bounds from it, and a zero here becomes
                    // "BUG IN LIBPTHREAD: Token from the kernel is 0" -- a message about
                    // something else entirely.
                    //
                    // The number is 59 on Sequoia, not the 70 the older headers give, and
                    // that was settled by reading the caller rather than a header: on
                    // failure it substitutes 0x1_6FE00000, which is exactly where a macOS
                    // arm64 main-thread stack sits. Nothing else it could be asking for.
                    case 59: case 70: r = give_int(kStackTop, 8); break;
                    case 35: r = give_int(kStackTop, 4); break;   // KERN_USRSTACK32
                    case 65: r = give_str("24G84"); break;        // KERN_OSVERSION: build
                    // KERN_VERSION: the banner `uname -v` prints. `os.uname()` reads
                    // it, and libc turns a missing sysctl into ENOENT -- which Python
                    // reports as `FileNotFoundError: No such file or directory` from a
                    // call that opened no file at all.
                    case 4: r = give_str("Darwin Kernel Version 24.6.0: "
                                         "aarch64_emu_cpp"); break;
                    // KERN_BOOTTIME, a struct timeval. Taken once, the first time it is
                    // asked: the guest subtracts it from the current time to get the
                    // uptime, and a boot time that moved between two calls would make
                    // that go backwards. From the guest's side this machine did just
                    // come up, so the first ask is the truth.
                    case 21: {
                        if (!boot_time_) boot_time_ = static_cast<uint64_t>(std::time(nullptr));
                        if (oldlenp) mem_.write<uint64_t>(oldlenp, 16);
                        if (oldp) {
                            mem_.write<uint64_t>(oldp, boot_time_);
                            mem_.write<uint64_t>(oldp + 8, 0);
                        }
                        r = 0;
                        break;
                    }
                    default: goto sysctl_unknown;
                }
                break;
            }
            if (namelen == 2 && mib[0] == CTL_HW) {
                switch (mib[1]) {
                    case 3:  r = give_int(1, 4); break;            // HW_NCPU
                    case 7:  r = give_int(16384, 4); break;        // HW_PAGESIZE
                    case 24: r = give_int(1, 4); break;            // HW_AVAILCPU
                    case 25: r = give_int(8ull << 30, 8); break;   // HW_MEMSIZE
                    // HW_MACHINE. "arm64" and not "arm64e": the *guest* is arm64,
                    // and `platform.machine()` is read by code that branches on it.
                    case 1: r = give_str("arm64"); break;
                    default: goto sysctl_unknown;
                }
                break;
            }
        sysctl_unknown:
            // {0, 3} is "name2oid", the call underneath sysctlbyname(3): the name arrives
            // as a string in `newp` and the MIB is written back into `oldp`. Report the
            // name, because the numbers alone say nothing about what was wanted.
            if (namelen == 2 && mib[0] == 0 && mib[1] == 3)
                std::fprintf(stderr, "[mac]   name2oid(\"%s\")\n",
                             guest_str(cpu_.xr(4)).c_str());
            std::fprintf(stderr, "[mac] sysctl not implemented:");
            for (uint32_t k = 0; k < namelen && k < 8; ++k) std::fprintf(stderr, " %u", mib[k]);
            std::fprintf(stderr, "   (namelen %u, at PC %016llX)\n", namelen,
                         static_cast<unsigned long long>(cpu_.pc - 4));
            err = kBsdENOENT;
            break;
        }
        case 274: err = kBsdENOENT; break;                 // sysctlbyname
        case 54: err = 25; break;                          // ioctl: ENOTTY, we are not a tty
        case 92: case 406: r = 0; break;                   // fcntl[_nocancel]
        case 294: err = kBsdEINVAL; break;                 // shared_region_check_np: no cache
        case 336: err = kBsdEINVAL; break;                 // proc_info
        // The code-signing status of a process, which libSystem consults before it
        // decides whether library validation, the debugger interfaces or the hardened
        // runtime apply. CS_OPS_STATUS is the only query it needs an answer to; the blob
        // queries (entitlements, team id, cdhash) have no answer for a binary that is
        // not signed, and ENOENT is what the kernel returns for them then -- so callers
        // are already written for it.
        case 169:                                          // csops(pid, ops, addr, size)
        case 170: {                                        // csops_audittoken(+ token)
            constexpr uint32_t CS_OPS_STATUS = 0;
            constexpr uint32_t CS_VALID = 0x1, CS_ADHOC = 0x2;
            if (a1 == CS_OPS_STATUS && a2 && a3 >= 4) {
                mem_.write<uint32_t>(a2, CS_VALID | CS_ADHOC);
                r = 0;
            } else {
                err = kBsdENOENT;
            }
            break;
        }
        // System Integrity Protection's configuration. Nothing here relaxes any part of
        // it, which is also what a stock machine reports, so the bitmask is zero and the
        // call *succeeds* -- failing it instead makes a caller assume the opposite.
        case 483: {                                        // csrctl(op, addr, size)
            if (a1 && a2 >= 4) mem_.write<uint32_t>(a1, 0);
            r = 0;
            break;
        }
        // POSIX shared memory. There is no shm namespace here; ENOENT is what an absent
        // object gives, and notify(3) then asks its daemon each time instead of reading
        // a shared page.
        case 266: err = kBsdENOENT; break;                 // shm_open
        // The bulk filesystem-attribute call. ENOTSUP is what a filesystem that does not
        // implement it returns, and callers carry a stat(2) fallback for exactly that
        // case -- which is a path this emulator does implement.
        case 220: err = 45; break;                         // getattrlist: ENOTSUP
        // socket(2). There is no networking here, and the one the guest actually asks for
        // is AF_UNIX/SOCK_DGRAM: libsystem_c's syslog fallback, on its way to
        // /var/run/syslog. EPERM is the answer a sandboxed process gets.
        case 97: err = 1; break;                           // socket: EPERM
        default:
            if (unknown) unknown(static_cast<uint64_t>(nr));
            std::fprintf(stderr, "[mac] unimplemented syscall %lld at PC %016llX\n",
                         static_cast<long long>(nr),
                         static_cast<unsigned long long>(cpu_.pc - 4));
            err = kBsdENOSYS;
            break;
    }

    // `Files` speaks Linux, returning a negative errno. Darwin wants the sign in
    // the carry flag and the magnitude in x0.
    if (!err && r < 0) { err = bsd_errno(r); r = 0; }
    if (err) { cpu_.setx(0, static_cast<uint64_t>(err)); cpu_.c = true; }
    else     { cpu_.setx(0, static_cast<uint64_t>(r));   cpu_.c = false; }
    if (vfork_pending()) cpu_.stop_requested = true;
    return true;
}

}  // namespace a64
