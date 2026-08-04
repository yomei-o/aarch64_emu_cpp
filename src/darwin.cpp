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
void Syscalls::call_guest(uint64_t fn, uint64_t a0, uint64_t a1, uint64_t a2) {
    constexpr uint64_t kReturnMagic = 0x0000'0000'DEAD'2000ull;
    const uint64_t insns0 = cpu_.insns;
    const Cpu::Context saved = cpu_.save_context();
    cpu_.pc = fn;
    cpu_.setx(0, a0);
    cpu_.setx(1, a1);
    cpu_.setx(2, a2);
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

// The handler for those stubs. `w16` holds the vtable slot index.
int64_t Syscalls::dyld_api_stub(uint32_t slot) {
    switch (slot) {
        // _dyld_get_active_platform. PLATFORM_MACOS is 1; returning 0 would be
        // PLATFORM_UNKNOWN, and libSystem branches on it.
        case 66: return 1;
        // _dyld_get_prog_image_header: the main executable's mach_header. Zero is simply
        // wrong -- it is the one image whose address is never in doubt.
        case 94:
            return static_cast<int64_t>(objc_image_headers_.empty() ? 0 : prog_header_);
        // _dyld_for_objc_header_opt_ro. On this OS the shared cache's ObjC optimisation
        // header lives inside libobjc itself, in `__TEXT,__objc_opt_ro` -- so unlike the
        // rest of the cache's tables, it is *present* in an extracted library and only
        // needs pointing at. libobjc uses it to interpret the preoptimized class layout,
        // which is what `OBJC_METACLASS_$_NSObject`'s data field is in: its `bits` field
        // decodes to nonsense read as an ordinary pointer, and only four slots in the
        // whole of libobjc's data have the top bit set, so it is not an unpacked pointer.
        case 118: return static_cast<int64_t>(objc_opt_ro_);
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
            if (!objc_opt_rw_) {
                objc_opt_rw_ = kObjcOptRw;
                mem_.set(objc_opt_rw_, 0, kObjcOptRwSize);
            }
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
            if (trace)
                std::fprintf(stderr, "[objc] map_images(%zu) at %012llX\n", n,
                             static_cast<unsigned long long>(map_images));
            call_guest(map_images, n, infos, 0);

            // Then the `init` callback, once per image, which is the rest of what dyld
            // does at registration: it runs each image's `+load` methods and finishes
            // whatever `map_images` deferred. Same order, for the same reason.
            const uint64_t load_images = mem_.read<uint64_t>(p + 16);
            if (load_images && !cpu_.halted)
                for (size_t j = 0; j < n && !cpu_.halted; ++j)
                    call_guest(load_images, infos + j * kInfoSize, 0, 0);
            return 0;
        }
        default:
            // The return address, because the stub is three instructions and says nothing
            // about which API it stands for. x30 names the caller, and the caller's symbol
            // names the method.
            std::fprintf(stderr,
                         "[mac] dyld API vtable slot %u (+0x%X) is not implemented, "
                         "returning 0; called from %012llX\n",
                         slot, slot * 8, static_cast<unsigned long long>(cpu_.xr(30)));
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
                uint32_t& slot = special_ports_[mem_.read<uint32_t>(data + 32)];
                if (!slot) slot = next_port_++;
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
        case 8000: case 8001:
        case 3419: {
            const uint32_t size = 24 + 8 + 4;
            if (reply_cap && size > reply_cap) return kKernFailure;
            reply_header(size);
            mem_.write<uint32_t>(data + 32, 0);              // RetCode
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
        case 366: r = 0x4000001F; break;                   // bsdthread_register
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
            // than a plausible constant.
            constexpr uint64_t kStackTop = 0x0000'7FFF'FFFF'F000ull;
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
                    default: goto sysctl_unknown;
                }
                break;
            }
        sysctl_unknown:
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
    return true;
}

}  // namespace a64
