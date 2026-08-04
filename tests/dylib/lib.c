// The library half of the dynamic-linking test. Built as a real arm64 .dylib for
// the guest, and compiled straight into the program for the host oracle.
#include "lib.h"

int32_t lib_value = 42;
const char lib_name[] = "libfoo";
// A pointer whose value is an address inside this image. In the dylib it cannot be
// stored as a constant -- the image does not know where it will be loaded -- so the
// linker leaves a *rebase* fixup here and the loader has to add the slide. Reading
// the string back through it is the only way to tell a correct rebase from a
// plausible one.
const char* lib_name_ptr = lib_name;

int32_t lib_add(int32_t a, int32_t b) { return a + b; }
int32_t lib_mul(int32_t a, int32_t b) { return a * b; }

uint64_t lib_hash(const char* s) {
    uint64_t h = 1469598103934665603ull;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 1099511628211ull;
    }
    return h;
}
