// Dynamic linking on the Darwin side, where the emulator plays dyld.
//
// Three kinds of fixup have to come out right and each fails differently:
//
//   - a **function bind** — calling lib_add goes through the __got, which holds a
//     placeholder until something writes the real address in;
//   - a **data bind** — reading lib_value reaches through the same table;
//   - a **rebase** — lib_name_ptr is an address inside the library, and the library
//     does not know where it will be loaded, so the loader has to add the slide.
//
// A wrong bind usually crashes. A wrong *rebase* does not: it produces a pointer
// that is merely somewhere else, which is why the string is printed rather than
// just checked for non-null.
#include "harness.h"
#include "lib.h"

TEST_MAIN {
    say("add: ");
    dec(lib_add(lib_value, 7));
    say("mul: ");
    dec(lib_mul(lib_value, 3));
    say("name: ");
    say(lib_name_ptr);
    out("\n", 1);
    say("hash: ");
    hex64(lib_hash(lib_name_ptr));
    say("value: ");
    dec(lib_value);
    finish();
}
