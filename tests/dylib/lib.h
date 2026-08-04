#pragma once
#include <stdint.h>

extern int32_t lib_value;
extern const char lib_name[];
extern const char* lib_name_ptr;   // a pointer *into* the library: needs a rebase
int32_t lib_add(int32_t a, int32_t b);
int32_t lib_mul(int32_t a, int32_t b);
uint64_t lib_hash(const char* s);
