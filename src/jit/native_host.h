// Which native backend, if any, this build has: the host the emulator itself is compiled for.
#pragma once

#if defined(__EMSCRIPTEN__)
// the WebAssembly build has its own tier (backend_wasm.cpp)
#elif defined(__x86_64__) || defined(_M_X64)
#define JIT_NATIVE_X64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#define JIT_NATIVE_A64 1
#endif
