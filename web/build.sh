#!/bin/sh
# Builds the browser/node demo.
#
# Everything lands in one self-contained aarch64emu.js (the wasm is embedded with
# SINGLE_FILE), so web/ serves as plain static files -- no MIME setup, no separate
# .wasm fetch, and it works from GitHub Pages.
#
# Needs emscripten on PATH, or EMCC pointing at emcc.
set -e
cd "$(dirname "$0")/.."
EMCC=${EMCC:-emcc}
command -v "$EMCC" >/dev/null 2>&1 || { echo "emcc not found; set EMCC=/path/to/emcc"; exit 1; }

# Everything in src/ except the command-line front end, which web/wasm_api.cpp
# replaces. Globbing keeps this from going stale when a source file is added.
SOURCES=$(ls src/*.cpp | grep -v '/main\.cpp$')

echo "== building web/aarch64emu.js"
"$EMCC" -std=c++17 -O2 -Isrc \
    $SOURCES web/wasm_api.cpp \
    -o web/aarch64emu.js \
    -sMODULARIZE=1 -sEXPORT_NAME=createA64Emu \
    -sSINGLE_FILE=1 -sALLOW_MEMORY_GROWTH=1 \
    -sMAXIMUM_MEMORY=2GB \
    -sEXPORTED_FUNCTIONS='["_emu_run","_emu_error","_emu_instructions","_malloc","_free"]' \
    -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","HEAPU8","FS","stringToUTF8","lengthBytesUTF8"]' \
    -sFORCE_FILESYSTEM=1 -sENVIRONMENT=web,worker,node --no-entry
ls -l web/aarch64emu.js
echo done
