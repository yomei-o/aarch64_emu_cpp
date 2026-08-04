#!/bin/sh
# Builds the emulator without needing CMake.
#
#   sh build.sh                     # g++ (or $CXX), the usual case
#   CXX=clang++ sh build.sh         # clang, same flags
#   CXX=cl sh build.sh              # MSVC: cl.exe's own flags, and aarch64emu.exe
#
# The MSVC branch exists because CMakeLists.txt already promised it and the sources are
# now free of GCC/Clang extensions (see bswap32/umulh in cpu.cpp). cl.exe needs its
# arguments spelled differently -- /Fe for the output name, /EHsc for exceptions -- so it
# gets its own line rather than a pile of translated variables.
set -e
cd "$(dirname "$0")"
CXX=${CXX:-g++}

case "$(basename "$CXX")" in
    cl|cl.exe)
        # -utf-8 because the sources are UTF-8 and cl.exe otherwise reads them in the
        # system code page; NOMINMAX and _CRT_SECURE_NO_WARNINGS for the usual reasons.
        "$CXX" -nologo -std:c++17 -O2 -EHsc -utf-8 -W3 -DNOMINMAX \
               -D_CRT_SECURE_NO_WARNINGS -Isrc src/*.cpp -Fe:aarch64emu.exe
        echo "built aarch64emu.exe"
        ;;
    *)
        CXXFLAGS=${CXXFLAGS:--std=c++17 -O2 -Wall -Wextra}
        $CXX $CXXFLAGS -Isrc -o aarch64emu src/*.cpp
        echo "built aarch64emu"
        ;;
esac
