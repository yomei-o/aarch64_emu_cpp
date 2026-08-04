#!/bin/sh
# Builds the emulator without needing CMake.
set -e
cd "$(dirname "$0")"
CXX=${CXX:-g++}
CXXFLAGS=${CXXFLAGS:--std=c++17 -O2 -Wall -Wextra}
$CXX $CXXFLAGS -Isrc -o aarch64emu src/*.cpp
echo "built aarch64emu"
