# 👻 GHOST

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Restricted-red?style=for-the-badge" />
</p>

<p align="center">
  <b>Serverless implant. Fileless persistence. Double-encrypted C2.</b><br/>
  <b>Built to survive modern EDRs. Built to stay invisible.</b>
</p>

<p align="center">
  <i>"You can't kill what you can't see."</i>
</p>

---

## The Problem With Every Other Implant

They beacon on a timer. They touch disk. They leave a module in memory that looks exactly like what it is.

GHOST doesn't do any of that.

- **No static IPs.** Serverless. Cloudflare's global CDN is your infrastructure. There is nothing to trace.
- **No disk artifacts.** Persistence lives in the WMI repository. The file system never knows it was here.
- **No static imports.** Every API resolved at runtime via FNV-1a hash. Import tables are clean.
- **No plain strings.** Every literal XOR-obfuscated at compile time. Strings don't survive analysis.
- **No `sleep()` calls.** `NtDelayExecution` with randomised jitter. Behavioural signatures don't apply.

Blue teams hunt patterns. GHOST doesn't have any.

---

## Evasion Arsenal

| Technique | What It Kills |
|---|---|
| **AMSI Bypass** — patch `AmsiScanBuffer` in-process | AV scan-on-execute, AMSI ETW provider |
| **ETW Bypass** — `EtwEventWrite` no-op'd at runtime | All ETW-sourced telemetry, Sysmon EID 7 |
| **Direct Syscalls (Hell's Gate + Halo's Gate)** — clean ntdll copy, SSN extraction, RWX stubs built in memory | User-mode hooking, EDR API interception |
| **PPID Spoofing** — spawn under `svchost.exe` or any trusted parent | Sysmon EID 1, process tree anomaly detection |
| **Module Stomping** — overwrite `.text` of a legitimate loaded DLL | Unbacked executable memory scanning |
| **WMI Scriptless Persistence** — VBScript stored in WMI repository, never touches disk | File-based scans, autoruns, Sysmon EID 11 |
| **AES-GCM Double Encryption** — hardware-derived key, TLS + application layer | DPI, TLS interception, traffic analysis |
| **DNS Tunneling** — C2 fallback when 443 is blocked | Perimeter HTTPS filtering |
| **Dropbox Exfiltration** — data leaves as cloud sync | DLP, network egress monitoring |

---

## Infrastructure

No servers. No IPs. No logs.
Target ──── POST /beacon (AES-GCM) ──── Cloudflare Worker ──── KV Storage
│
Operator CLI ────────── HTTPS API

Implant and operator never communicate directly. Dead-drop architecture. Even if the Worker is found, it proves nothing — all stored data is encrypted and the keys never leave your machine.

- **Two-token auth** — `BEACON_TOKEN` and `OPERATOR_TOKEN` are separate, constant-time validated, rotated per engagement.
- **Jittered beaconing** — 45–180s randomised intervals. No heartbeat pattern.
- **Operator CLI** — Python-based, interactive session management, task queue, result retrieval.

---

## Implant

Pure WinHTTP over port 443. Blends with every TLS-capable application on the host. No console window (`-mwindows`). No external DLL dependencies — statically linked, single executable.

C2 domain is XOR-encrypted inside the binary, decrypted at runtime using the FNV-1a hash of the hostname. Even if the binary is pulled from memory and analysed, the domain is not readable.

---

## Build

Configure `BEACON_TOKEN` and the XOR-encrypted domain in `src/c2.cpp` before compiling. See `START_GUIDE.md`.

**Windows (MSVC):**
```powershell
.\build.ps1          # Release → build\bin\Release\ghost.exe
.\build.ps1 -Debug   # Debug   → build\bin\Debug\ghost.exe
```

**Linux (MinGW cross-compile):**
```bash
sudo apt install mingw-w64
chmod +x build.sh && ./build.sh   # → build/ghost.exe
```

---

## Project Structure
ghostimplant/
├── src/
│   ├── main.cpp          # Entry point, payload execution
│   ├── c2.cpp            # WinHTTP transport, beacon logic
│   ├── utils.cpp         # AES-GCM, FNV-1a, string handling
│   └── *.cpp             # Syscall stubs, evasion modules
├── include/
├── worker/
│   ├── src/index.ts      # Cloudflare Worker — C2 routing
│   └── wrangler.toml
├── server/
│   ├── c2_cli.py         # Operator console
│   └── requirements.txt
├── tools/
│   └── encrypt_domain.py # XOR config generator
├── build.ps1
├── build.sh
├── START_GUIDE.md
└── SYSTEM_DESIGN.md

---

## OPSEC

- Rotate `BEACON_TOKEN` and `OPERATOR_TOKEN` every engagement. Never reuse.
- One domain per campaign. Never share infrastructure across operations.
- Change the XOR key in `obfuscate.hpp` before every build. Different key = different binary fingerprint.
- Sign with a valid certificate. SmartScreen doesn't touch signed binaries.
- Deploy via phishing or USB. `launcher.exe` acts as decoy; implant spawns in background.
- `wrangler tail` for real-time Worker log monitoring during an operation.

---

## Research Foundation

GHOST is built on published offensive security research:

- **Hell's Gate / Halo's Gate** — direct syscall invocation bypassing user-mode hooks
- **AMSI / ETW bypass techniques** — from the offensive security community
- **WMI scriptless persistence** — modern APT tradecraft
- **AES-GCM + DNS tunneling** — resilient C2 architecture

---

<p align="center">
  <b>Built for authorised Red Team operations and EDR evasion research.</b><br/>
  <b>Do not deploy against systems you do not own or have explicit written authorisation to test.</b>
</p>

<p align="center">
  <i>By the time you're reading this — it already ran.</i>
</p>
