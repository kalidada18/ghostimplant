# 👻 GHOST – The Invisible Implant

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Restricted-red?style=for-the-badge" />
</p>

<p align="center">
  <b>GHOST</b> is an advanced, stealthy Windows implant and serverless C2 infrastructure – <br/>
  built for authorised Red Team operations and defensive research against modern EDRs.
</p>

<p align="center">
  <i>“You can’t kill what you can’t see.”</i>
</p>

---

## 🧠 Why GHOST?

Most implants are **loud**, **predictable**, and **easy to catch**.  
GHOST is designed to be the **quietest** tool in your arsenal – using **direct system calls**, **fileless persistence**, **double‑encrypted C2**, and **DNS fallback** to stay invisible even under active threat hunting.

- **No static IPs** – serverless, route through Cloudflare’s global CDN.  
- **No disk artifacts** – everything runs in memory; persistence lives in the WMI repository.  
- **No static imports** – all APIs resolved at runtime via FNV‑1a hashes.  
- **No plain strings** – all literals are XOR‑obfuscated at compile time.  
- **No sleep() calls** – uses `NtDelayExecution` with randomised jitter.

This isn’t a script‑kiddie tool. This is a **professional‑grade** implant used in advanced threat simulation.

---

## 🚀 Features

### 🌐 Infrastructure
- **Serverless C2** – Cloudflare Worker + KV. No servers to log, no IPs to block.  
- **Asynchronous Beaconing** – dead‑drop architecture, implant and operator never talk directly.  
- **Two‑Tier Authentication** – separate tokens for beacons (`BEACON_TOKEN`) and operator (`OPERATOR_TOKEN`), constant‑time validated.  
- **Interactive CLI** – Python‑based operator console with session management, task queuing, and result retrieval.

### 🧬 Implant (Payload)
- **Direct WinHTTP** – pure HTTPS over port 443, blends with legitimate traffic.  
- **Jittered Sleep** – randomised intervals (45–180s) defeat behavioural analysis.  
- **Encrypted Config** – C2 domain XOR‑encrypted, decrypted using FNV‑1a hostname hash.  
- **GUI Subsystem** – runs silently, no console window (`-mwindows`).  
- **Statically Linked** – standalone `.exe`, no external DLL dependencies.

### 🛡️ Evasion Arsenal
| Technique | Detection Surface |
|-----------|-------------------|
| **AMSI Bypass** – patch `AmsiScanBuffer` to always return clean | ETW `Microsoft-Antimalware-Scan-Interface`, Sysmon EID 7 |
| **ETW Bypass** – patch `EtwEventWrite` to no‑op | Kernel ETW audit, integrity checks |
| **Direct Syscalls (Hell’s Gate + Halo’s Gate)** – read clean ntdll, extract SSNs, build RWX stubs | Memory scanning for syscall patterns |
| **PPID Spoofing** – spawn child processes under trusted parent (e.g., `svchost.exe`) | Sysmon EID 1 (parent PID mismatch) |
| **Module Stomping** – overwrite `.text` of a legitimate loaded DLL with shellcode | Memory integrity scans, unbacked executable pages |
| **WMI Scriptless Persistence** – VBScript stored directly in WMI repository; no file on disk | File system scans, Sysmon EID 11 |
| **AES‑GCM Double Encryption** – hardware‑derived key, TLS + application‑layer encryption | Network DPI, TLS interception |
| **DNS Tunneling** – fallback C2 when HTTPS is blocked | DNS query monitoring |
| **Dropbox Exfiltration** – blend with legitimate cloud sync traffic | Network traffic analysis |

---

## 📡 Architecture Diagram

```mermaid
graph TD
    subgraph Target["Target Environment"]
        A[GHOST Implant]
    end

    subgraph Cloudflare["Cloudflare Edge"]
        B(Cloudflare Worker API)
        C[(Workers KV Storage)]
    end
    
    subgraph Operator["Operator Environment"]
        D[Operator CLI]
    end

    A -- "POST /beacon (encrypted)" --> B
    B <--> C
    D -- "HTTPS API (task/result)" --> B


⚡ Quick Start
A complete step‑by‑step guide for deployment, configuration, building, and running the implant is available in START_GUIDE.md.

📁 Project Structure
ghostimplant/
├── src/                # Implant C++ Source
│   ├── main.cpp        # Entry point and payload execution
│   ├── c2.cpp          # WinHTTP transport and beaconing logic
│   ├── utils.cpp       # Crypto, FNV‑1a hashing, string conversions
│   └── *.cpp           # Stub implementations (syscalls, evasion)
├── include/            # C++ Headers
├── worker/             # Cloudflare Worker Backend
│   ├── src/index.ts    # Serverless C2 API routing and logic
│   └── wrangler.toml   # Cloudflare deployment configuration
├── server/             # Operator Environment
│   ├── c2_cli.py       # Interactive command line interface
│   └── requirements.txt
├── tools/
│   └── encrypt_domain.py # Generates XOR payload config
├── build.ps1           # Windows MSVC Build Script
├── build.sh            # Linux MinGW Cross-Compile Script
├── START_GUIDE.md      # Step‑by‑step deployment guide
└── SYSTEM_DESIGN.md    # Advanced architectural and OPSEC documentation

## ⚠️ Disclaimer ##
This tool is developed exclusively for authorised security research and academic purposes.

<p align="center"> <b>Built for the Red Team. Survived the Blue Team.</b><br/> <i>You are already compromised.</i> </p> ```
