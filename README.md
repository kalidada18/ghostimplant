# 👻 GHOST — The Silent Implant

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-2.0.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-informational?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-Restricted-red?style=for-the-badge" />
</p>

<p align="center">
  <b>GHOST</b> is a stealthy, fully‑featured Windows x64 implant with a serverless C2 backend.<br/>
  Built for authorized red‑team operations. Cross‑compiled from Kali Linux in one command.
</p>

<p align="center">
  <i>“You can’t kill what you can’t see.”</i>
</p>

---

## 🧬 Capabilities – What Makes It Dangerous

| Feature | Description |
|---------|-------------|
| **Direct Syscalls (Hell’s Gate)** | Parses ntdll.dll at runtime, builds RWX stubs. No import table for NT functions. |
| **AMSI / ETW Bypass** | Patches `AmsiScanBuffer` and `EtwEventWrite` family – no logging, no scanning. |
| **Hardware Breakpoint Clear** | Clears DR0–DR7 on all threads – defeats kernel‑level debugging. |
| **AES‑GCM Double Encryption** | Hostname‑derived key (volume serial + CPUID + hostname → SHA‑256). TLS + application‑layer encryption. |
| **Process Injection** | Full syscall‑chain injection (NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx). APC and module stomping included. |
| **PPID Spoofing** | Spawns processes under a legitimate parent (e.g., svchost.exe) – breaks parent‑chain heuristics. |
| **Persistence (3 Layers)** | WMI CommandLine/ActiveScript (no file on disk), Registry Run key, Scheduled Task. |
| **C2 (Cloudflare Worker)** | Serverless, no static IP, KV‑based task queue and session management. |
| **Telegram Exfiltration & C2** | Upload files and receive commands directly via Telegram bot – no extra infrastructure. |
| **Wallpaper Control** | Set or reset the victim’s desktop background – a low‑key persistent reminder. |
| **Post‑Exploitation Arsenal** | Credential dumping (Windows Vault, PuTTY, autologon), browser cookie/password extraction, file exfiltration, lateral movement (WMI), process listing, download/upload. |

---

## 📡 Architecture

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
    A -- "Telegram bot commands" --> T[Telegram API]
    🔐 Obfuscation & Anti‑Forensics
All strings are XOR‑encrypted at compile time (XS/XSW macros) – none appear in .rdata.

API calls are resolved by FNV‑1a hash – no GetProcAddress strings.

PE timestamp is randomised on every build – defeats hash‑based blocklists.

Stripped binary – no debug symbols, no .comment section, no GNU notes.

🛠️ Operator CLI Capabilities
sessions – list active implants

shell <sid> – interactive command shell on a remote host

task <sid> <cmd> – queue a single command

!wallpaper <path> – set desktop background

!reverse IP[:PORT] – launch reverse shell to your listener

!browser – dump saved passwords and cookies from Chrome/Edge

!telegram <file> – exfiltrate file to Telegram bot

!inject <PID> <b64_shellcode> – inject shellcode remotely

!migrate – migrate to a SYSTEM svchost process

!creds – dump Windows Vault, autologon, PuTTY credentials

!wipe – clear event logs, prefetch, shimcache

download/upload – file transfer via C2

⚙️ Deployment Overview
The implant is delivered to the target, executed (preferably with administrative privileges), and establishes an encrypted beacon to the Cloudflare Worker. The operator connects via the CLI, queues tasks, and receives results through the same channel. Persistence is installed automatically, and the implant self‑heals via a watchdog thread.

⚠️ Disclaimer
This tool is developed exclusively for authorised security research and academic purposes.

Do not use this tool against systems you do not own or have explicit written authorisation to test.

The authors are not responsible for misuse.

All testing should be conducted in isolated lab environments.

<p align="center"> <b>Built for the Red Team. Survived the Blue Team.</b><br/> <i>You are already compromised.</i> </p> ```