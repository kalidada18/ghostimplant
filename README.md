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
