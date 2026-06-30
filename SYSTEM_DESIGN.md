# GHOST — System Design Document

## 1. Overview

GHOST is a research-grade Windows C2 implant framework built for studying EDR evasion
techniques, implant lifecycle management, and serverless C2 infrastructure. It consists
of three components: a native Windows implant, a serverless C2 backend, and an operator CLI.

This document covers architecture, data flow, protocol specification, evasion technique
catalog, operational security considerations, and deployment topology.

---

## 2. Architecture

### 2.1 Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE                              │
│                                                                     │
│   ┌────────────┐           ┌──────────────────────────────────┐     │
│   │            │   HTTPS   │      Cloudflare Worker           │     │
│   │  Operator  │◄─────────►│                                  │     │
│   │    CLI     │  Token    │  ┌────────┐  ┌───────────────┐   │     │
│   │  (Python)  │  Auth     │  │ Router │──│  KV Namespace │   │     │
│   │            │           │  └────────┘  └───────────────┘   │     │
│   └────────────┘           └──────────────┬───────────────────┘     │
│                                           │                         │
└───────────────────────────────────────────┼─────────────────────────┘
                                            │
                         HTTPS / TLS 1.3    │  Cloudflare Edge
                         Port 443           │  (300+ PoPs)
                         Jittered Interval  │
                                            │
┌───────────────────────────────────────────┼─────────────────────────┐
│                          DATA PLANE       │                         │
│                                           │                         │
│   ┌───────────────────────────────────────▼──────────────────┐      │
│   │                    ghost.exe                             │      │
│   │                                                          │      │
│   │  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐    │       │
│   │  │   Syscall    │  │   Evasion   │  │  Persistence  │    │      │
│   │  │   Manager    │  │    Stack    │  │    Engine     │    │      │
│   │  │             │  │             │  │                │    │      │
│   │  │  SSN Extract │  │  AMSI Patch │  │  WMI Event    │    │      │
│   │  │  Stub Build  │  │  ETW Patch  │  │  Subscription │    │      │
│   │  │  Trampoline  │  │  HW BP Clr  │  │               │    │      │
│   │  └──────┬──────┘  └──────┬──────┘  └───────┬────────┘    │      │
│   │         │                │                  │            │      │
│   │  ┌──────▼──────────────────▼──────────────────▼───────┐   │      │
│   │  │                  Beacon Loop                       │   │      │
│   │  │                                                    │   │      │
│   │  │  WinHTTP ──► JSON Serialize ──► HTTP POST          │   │      │
│   │  │         ◄── JSON Parse     ◄── HTTP Response       │   │      │
│   │  │                                                    │   │      │
│   │  │  Recv Task ──► cmd.exe /C ──► Pipe Capture         │   │      │
│   │  │           ──► POST /result                         │   │      │
│   │  └────────────────────────────────────────────────────┘   │      │
│   │                                                          │      │
│   │  ┌────────────────────────────────────────────────────┐   │      │
│   │  │              Injection Engine                      │   │      │
│   │  │  PPID Spoof │ Remote Inject │ Module Stomp         │   │      │
│   │  └────────────────────────────────────────────────────┘   │      │
│   └──────────────────────────────────────────────────────────┘      │
│                                                                     │
│   Target: Windows 10/11 x64 │ Static CRT │ GUI Subsystem            │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Design Decisions

| Decision | Rationale |
|---|---|
| **Cloudflare Workers over VPS** | No static IP to block. Traffic goes through Cloudflare's CDN — indistinguishable from legitimate HTTPS. Workers auto-scale, no infra to maintain. |
| **Workers KV over D1 (SQLite)** | KV is simpler, lower latency for key-value session lookups. Eventual consistency is acceptable — beacon intervals are 45-180s. |
| **WinHTTP over WinInet** | WinHTTP is designed for service-to-service communication. Doesn't respect IE proxy auto-config (more predictable), lower overhead, no cookie jar pollution. |
| **JSON over custom binary protocol** | Blends with legitimate HTTPS API traffic. JSON is inspectable for debugging. The performance penalty is irrelevant at beacon intervals of 45+ seconds. |
| **Static CRT (/MT)** | No dependency on `msvcrt.dll`. Binary is self-contained. Avoids DLL search-order issues. |
| **GUI subsystem** | No console window on execution. `WinMain` entry point. |
| **XOR domain encryption** | Prevents static string analysis. Key derived from hostname means different machines decrypt to different (wrong) values unless they have the target hostname. |
| **FNV-1a over simple XOR hash** | Better distribution across the 32-bit space. Fewer collisions for similar hostnames. |

---

## 3. Data Flow

### 3.1 Beacon Cycle (Normal Operation)

```
Implant                          Worker                         KV
  │                                │                             │
  │  POST /beacon                  │                             │
  │  {session, recon}              │                             │
  │ ──────────────────────────────►│                             │
  │                                │  PUT session:{sid}          │
  │                                │────────────────────────────►│
  │                                │                             │
  │                                │  GET tasks:{sid}            │
  │                                │────────────────────────────►│
  │                                │◄────────────────────────────│
  │                                │  ["whoami"]                 │
  │                                │                             │
  │                                │  PUT tasks:{sid} = []       │
  │                                │────────────────────────────►│
  │                                │                             │
  │  {"cmd": "whoami"}             │                             │
  │◄──────────────────────────────│                             │
  │                                │                             │
  │  cmd.exe /C whoami             │                             │
  │  ─────► pipe capture           │                             │
  │                                │                             │
  │  POST /result                  │                             │
  │  {session, output}             │                             │
  │ ──────────────────────────────►│                             │
  │                                │  GET results:{sid}          │
  │                                │────────────────────────────►│
  │                                │  append + PUT               │
  │                                │────────────────────────────►│
  │                                │                             │
  │  {"status": "ok"}              │                             │
  │◄──────────────────────────────│                             │
  │                                │                             │
  │  JitterSleep(45, 180)          │                             │
  │  zzz...                        │                             │
```

### 3.2 Operator Task Flow

```
Operator CLI                     Worker                         KV
  │                                │                             │
  │  POST /task                    │                             │
  │  {session, cmd: "whoami"}      │                             │
  │ ──────────────────────────────►│                             │
  │                                │  GET tasks:{sid}            │
  │                                │────────────────────────────►│
  │                                │  push("whoami")             │
  │                                │  PUT tasks:{sid}            │
  │                                │────────────────────────────►│
  │                                │                             │
  │  {"status": "queued"}          │                             │
  │◄──────────────────────────────│                             │
  │                                │                             │
  │  ... waits for next beacon ... │                             │
  │                                │                             │
  │  GET /results/{sid}            │                             │
  │ ──────────────────────────────►│                             │
  │                                │  GET results:{sid}          │
  │                                │────────────────────────────►│
  │                                │◄────────────────────────────│
  │                                │                             │
  │  {results: [{output: "..."}]}  │                             │
  │◄──────────────────────────────│                             │
```

### 3.3 Adaptive Backoff (Failure Mode)

```
Beacon attempt 1: fail → sleep [45, 180]s
Beacon attempt 2: fail → sleep [45, 180]s
...
Beacon attempt 5: fail → backoff triggered
Beacon attempt 6: fail → sleep [135, 540]s  (3× multiplier)
Beacon attempt 7: success → reset to [45, 180]s
```

---

## 4. Protocol Specification

### 4.1 Implant → Server

#### POST /beacon

| Field | Type | Required | Constraints |
|---|---|---|---|
| `session` | string | yes | max 128 chars, format: `{hostname_hash}\|{username}` |
| `recon.hostname` | string | no | computer name |
| `recon.user` | string | no | username |
| `recon.build` | number | no | OS build number |
| `recon.elevated` | boolean | no | admin status |
| `recon.amsi` | boolean | no | AMSI patched |
| `recon.etw` | boolean | no | ETW patched |
| `recon.hwbps` | boolean | no | HW BPs cleared |

Response: `{"cmd": "<command>"}` or `{"cmd": "sleep"}`

#### POST /result

| Field | Type | Required | Constraints |
|---|---|---|---|
| `session` | string | yes | max 128 chars |
| `output` | string | yes | max 65,536 chars (64 KB) |

Response: `{"status": "ok"}`

### 4.2 Operator → Server

#### GET /sessions

Response: array of session objects with `idle_seconds`, `pending_tasks`, `result_count`.

#### POST /task

| Field | Type | Required | Constraints |
|---|---|---|---|
| `session` | string | yes | must exist |
| `cmd` | string | yes | max 4,096 chars |

#### GET /results/{sid}?keep=0|1

Returns `{session, results: [{ts, output}]}`. Clears results unless `keep=1`.

#### DELETE /sessions/{sid}

Queues `exit` at front of task queue.

### 4.3 Authentication

| Header | Used By | Purpose |
|---|---|---|
| `X-Beacon-Token` | Implant | Authenticates beacon/result requests |
| `X-Operator-Token` | CLI | Authenticates operator requests |

Both use constant-time comparison to prevent timing side-channels.

---

## 5. KV Schema

### 5.1 Workers KV Layout

| Key Pattern | Value Type | TTL | Purpose |
|---|---|---|---|
| `session:{sid}` | `SessionData` JSON | Configurable (default 600s) | Session metadata, recon, timestamps |
| `tasks:{sid}` | `string[]` JSON | 86,400s (24h) | Pending command queue (FIFO) |
| `results:{sid}` | `ResultEntry[]` JSON | 86,400s (24h) | Command outputs with timestamps |
| `audit_log` | `AuditEntry[]` JSON | 604,800s (7d) | Operator action audit trail |

### 5.2 Consistency Model

Workers KV is **eventually consistent** with a propagation delay of up to 60 seconds
globally. This means:

- A task queued by the operator may not appear for the implant for up to 60s
- This is acceptable because the beacon interval is 45-180s
- In the worst case, the task is picked up on the next beacon cycle

### 5.3 Size Limits

| Limit | Value |
|---|---|
| Max key size | 512 bytes |
| Max value size | 25 MB |
| Results cap | 500 entries per session |
| Audit log cap | 1,000 entries |

---

## 6. Evasion Technique Catalog

> Techniques are documented here with their detection surface for research purposes.
> Stub implementations exist in the codebase with algorithm descriptions in comments.

### 6.1 Direct Syscalls (T1106)

**Purpose:** Bypass EDR hooks placed on ntdll.dll exports.

**Algorithm:**
1. Open `ntdll.dll` from disk (clean copy, not the hooked in-memory version)
2. Parse PE headers → export directory → find `Nt*` function RVAs
3. Scan for SSN pattern: `4C 8B D1 B8 XX XX XX XX` (mov r10, rcx; mov eax, SSN)
4. Extract the 32-bit immediate (system service number)
5. Allocate RWX memory, write stub: `mov r10, rcx; mov eax, {SSN}; syscall; ret`
6. Store function pointer in `SyscallTable`

**Detection Surface:**
- Memory scanning for RWX regions containing syscall instruction pattern
- ETW `Microsoft-Windows-Threat-Intelligence` provider (kernel)
- Sysmon Event ID 8 (CreateRemoteThread) if used for injection

### 6.2 AMSI Bypass (T1562.001)

**Purpose:** Disable Antimalware Scan Interface for the current process.

**Algorithm:**
1. `LoadLibrary("amsi.dll")`
2. `GetProcAddress("AmsiScanBuffer")`
3. `VirtualProtect` → RWX
4. Overwrite first bytes with `xor eax, eax; ret` (0x33 0xC0 0xC3)

**Detection Surface:**
- ETW provider `Microsoft-Antimalware-Scan-Interface`
- Sysmon Event ID 7 (Image loaded) for amsi.dll
- Integrity checking of amsi.dll .text section
- Windows Defender runtime integrity checks

### 6.3 ETW Bypass (T1562.001)

**Purpose:** Disable Event Tracing for Windows to prevent telemetry.

**Algorithm:**
1. `GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite")`
2. `VirtualProtect` → RWX
3. Overwrite first byte with `ret` (0xC3)

**Detection Surface:**
- Kernel ETW provider audit (if enabled)
- ntdll.dll integrity checking
- Missing telemetry events (absence-based detection)

### 6.4 Hardware Breakpoint Clearing

**Purpose:** Remove analyst-set breakpoints on the implant.

**Algorithm:**
1. `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)`
2. Enumerate all threads in the process
3. For each thread: `GetThreadContext` → zero DR0-DR3, DR6, DR7 → `SetThreadContext`

**Detection Surface:**
- Thread context modification events
- Debugger detection by security products monitoring debug register changes

### 6.5 PPID Spoofing (T1134.004)

**Purpose:** Create child processes under a legitimate parent (e.g., explorer.exe).

**Algorithm:**
1. `OpenProcess` on target parent PID
2. `InitializeProcThreadAttributeList`
3. `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)`
4. `CreateProcess` with `EXTENDED_STARTUPINFO_PRESENT`

**Detection Surface:**
- Sysmon Event ID 1: parent PID mismatch in process tree
- ETW process creation events with cross-reference
- Behavioral analytics on unusual parent-child relationships

### 6.6 WMI Persistence (T1547.003)

**Purpose:** Survive reboots via WMI event subscription.

**Algorithm:**
1. Connect to `ROOT\subscription` WMI namespace
2. Create `__EventFilter` with WQL startup query
3. Create `CommandLineEventConsumer` pointing to implant path
4. Create `__FilterToConsumerBinding` linking filter to consumer

**Detection Surface:**
- Sysmon Event IDs 19, 20, 21 (WMI filter/consumer/binding)
- WMI activity logs in Event Viewer
- `Get-WMIObject -Namespace root\subscription -Class __EventFilter`
- Autoruns detection

### 6.7 Module Stomping (T1055.001)

**Purpose:** Execute code within a legitimately signed DLL's memory space.

**Algorithm:**
1. Open target process
2. Load a legitimate, signed DLL (e.g., `amsi.dll`, `dbghelp.dll`)
3. Parse remote PE to find .text section RVA and size
4. `VirtualProtect` .text to RW
5. Overwrite .text with payload
6. Restore .text to RX
7. Execute via thread creation or DLL export

**Detection Surface:**
- Memory integrity scanning (unbacked executable pages)
- Code signing verification of in-memory module content
- ETW Image Load events with hash mismatch

---

## 7. Operational Security Considerations

### 7.1 Network Layer

| Feature | OPSEC Benefit | Limitation |
|---|---|---|
| Cloudflare Workers | Traffic goes through legitimate CDN IPs | Cloudflare can inspect traffic |
| TLS 1.3 | Encrypted payload, no content inspection | TLS fingerprinting (JA3) can identify WinHTTP |
| User-Agent mimicry | `Microsoft-WNS/10.0` blends with Windows Update | Static UA is fingerprintable over time |
| Jittered beacon | No periodic pattern in network logs | Still generates regular HTTPS POST traffic |
| JSON protocol | Looks like API traffic | POST to `/beacon` is a static path |

### 7.2 Host Layer

| Feature | OPSEC Benefit | Limitation |
|---|---|---|
| Static CRT | No msvcrt.dll dependency | Larger binary size |
| GUI subsystem | No console window | Still visible in Task Manager |
| PE metadata mimicry | Version info looks legitimate | Hash won't match real Microsoft binary |
| Manifest (asInvoker) | Doesn't trigger UAC prompt | Limited to user-level privileges unless elevated |

### 7.3 Known Weaknesses

1. **JA3 fingerprint**: WinHTTP has a distinctive TLS client hello. Detectable at the network perimeter.
2. **Static beacon path**: `/beacon` and `/result` are hardcoded. URL rotation would improve stealth.
3. **No domain fronting**: While traffic goes through Cloudflare, the SNI header reveals the Worker domain.
4. **Single-threaded beacon**: Long-running commands block the beacon loop.
5. **Beacon token is static**: If extracted from the binary, an attacker can impersonate the implant.
6. **XOR encryption is weak**: Key derived from hostname is recoverable. AES-256 would be stronger.
7. **No process migration**: Implant dies if the host process is killed.
8. **cmd.exe execution**: Using `cmd.exe /C` is noisy. Direct API execution would be stealthier.

### 7.4 Detection Signatures

| Detection Method | What It Catches |
|---|---|
| Sysmon Event ID 1 | Process creation (cmd.exe child of ghost.exe) |
| Sysmon Event ID 3 | Network connection to Worker domain |
| Sysmon Event ID 7 | Image load of amsi.dll (AMSI patch trigger) |
| Sysmon Event ID 19-21 | WMI persistence creation |
| Sigma Rule | `win_susp_wmi_persistence` |
| YARA Rule | Byte pattern for syscall stub: `4C 8B D1 B8 ?? ?? ?? ?? 0F 05 C3` |
| Memory Scan | RWX regions containing `syscall` instruction |
| Network IOC | Repeated HTTPS POST to same Cloudflare Worker domain |
| Behavioral | cmd.exe spawned by unsigned binary with no console |

---

## 8. Deployment Topology

### 8.1 Lab Environment

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│                 │     │                  │     │                 │
│  Attacker VM    │     │  Cloudflare      │     │  Target VM      │
│                 │     │  Edge Network    │     │                 │
│  - c2_cli.py    │────►│  - Worker        │◄────│  - ghost.exe    │
│  - Python 3.10+ │     │  - KV Namespace  │     │  - Win 10/11    │
│                 │     │                  │     │  - x64           │
└─────────────────┘     └──────────────────┘     └─────────────────┘
     Operator                  C2 Backend               Implant
```

### 8.2 Deployment Checklist

```
[ ] 1. Create Cloudflare account (free tier works for dev)
[ ] 2. Install wrangler CLI: npm install -g wrangler
[ ] 3. Authenticate: wrangler login
[ ] 4. Create KV namespace: wrangler kv:namespace create GHOST_KV
[ ] 5. Update wrangler.toml with KV namespace ID
[ ] 6. Set secrets:
        wrangler secret put BEACON_TOKEN
        wrangler secret put OPERATOR_TOKEN
[ ] 7. Deploy: cd worker && npm install && wrangler deploy
[ ] 8. Note the worker URL: https://ghost-c2.<your-subdomain>.workers.dev
[ ] 9. Update implant config.hpp / c2.cpp with:
        - Worker domain (XOR-encrypted)
        - Matching BEACON_TOKEN
[ ] 10. Build implant: .\build.ps1
[ ] 11. Configure CLI:
         export GHOST_C2_URL="https://ghost-c2.<subdomain>.workers.dev"
         export GHOST_OPERATOR_TOKEN="<your_operator_token>"
[ ] 12. Verify: python c2_cli.py sessions
```

---

## 9. Comparison: Flask Server vs. Cloudflare Worker

| Dimension | Flask (c2_server.py) | Worker (index.ts) |
|---|---|---|
| **Infrastructure** | Single VPS, single IP | 300+ edge PoPs, Cloudflare IPs |
| **State** | In-memory (lost on restart) | Workers KV (persistent, distributed) |
| **TLS** | Self-signed (must generate) | Automatic (Cloudflare-managed) |
| **Scaling** | Single-threaded Flask | Auto-scaling, per-request isolation |
| **Cost** | VPS cost ($5-20/mo) | Free tier: 100k req/day |
| **Takedown** | IP block kills it | Domain block, but Worker redeploys in seconds |
| **Latency** | Network RTT to VPS | Edge-served, nearest PoP |
| **Logging** | Local file + stdout | `wrangler tail` for real-time logs |
| **Auth** | Token in env var | Token as Worker secret (encrypted at rest) |
| **Use case** | Lab / local testing | Distributed / realistic engagement |

---

## 10. Future Work

| Area | Enhancement | Complexity |
|---|---|---|
| **Protocol** | Add AES-256-GCM encryption layer over JSON | Medium |
| **Protocol** | Rotate beacon paths per session | Medium |
| **Network** | JA3 randomization via custom TLS config | High |
| **Network** | Domain fronting via CDN configuration | Medium |
| **Host** | Sleep obfuscation (encrypt sections before sleep) | High |
| **Host** | Call stack spoofing for syscall returns | High |
| **Host** | Thread pool for concurrent command execution | Medium |
| **Host** | Process migration / injection for persistence | High |
| **Server** | Cloudflare D1 (SQLite) for relational queries | Low |
| **Server** | WebSocket support for real-time operator updates | Medium |
| **CLI** | Tab completion via prompt_toolkit | Low |
| **CLI** | File upload/download commands | Medium |

---

## Appendix A: MITRE ATT&CK Coverage Matrix

| Tactic | Technique | ID | Component |
|---|---|---|---|
| Execution | Native API | T1106 | syscalls.cpp |
| Persistence | WMI Event Subscription | T1547.003 | persistence.cpp |
| Privilege Escalation | Access Token Manipulation | T1134.004 | injection.cpp |
| Defense Evasion | Disable AMSI | T1562.001 | evasion.cpp |
| Defense Evasion | Disable ETW | T1562.001 | evasion.cpp |
| Defense Evasion | Process Injection | T1055.001 | injection.cpp |
| Defense Evasion | Masquerading | T1036.005 | ghost.rc |
| Command & Control | Web Protocols (HTTPS) | T1071.001 | c2.cpp |
| Command & Control | Encrypted Channel | T1573.001 | c2.cpp |
| Command & Control | Application Layer Protocol | T1071.001 | worker/index.ts |

## Appendix B: References

1. MITRE ATT&CK Framework — https://attack.mitre.org/
2. Cloudflare Workers Documentation — https://developers.cloudflare.com/workers/
3. Workers KV — https://developers.cloudflare.com/kv/
4. Direct Syscalls Research — https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/
5. WMI Persistence — https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html
6. Sysmon Configuration — https://github.com/SwiftOnSecurity/sysmon-config
