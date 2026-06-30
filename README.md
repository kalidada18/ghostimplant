# GHOST – Windows Implant System Design

## Architecture Overview
GHOST is a single‑file, stageless Windows x64 implant that communicates over HTTPS to a Python C2 server. It uses direct system calls (syscalls) to evade EDR hooks, patches AMSI and ETW in‑process, clears hardware breakpoints, and achieves persistence via WMI event subscriptions. All components are statically linked and avoid suspicious imports.

## Core Components
1. **Direct Syscall Manager** – extracts SSNs from ntdll.dll at runtime and builds custom syscall stubs.
2. **Evasion Stack** – AMSI, ETW, Hardware Breakpoint clearing, PPID spoofing, Defender exclusion.
3. **Injection Module** – unhooked remote process injection and module stomping.
4. **Persistence** – WMI `__EventFilter` + `CommandLineEventConsumer` for boot‑time activation.
5. **C2 Client** – WinHTTP beacon with JSON tasks/results, jitter, and SSL.
6. **Operator CLI** – Python scripts for tasking and result retrieval.

## Data Flow
- Implant beacon sends recon data (hostname, user, build, etc.) to `/beacon`.
- Server responds with a task JSON (e.g., `{"cmd":"whoami"}`) or `{"cmd":"sleep"}`.
- Implant executes command (using `CreateProcess`, `WinExec`, or inline APIs) and posts result to `/result`.
- Results are stored per session and retrieved via CLI.

## Evasion Matrix
| Technique                  | Implementation                                     |
|----------------------------|----------------------------------------------------|
| Direct syscalls            | `mov r10, rcx; mov eax, SSN; syscall; ret`        |
| AMSI bypass                | Patch `AmsiScanBuffer` with `xor eax,eax; ret`    |
| ETW bypass                 | Patch `EtwEventWrite` with `ret`                  |
| Hardware breakpoints       | Zero DR0‑DR3 on all threads via `GetThreadContext`|
| PPID spoofing              | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`             |
| Defender exclusion         | WMI `AddExclusionPath` on `ROOT\Microsoft\Windows\Defender` |
| Module stomping            | Overwrite `.text` of legitimate DLL in remote process |

## Operational Security
- All C2 strings XOR‑encrypted with hostname hash.
- No console window, built as GUI subsystem.
- Static CRT (`/MT`) – no runtime dependencies.
- IAT only contains benign imports; sensitive APIs resolved dynamically.
- Jittered beacon intervals (45‑180s).
- Re‑entrant evasion: AMSI/ETW patches and HW BP clearing repeated each beacon cycle.

## Extensibility
Hooks provided for sleep obfuscation (Ekko/Foliage), keylogger, screenshot, UAC bypass, lateral movement, and credential dumping.

## Build & Deployment
- MSVC 2022, CMake optional.
- `build.bat` compiles with `/O2 /MT /W4`.
- Resource file embeds system‑like version info and manifest.
- Binary can be signed with a stolen certificate for extra stealth.