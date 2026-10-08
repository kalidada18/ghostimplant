# Design — making the implant and server "real"

Status: Phase 1 (server persistence) **done and verified**; Phase 2 (`simpleserver.sh`) **done and
smoke-tested**; Phase 3 (Defender tampering) **done**: `src/defender.cpp` with posture
before/after on every action, `!defender status|exclude|disable|asr|restore`, one new Sigma rule
for the policy-key vector, and T1518.001 recorded as a documented gap rather than an unfireable
rule. The Defender-log channel work stays explicitly held until the repo owner asks for it.

## Understanding summary

The project owner's direction was: the **implant and the server** should stop being
demo-grade — not more detection tooling, not new emulation scenarios. Three legs:

1. **Server durability.** Sessions, task queues, results, staged payload and the audit
   trail move from process memory into SQLite so a restart no longer discards lab history,
   and the existing re-handshake path recovers live agents.
2. **One-command lab bring-up.** `simpleserver.sh` starts the whole stack (deps check,
   tokens/config, DB init, TLS server, optional tunnel), reports status, and stops cleanly.
3. **Implant Defender tampering**, extended into a full set of ATT&CK-mapped test cases:
   exclusions (registry + PowerShell), monitoring disable, posture reporting, and broader
   vectors — each paired with detection coverage or a stated telemetry gap.

Explicit non-goals: no destructive impact (no quarantine operations, no Defender
uninstall, no signature deletion), no anti-forensics or log tampering, and the repository's
lab-only authorized-use framing is unchanged.

## Assumptions (proposed defaults, in force unless corrected)

- **Scale**: lab-grade — up to ~10 concurrent implants, 1–3 operators. SQLite in WAL mode
  with a single writer is sufficient; no external database.
- **Dependencies**: Python stdlib `sqlite3` only. No ORM, so CI keeps installing just
  `server/requirements.txt`.
- **Performance**: the beacon path must never block on disk I/O; result and audit caps keep
  their current semantics, enforced in SQL.
- **Reliability**: schema versioning via `PRAGMA user_version` with forward migrations; an
  existing in-memory deployment upgrades cleanly on first run.
- **Security**: the DB is a local file with restrictive permissions, documented as not
  encrypted at rest. Tokens come from config/env; nothing secret is committed.
- **CI**: all three existing jobs stay green; the persistence layer gets its own tests.
- **Hosts**: Windows x64 implant (MinGW), server runs on Linux/WSL/Git Bash.

## Decision log

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| 1 | Target "implant + server realism", not detection-validation tooling or emulation scenarios | Detection validation harness; tradecraft breadth; emulation realism | Owner's explicit direction |
| 2 | SQLite as the **source of truth** behind a `server/db.py` repository module; memory only for hot/ephemeral state (locks, ECDH keys) | Write-through cache over existing dicts; full event sourcing | Dual representations are where restart bugs hide; event sourcing is overkill at lab scale, and the audit table already carries the thesis-visible history |
| 3 | All four Defender-tampering vector groups in scope: exclusions (reg + PS), monitoring disable, posture reporting, broader vectors | Subset of vectors | Owner selected all four |
| 4 | Tampering implemented hybrid: native registry for keys/exclusions, `RunFilelessPS` for `*MpPreference` cmdlets, JSON posture collector | PowerShell-only; native-only | PowerShell-only is more detectable and less reliable; native-only cannot express the cmdlet surface |
| 5 | Launcher is **bash only** (`up\|down\|status\|logs\|reset`), PID files + log file | Bash + PowerShell wrapper; Docker Compose | Owner chose bash only |
| 6 | Per-operator identities/RBAC and certificate pinning **deferred** out of this pass | Include now | Not selected in scoping; keeps the pass reviewable |
| 7 | Defender-log channel (windefend rules + gate support) **held** | Implement now | Owner: "will write in last, I will tell you when to write" |
| 8 | Tamper-protection blocking an action is a **first-class measurable result**, not an error | Treat as failure | The blocked attempt is itself the experiment's finding |
| 9 | Session **channel keys stay in memory** while sessions themselves are durable | Persist the key column with the session row | Implemented as designed first, and the protocol suite caught the defect immediately: after a restart the server answered encrypted with the stored (stale) key while advertising the new server point, so the implant re-keyed *before* decrypting that same response and lost a beacon. A restart rotates the keypair; the key is epoch state by construction |
| 10 | The store defaults to `:memory:`; durability is opt-in (`--db`, `GHOST_DB_PATH`, `simpleserver.sh`) | Default to a file (e.g. `ghost.db` in CWD) | Importing the module must have no filesystem side effects — the test suite imports it. The launcher always passes a file, and `main()` prints a warning when no database is configured |
| 11 | Defender cmdlet vectors run through `powershell -EncodedCommand` (reusing `RunFilelessPS`) | Inline `-Command` so a Sysmon `CommandLine` rule can see the cmdlet | Encoded is what the rest of the framework does and what real tooling does; writing a `CommandLine`-scoped rule that can never fire on this implant would be detection theatre. The blind spot is recorded as gap T1518.001 and in the limitations table |
| 12 | `!defender restore` re-enables monitoring and clears the policy values, but never removes exclusions implicitly | Clean up everything on restore | Silently removing an exclusion would erase the artifact the experiment is measuring; the operator removes it explicitly with `exclude remove` |
| 13 | The new toolkit strings (cmdlet names, Defender key paths) are XSW-wrapped but **not yet added to the CI string tripwire** | Add needles now | The local clang/zig artifact keeps four of them in rodata where MinGW-GCC folds comparable sites; since the deciding compiler cannot be run here, the needles are the repo owner's call once CI has spoken |
| 14 | Disk access is **read-only**: `!diskread` inspects one sector; no write path, no corrupt variant. T1561.002/T1542.003 recorded as gaps | Add an MBR-overwrite test case for the VM | Blast radius is only one of three reasons: the framework self-installs and persists, so destructive code in it is one task away from any machine it reaches; a raw write emits **no** event in this profile, so it would add zero measurable value; and the repo's own rule (destruction is never required to validate a detection) applies. The operator runs a destructive trigger with their own VM tooling if an experiment needs one |
| 15 | Sysmon collection gains EID 9 (`RawAccessRead`), previously not collected | Leave it out, document the raw-access precursor as unobservable too | Without the arm, no rule could fire and the T1006 test case would have no telemetry; the arm has OS-noise excludes so lab volume stays usable |
| 16 | Capability set: privilege escalation first, then lateral movement, then an in-memory second stage; LSASS is a read-only test case; the stager fetches through the existing C2 payload path | Standalone bootstrap stager binary; LSASS dump + parser; lateral via credential material | Owner's explicit choices in scoping. The LSASS boundary keeps the framework a test-case generator rather than a credential tool; the stager rides the channel that already exists instead of adding a second delivery model |
| 17 | Lateral vectors authenticate with the caller's token only — no credential handling | Pass-the-hash / explicit credential plumbing | Same technique class needs different, credential-centric plumbing that this project has no detection story for yet; keeps the module reviewable |
| 18 | `!stage` ships three modes (`<pid>` / `self` / `info`) and fetches through the existing `/payload` path | Auto-inject into a spawned host; write the stage to disk first | Remote-thread mode reuses the tested injection chain and lands on an existing rule; `self` exists because the operator may want the no-telemetry case measured, and the risk to the implant is stated in the output rather than hidden; `info` gives the experiment its hash/size record |
| 19 | The dashboard command reference is generated from one JS array (`CMD_REF`) shared with the palette; content mirrors README section 10 | Generate the panel from a server-side spec served over an API | Three consumers of the command surface already exist (C++ table, README, dashboard); a fourth indirection would not remove the sync duty, and a static array keeps the panel working with zero requests. The sync duty is written down in both places instead |

## Design

### 1 — Server persistence (Phase 1)

`server/db.py` owns one SQLite connection (WAL, `synchronous=NORMAL`,
`check_same_thread=False`) guarded by an internal lock. Tables: `sessions`, `tasks`,
`results`, `audit`, `payloads`, plus `meta` for schema version. Endpoints call repository
methods; wire formats are unchanged so the protocol suite keeps passing. On startup:
pending/accepted sessions load live, unacked tasks return to `queued` (at-least-once
survives restart), results and audit are readable, the staged payload survives.
Caps (`result_cap`, `audit_cap`, `task_queue_max`) and the janitor TTL keep their current
semantics, enforced in SQL. `--db` routes through the existing config precedence;
`--db :memory:` preserves today's ephemeral behavior for tests.

### 2 — Defender tampering (Phase 3)

New `src/defender.cpp` + `include/defender.hpp`; commands
`!defender status|exclude|disable|restore`. Posture JSON before/after every action
(real-time state, tamper-protection source, exclusion lists, ASR rules, signature age,
`WinDefend` service state). Sysmon-side detections extended for the new vectors; the
Defender operational log is read for lab evidence but not yet a Sigma channel (decision 7).

### 3 — Launcher (Phase 2)

`simpleserver.sh up` checks Python and imports (installing only with `--install`), generates
tokens/config into a gitignored path on first run, initialises the DB, starts the server
with TLS, optionally starts ngrok when `GHOST_NGROK=1`, prints the operator command and
dashboard URL. `down` stops by PID; `status` probes `/health`; `logs` tails; `reset` wipes
lab state behind a confirmation prompt. Safe defaults: no `--auto-accept`, generated
operator token, no shared secrets.

## Verification plan

- Phase 1: `tests/test_persistence.py` (restart recovery, unacked re-serve, caps, payload,
  audit) wired into CI; existing 34-check protocol suite must stay green; server boot smoke
  test on a file DB.
- Phase 2: `bash -n`, `up`/`status`/`down` smoke test locally.
- Phase 3: zig compile + link locally, MinGW CI job; `sigma check` + conversions for every
  new rule; `check_coverage.py` green.
- Standing caveat: rules remain structurally validated only — no live EVTX has been
  replayed for any rule in this repository.
