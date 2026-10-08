# Detection layer

Defensive half of the project: artefacts that observe the techniques the implant
implements, and a gate that stops the coverage claim from drifting away from the
code.

Lab use only, against hosts you own or are contracted to test. Same constraint as
the rest of the repository.

---

## Layout

```
detections/
├── check_coverage.py          # structural + coverage gate (CI job 3)
├── requirements.txt           # PyYAML only; kept out of server/requirements.txt
├── sysmon/
│   └── sysmon-ghost.xml       # collection profile: the event ids these rules need
└── sigma/
    └── *.yml                  # 30 rules, each tagged to a section 16 technique
```

---

## Validation status — read this before citing anything

**The rules are structurally validated. They are not behaviourally validated.**

`check_coverage.py` proves each rule parses, has a canonical unique UUID, carries
a tactic and technique tag, references only selectors it defines, defines no
selector nothing references, and matches a Sysmon event id the collector config
actually enables — with filter tags validated against the documented Sysmon
event table. That is a real and useful set of checks: across its first two
runs it caught six defects in these rules — four YAML syntax errors that would
have made the rules unloadable by any Sigma tool, a selector no condition
referenced, and a technique-extraction bug that invented phantom ATT&CK ids out
of the URLs in the README table. Two more were found by re-reading the source
rather than by the tool: a registry arm matching the event's data field when it
meant the value name, and a Defender key path that the implant does not write.

A pass against the Sysmon documentation on 2026-10-08 found three more that no
local check could see, because the *collector* was wrong the same way the rules
were: the ingress rule matched event id 22 as a file download (22 is `DnsQuery`,
and the config's `<FileDownloadEvent>` is not a Sysmon element at all), the
injection rule's access arm matched event id 25 as process access (25 is
`ProcessTampering`; process access is 10), and the ImageLoad filter used
`ImageName`/`TargetImage`, which are not fields of event id 7. All three are
fixed, the ingress rule keeps its event-11 arms (T1105 coverage survives), and
the DNS lookup the beacon makes now has its own rule. The gate validates every
filter tag against the documented table, so a tag typo cannot pass review again.

It does **not** prove a rule fires on real telemetry. Nothing here has been run
against a live Sysmon event log. To get that, in rough order of cost:

1. ~~**Parse through a Sigma backend**~~ — **run 2026-10-08, see below.** The
   backend caught three real defects the local gate cannot see.
2. **Replay recorded EVTX** — export `Microsoft-Windows-Sysmon/Operational` from
   a lab VM and run [hayabusa](https://github.com/Yamato-Security/hayabusa) or
   `tac` against the rules. This is the cheapest path to honest per-technique
   hit/miss numbers for the thesis.
3. **Execute harmless triggers** — for the ransom-behaviour rules, Atomic Red
   Team's `T1486` and `T1490` tests write marker files and invoke the recovery
   suppression commands. They produce the telemetry without destroying data,
   which is the point: those two rules are testable without an encryptor.

Record which of these you actually ran next to any coverage number you publish.

### Backend validation — sigma-cli run, 2026-10-08

`sigma-cli` 3.1.0 (PySigma 1.5.1) with the Splunk and Elasticsearch backends parses all 19
rules and converts them to queries. It found three real defects the local gate cannot see:
three rules used `Image|notstartswith` / `ParentImage|notstartswith`, and `notstartswith` is
not a Sigma modifier, so pySigma refused to load them. They now express the same logic as a
`|startswith` filter negated in the condition.

The remaining check output is accepted noise, not rule defects:

- 30 × `SpecificInsteadOfGenericLogsourceIssue` — the rules deliberately use
  `service: sysmon` because the lab ships one collector profile (`sysmon-ghost.xml`).
  Backends therefore need `--without-pipeline` or a Sysmon pipeline to convert.
- 18 × `InvalidATTACKTagIssue` — the core validator compares tags against hyphenated,
  recently-renamed ATT&CK tactic names ("defense-impairment") and its bundled technique
  dataset does not include the T1562 family. The SigmaHQ-style `attack.defense_evasion` and
  `attack.t1562.001` tags are correct as written.

Steps 2 and 3 (EVTX replay, harmless triggers) still have not been run — no rule in this
directory has seen a live event log.

### The two rules added with the DoH fallback — 2026-10-08

`command_and_control_doh_resolver_unknown_image.yml` (new matrix row, T1071.004) and
`credential_access_token_access_winlogon.yml` (closes the T1134.001 gap, together with a
`<TargetImage>winlogon.exe</TargetImage>` arm added to the collector) went through the same
checks: the gate passes, `sigma check` reports **0 errors and 0 condition errors** — the same two
accepted noise classes as above, now 52 logsource and 36 tag findings across 30 rules, plus the
pre-existing single low-severity `NumberAsStringIssue` in the Defender-exclusion rule — and both
convert under the Splunk and Lucene/Elasticsearch backends.

What has *not* happened is still steps 2 and 3 for every rule here, the new ones included: no
live EVTX has been replayed, so both are structurally valid and behaviourally unproven. The DoH
rule in particular inherits an honest limitation from the technique itself: it sees the
connection to the resolver, never the name being resolved, because the DNS message rides inside
TLS.

### Defender tampering, same day

`defense_evasion_defender_policy_write.yml` covers the new registry vector in
`src/defender.cpp` — writes to `Policies\Microsoft\Windows Defender`, which the exclusion rule
cannot see because it matches `\Exclusions\` and nothing here goes through the cmdlets. The
collector gained the matching `<TargetObject>` arm, so the gate can verify the rule is
fireable. The cmdlet vectors (`Set-MpPreference`/`Add-MpPreference`, including ASR exclusions)
are deliberately **not** given a new rule: they run through `-EncodedCommand`, so a
`CommandLine`-scoped rule would never fire on this implant and would be detection theatre. That
blind spot is recorded in `GAP_REASONS` as T1518.001, in the gap table above, and in the
section 18 limitations table instead.

### Raw disk access and the disk-wipe boundary, same day

`discovery_direct_volume_access_unknown_image.yml` covers Sysmon EID 9 (`RawAccessRead`) — the
open/read of `\\.\PhysicalDrive0` that `src/disk.cpp` performs to inspect the MBR — and the
collector gained the matching `<RawAccessRead>` arm (previously the event class was not collected
at all, so no rule could have fired).

Deliberately **not** covered: the overwrite. Sysmon has no raw-write event, so MBR/partition-table
corruption (T1561.002) and an MBR bootkit install (T1542.003) emit nothing in this profile. Both
are recorded as gaps above and in `GAP_REASONS`; the implant ships no write path at all, for the
reasons in the main README's section 18. A destructive trigger, if an experiment needs one, is the
operator's own tooling inside a snapshotted offline VM — not a command this framework offers.

### Privilege escalation and credential access, same day

Three rules land with `src/privesc.cpp`, and each one is fireable for a stated reason:
`defense_evasion_uac_bypass_auto_elevate.yml` (the ms-settings handler write is attributed to the
implant's Image even though `!uac` deletes the keys a second later, plus a helper-spawn arm
filtered by non-Windows parent), `persistence_service_user_writable_binary.yml` (keys on the
`ImagePath` *value*, because API-created services are written by services.exe — the writer is not
the signal), and `credential_access_lsass_process_access.yml` (the `0x1010`/`0x1410` masks the
collector now logs for `lsass.exe` via an explicit target arm).

The LSASS rule is worth stating plainly: `!lsass` reads a bounded window, reports statistics and
discards the bytes. No dump file and no credential parser ship with the framework. The rule exists
because EDRs alert on the *access pattern*, and that pattern is what the lab is measuring.

### Lateral movement, same day

Three rules land with `src/lateral.cpp`, and the interesting property is that each keys on the
side of the connection where the evidence survives: the WMI rule uses the `WmiPrvSE.exe` parent
on the target plus TCP 135 on the source, the WinRM rule uses `winrs -r:` on the source and the
`wsmprovhost.exe` parent on the target, and the SMB rule uses the two source command lines
(`net use` with an admin share, `schtasks /S ... /Create`) because a task-scheduler-child arm
would be indistinguishable from every legitimate scheduled task on the host.

All three are *cross-host* rules in practice: they need the collector deployed on both the source
and the target VM. That is stated here because a rule that only ever sees one side of a lateral
movement is a coverage claim that cannot fire, and this directory has a gate against exactly that
class of claim.


### Second stage, same day

No new rule: `!stage` fetches over the channel every rule already sees, and its execution modes
land on rules that exist — remote-thread injection is covered by the injection rule (EID 10 +
EID 8), and in-process execution produces no host event, which the T1055 gap note already
describes. What the stager adds to the *evidence* side is the server-side sequence
(`payload_uploaded` → `payload_downloaded`), so the hunt guidance in the main README points at the
audit trail rather than inventing a rule that could not fire.

---

## Quick start

```powershell
# On the lab VM, elevated. Sysmon is distributed as a zip, so unpack it first.
Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath C:\Sysmon
C:\Sysmon\sysmon64.exe -accepteula -i .\detections\sysmon\sysmon-ghost.xml

# Baseline before the run. epl (not qe) writes a real .evtx, which is what
# hayabusa and tac need; qe /f:text only gives you a readable dump.
wevtutil epl Microsoft-Windows-Sysmon/Operational baseline.evtx

# Gate, any OS, needs only Python
pip install -r detections\requirements.txt
python detections\check_coverage.py --report
```

Score an experiment by snapshotting the event log before and after one technique,
filtering to the window, and checking which rules matched. One technique per run
— that is the entire reason the matrix in the main README exists.

---

## Coverage, as the gate computes it

25 of 43 techniques in the main README's section 16 matrix are covered by a rule.
The other 18 are recorded gaps, and the gate fails if a gap is present but
unstated. Two of the covered techniques (T1029 and T1564.001) are only partially
covered and carry a gap note next to their rule, which is why the table below
lists twenty ids. Grouped by cause:

| Cause | Techniques | Why no rule |
|---|---|---|
| No host event exists | T1106 | Direct syscalls bypass user-mode hooks; needs a kernel-side sensor |
| No host event exists | T1622, T1480.001, T1056.001, T1113, T1115 | Debug-register writes, `CreateMutexW`, `SetWindowsHookEx`, GDI capture and clipboard reads emit nothing Sysmon collects |
| Weakly covered | T1055.004 | APC queue does not raise event id 8, and Sysmon has no thread-open event to match either; only the access arm may catch it |
| Static, not runtime | T1027, T1070.006 | Obfuscation and compile-timestamp randomization are YARA/PE-analyser problems |
| Network or traffic-analysis layer | T1001.001, T1573.001, T1573.002, T1029 | User-Agent spoofing, an encrypted channel, and beacon periodicity are not single host events |
| Ordinary read-only behaviour | T1497.001, T1497.003, T1005 | Environment enumeration and local data discovery are indistinguishable from normal application behaviour |
| Command text is encoded | T1518.001 | The Defender posture read is a `Get-MpComputerStatus` call inside an `-EncodedCommand` PowerShell child: event id 1 carries the blob, not the cmdlet, and script-block logging (4104) is the channel that would recover it |
| Attribute not carried | T1564.001 | Hidden/system file flags are absent from event id 11 |
| No raw-write event exists | T1561.002, T1542.003 | Sysmon event id 9 is RawAccessRead only; the MBR/partition-table overwrite emits nothing, and the boot-chain reads of a bootkit happen before Windows logging exists. The read/open precursor is ruled under T1006; the write is a kernel-sensor problem |

Two gaps closed on 2026-10-08, both by fixing the *collector* rather than the rule count:
T1134.001 is now ruled because `sysmon-ghost.xml` logs process access to `winlogon.exe` (the
implant's own `OpenProcess(winlogon, 0x400)` was never emitted — the full-access masks did not
match), and T1071.004 is a new matrix row for the DoH fallback whose connection to the resolver
is the only host-side signal it produces. The honest reading of the table below is unchanged:
**half of what this implant does is invisible to the standard Windows event pipeline.** That is
the most defensible measurement in the whole project, and it is a statement about telemetry, not
about the rules being good.

---

## Ransomware-behaviour rules specifically

`impact_ransom_note_written_to_user_paths.yml`,
`impact_inhibit_system_recovery.yml` and
`impact_encrypted_file_extension_indicators.yml` detect ransomware behaviour as
families actually exhibit it. Two of the three need nothing from the implant at
all: the note and wallpaper artifact is already produced by the existing
`HandlePrank` handler, and shadow-copy suppression is a command-line artefact.

The implant has no file encryptor and none is planned. That is a deliberate
boundary, not an unfinished feature, and it does not weaken the detection work —
the high-confidence ransomware signals are recovery inhibition, note creation and
rename bursts, none of which require the payload to actually destroy anything to
be detected.

The extension rule is signature-based and its limitation is written into its own
description: it catches known family extensions, not the act of encryption. The
generic detection (a burst of renames in a short window) is a correlation over
many events and belongs in the SIEM, which is why it is not dressed up as a
Sigma rule here.

---

## Adding a rule

1. One rule per file, named by behaviour, in `sigma/`.
2. Tag it with the section 16 technique id it claims. If no row fits, the matrix
   needs a row first.
3. If it matches a Sysmon event id the profile does not enable, add that channel
   to `sysmon/sysmon-ghost.xml`, or the gate will fail it as unfireable.
4. Run `python detections/check_coverage.py --report`. Green means it parses, is
   unique, references only what it defines, and is covered by the collector.
5. If instead you are documenting a hole, add the technique to `GAP_REASONS` in
   `check_coverage.py` with a real reason. "No rule" is not a reason; "no event
   is emitted" is.
