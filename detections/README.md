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
    └── *.yml                  # 19 rules, each tagged to a section 16 technique
```

---

## Validation status — read this before citing anything

**The rules are structurally validated. They are not behaviourally validated.**

`check_coverage.py` proves each rule parses, has a canonical unique UUID, carries
a tactic and technique tag, references only selectors it defines, defines no
selector nothing references, and matches a Sysmon event id the collector config
actually enables. That is a real and useful set of checks: across its first two
runs it caught six defects in these rules — four YAML syntax errors that would
have made the rules unloadable by any Sigma tool, a selector no condition
referenced, and a technique-extraction bug that invented phantom ATT&CK ids out
of the URLs in the README table. Two more were found by re-reading the source
rather than by the tool: a registry arm matching the event's data field when it
meant the value name, and a Defender key path that the implant does not write.

It does **not** prove a rule fires on real telemetry. Nothing here has been run
against a live Sysmon event log. To get that, in rough order of cost:

1. **Parse through a Sigma backend** — `sigma-cli` or `pySigma` converting to
   Splunk/SigmaHQ-Elastic syntax catches field-name and modifier mistakes the
   local gate cannot see.
2. **Replay recorded EVTX** — export `Microsoft-Windows-Sysmon/Operational` from
   a lab VM and run [hayabusa](https://github.com/Yamato-Security/hayabusa) or
   `tac` against the rules. This is the cheapest path to honest per-technique
   hit/miss numbers for the thesis.
3. **Execute harmless triggers** — for the ransom-behaviour rules, Atomic Red
   Team's `T1486` and `T1490` tests write marker files and invoke the recovery
   suppression commands. They produce the telemetry without destroying data,
   which is the point: those two rules are testable without an encryptor.

Record which of these you actually ran next to any coverage number you publish.

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

16 of 32 techniques in the main README's section 16 matrix are covered by a rule.
The other 16 are recorded gaps, and the gate fails if a gap is present but
unstated. Grouped by cause:

| Cause | Techniques | Why no rule |
|---|---|---|
| No host event exists | T1106 | Direct syscalls bypass user-mode hooks; needs a kernel-side sensor |
| No host event exists | T1622, T1480.001, T1056.001, T1113, T1115 | Debug-register writes, `CreateMutexW`, `SetWindowsHookEx`, GDI capture and clipboard reads emit nothing Sysmon collects |
| Not in the enabled channels | T1134.001 | Token duplication/impersonation is not covered by this profile |
| Weakly covered | T1055.004 | APC queue does not raise event id 8; only the access arm may catch it |
| Static, not runtime | T1027, T1070.006 | Obfuscation and compile-timestamp randomization are YARA/PE-analyser problems |
| Network or traffic-analysis layer | T1001.001, T1573.001, T1573.002, T1029 | User-Agent spoofing, an encrypted channel, and beacon periodicity are not single host events |
| Ordinary read-only behaviour | T1497.001, T1497.003, T1005 | Environment enumeration and local data discovery are indistinguishable from normal application behaviour |
| Attribute not carried | T1564.001 | Hidden/system file flags are absent from event id 11 |

The honest reading of that table: **half of what this implant does is invisible to
the standard Windows event pipeline.** That is the most defensible measurement in
the whole project, and it is a statement about telemetry, not about the rules
being good.

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
