#!/usr/bin/env python3
"""
Structural and coverage gate for the GHOST detection artifacts.

Three jobs, in order of how much they matter:

1. Coverage honesty. Every technique row in README section 16 must either have
   at least one Sigma rule that claims its ATT&CK id, or appear in GAP_REASONS
   below with a stated reason it cannot be detected from Sysmon/Windows-event
   telemetry. A blank is not allowed to stay blank silently. This is the whole
   point of the file: an unacknowledged coverage gap in a detection-research
   thesis is the same failure as a fabricated result.

2. Rule validity. Required fields, UUID-format unique ids, allowed status and
   level values, at least one tactic and one technique tag, and every
   identifier referenced in a `condition` must actually be defined in that
   rule's `detection` block. That last check catches real copy-paste bugs where
   a filter was renamed but the condition still points at the old key.

3. Collection-layer sanity. detections/sysmon/sysmon-ghost.xml must be
   well-formed XML, must enable every event id the rules depend on, and must
   only use real Sysmon filter tags. A rule matching EventID 7 is dead on
   arrival if the config never includes ImageLoad; an element named
   <FileDownloadEvent> is not a Sysmon event at all (22 is DnsQuery) and would
   be silently inert.

Usage:
    pip install -r detections/requirements.txt
    python detections/check_coverage.py            # gate, for CI
    python detections/check_coverage.py --report   # also print the matrix

Exit codes: 0 clean, 1 findings, 2 PyYAML missing (the gate is skipped, never
faked - a silently weaker checker is worse than no checker).
"""
from __future__ import annotations

import argparse
import re
import sys
import uuid as uuidlib
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import yaml
except ImportError:
    print("[!] PyYAML is not installed. Run: pip install -r detections/requirements.txt")
    print("    Refusing to fall back to a weaker check.")
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "detections" / "sigma"
SYSMON_XML = ROOT / "detections" / "sysmon" / "sysmon-ghost.xml"
README = ROOT / "README.md"

REQUIRED_KEYS = (
    "title", "id", "status", "description", "references",
    "author", "date", "tags", "logsource", "detection", "level",
)
ALLOWED_STATUS = {"stable", "experimental", "deprecated", "test"}
ALLOWED_LEVEL = {"critical", "high", "medium", "low", "informational"}

# Documented Sysmon event id -> EventFiltering tag, from the "Events" and
# "Event filtering entries" tables in Microsoft's Sysmon documentation. Ids 4
# and 16 cannot be filtered and have no tag. This table was previously kept by
# hand from memory, which is how "EID 22 = file download" and
# "EID 25 = process access" shipped: both plausible, both wrong, both leaving a
# rule that could never fire.
SYSMON_TAG_BY_EID = {
    1: "ProcessCreate", 2: "FileCreateTime", 3: "NetworkConnect",
    5: "ProcessTerminate", 6: "DriverLoad", 7: "ImageLoad",
    8: "CreateRemoteThread", 9: "RawAccessRead", 10: "ProcessAccess",
    11: "FileCreate", 12: "RegistryEvent", 13: "RegistryEvent",
    14: "RegistryEvent", 15: "FileCreateStreamHash", 17: "PipeEvent",
    18: "PipeEvent", 19: "WmiEvent", 20: "WmiEvent", 21: "WmiEvent",
    22: "DnsQuery", 23: "FileDelete", 24: "ClipboardChange",
    25: "ProcessTampering", 26: "FileDeleteDetected",
    27: "FileBlockExecutable", 28: "FileBlockShredding",
    29: "FileExecutableDetected",
}
SYSMON_TAGS = set(SYSMON_TAG_BY_EID.values())

# Techniques with no rule, and why. Every uncovered technique in README
# section 16 MUST be listed here or the gate fails.
GAP_REASONS = {
    "T1106": "Direct syscalls bypass user-mode API hooks entirely; Sysmon emits no event. Needs an EDR sensor (kernel callbacks) or syscall-depth tracing.",
    "T1027": "Obfuscated strings, hashed imports and a stripped PE header are static properties. Correct tool is YARA or a PE analyzer, not a SIEM rule.",
    "T1070.006": "Compile-timestamp randomization happens at build time; no runtime telemetry exists on the host.",
    "T1001.001": "User-Agent and protocol impersonation is only observable in network metadata, not host telemetry. Belongs to a TLS/Zeek-side analysis.",
    "T1573.001": "Aes-Gcm/Ecdh channel encryption is not a host event. The wire being unreadable is the technique; detecting it means detecting the process, covered elsewhere.",
    "T1573.002": "Same as T1573.001.",
    "T1029": "Jittered beacon periodicity requires a traffic-interval analysis over time, not a single event match. Documented as a measurement task in the beacon rule's falsepositives.",
    "T1497.001": "Sandbox/environment checks are ordinary read-only enumeration (process list, registry query). No distinguishing telemetry.",
    "T1497.003": "Same enumeration path as T1497.001.",
    "T1480.001": "CreateMutexW for a single-instance guard produces no Sysmon event.",
    "T1622": "Debug-register writes to clear hardware breakpoints are not surfaced by Sysmon; requires a kernel-side sensor.",
    "T1056.001": "SetWindowsHookEx(WH_KEYBOARD_LL) is a user32 call with no ETW provider behind it. EDR-only.",
    "T1113": "Screen capture via GDI/BitBlt emits no host event.",
    "T1115": "OpenClipboard/GetClipboardData emits no host event.",
    "T1564.001": "Hidden/system file attributes are visible only via the attribute flags, which the open-sysmon schema does not carry in event id 11. Partial: the file-create itself is ruled.",
    "T1055.004": "APC injection queues via NtQueueApcThread on an OpenThread handle: Sysmon has no thread-open event at all (event id 25 is ProcessTampering, a different class) and event id 8 fires only for CreateRemoteThread. The injection rule's EID 10 access arm is the only host-side signal, and it catches the OpenProcess step, not the queue.",
    "T1005": "Data from local system is ordinary read-only file and registry enumeration by a process already running as the user. There is no event that distinguishes it from normal application behaviour; it is detected through its downstream artefacts (staging archive creation, exfil volume), not as a technique in its own right.",
    "T1518.001": "Defender posture reads (Get-MpComputerStatus / Get-MpPreference) run inside an -EncodedCommand PowerShell child, so Sysmon event id 1 carries the encoded blob rather than the cmdlet text. The process creation itself is covered by the hidden-window rule; recovering which cmdlet ran needs PowerShell script-block logging (4104), which is not part of this Sysmon-only profile.",
    "T1561.002": "The MBR/partition-table overwrite itself emits nothing: Sysmon event id 9 is RawAccessRead, and there is no raw-write event at all, so a disk wipe is invisible in this profile. Detecting it needs kernel/EDR driver telemetry or VM/hardware-side monitoring. The lab ships no write path on purpose (src/disk.cpp is read-only by construction); the read/open precursor is covered by the T1006 rule instead.",
    "T1542.003": "An MBR bootkit is the same raw write to the same device as T1561.002, and the boot-chain reads that follow happen before any Windows logging exists. Same telemetry hole as T1561.002: no Sysmon event, needs a kernel sensor. The read precursor is ruled under T1006; the write and the persistence are not observable here.",
}

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TECHNIQUE_IN_TAG = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$")
TECHNIQUE_IN_TEXT = re.compile(r"T\d{4}(?:\.\d{3})?")
COND_STOPWORDS = {"and", "or", "not", "of", "them", "all", "any", "keys", "value"}


def load_rules():
    """Return (rules, problems). Rules are (path, parsed) tuples."""
    problems, rules = [], []
    seen_ids: dict[str, Path] = {}
    if not SIGMA_DIR.is_dir():
        return [], [f"missing directory {SIGMA_DIR}"]
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            problems.append(f"{path.name}: YAML parse error: {exc}")
            continue
        if not isinstance(doc, dict):
            problems.append(f"{path.name}: top level is not a mapping")
            continue
        rules.append((path, doc))

        for key in REQUIRED_KEYS:
            if key not in doc:
                problems.append(f"{path.name}: missing required key '{key}'")

        rid = str(doc.get("id", ""))
        if rid and not UUID_RE.match(rid):
            problems.append(f"{path.name}: id '{rid}' is not a lowercase UUID")
        elif rid:
            try:
                parsed = uuidlib.UUID(rid)
            except ValueError:
                problems.append(f"{path.name}: id '{rid}' is not a valid UUID")
            else:
                if str(parsed) != rid:
                    problems.append(f"{path.name}: id '{rid}' is not canonical (str() gives '{parsed}')")
            if rid in seen_ids:
                problems.append(f"{path.name}: duplicate id also used by {seen_ids[rid].name}")
            else:
                seen_ids[rid] = path

        if doc.get("status") not in ALLOWED_STATUS:
            problems.append(f"{path.name}: status '{doc.get('status')}' not in {sorted(ALLOWED_STATUS)}")
        if doc.get("level") not in ALLOWED_LEVEL:
            problems.append(f"{path.name}: level '{doc.get('level')}' not in {sorted(ALLOWED_LEVEL)}")

        tags = doc.get("tags") or []
        if not isinstance(tags, list) or not tags:
            problems.append(f"{path.name}: tags must be a non-empty list")
            tags = []
        tech = [t for t in tags if TECHNIQUE_IN_TAG.match(str(t))]
        tact = [t for t in tags if str(t).startswith("attack.") and not TECHNIQUE_IN_TAG.match(str(t))]
        if not tech:
            problems.append(f"{path.name}: no attack.tNNNN technique tag")
        if not tact:
            problems.append(f"{path.name}: no attack tactic tag")

        # Every name used in condition must be defined in detection.
        det = doc.get("detection")
        if not isinstance(det, dict):
            problems.append(f"{path.name}: detection must be a mapping")
        else:
            cond = det.get("condition")
            if not isinstance(cond, str) or not cond.strip():
                problems.append(f"{path.name}: detection.condition missing")
            else:
                defined = {k for k in det if k != "condition"}
                used = {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cond)
                        if t not in COND_STOPWORDS}
                for name in sorted(used - defined):
                    problems.append(
                        f"{path.name}: condition references undefined selector '{name}' "
                        f"(defined: {sorted(defined)})")
                # An arm that no condition mentions can never fire. This caught a
                # real dead selector in the ransom-note rule, written as
                # `(A and B) or B`, which reduces to B.
                for name in sorted(defined - used):
                    problems.append(
                        f"{path.name}: selector '{name}' is defined but never "
                        f"referenced by condition, so it cannot match")
                if used & defined and not (used - COND_STOPWORDS):
                    pass

        refs = doc.get("references")
        if not isinstance(refs, list) or not refs:
            problems.append(f"{path.name}: references must be a non-empty list")
        else:
            ref_text = " ".join(str(r) for r in refs)
            for t in tech:
                tid = "T" + TECHNIQUE_IN_TAG.match(t).group(1)
                dotted = tid.replace(".", "/")
                if tid.split(".")[0] not in ref_text.replace(".", ""):
                    # tolerate T1546.003 -> .../T1546/003/ as well as bare ids
                    if dotted not in ref_text and tid not in ref_text:
                        problems.append(
                            f"{path.name}: technique tag {tid} has no matching reference URL")
    return rules, problems


def readme_techniques():
    """Technique ids from the README section 16 table, in table order."""
    text = README.read_text(encoding="utf-8")
    section = re.search(r"^## 16\. MITRE ATT&CK mapping$(.*?)^---$", text,
                        re.M | re.S)
    if not section:
        return []
    ids = []
    for line in section.group(1).splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] in ("Technique", "---"):
            continue
        # The cell is markdown: `[T1071.001](https://attack.mitre.org/techniques/T1071/001/)`.
        # Matching the raw cell also hits the `T1071` inside the URL and
        # invents a phantom parent technique for every sub-technique row, which
        # then shows up as an unexplained coverage gap. Drop link targets first.
        label = re.sub(r"\]\([^)]*\)", "]", cells[1])
        for tid in TECHNIQUE_IN_TEXT.findall(label):
            if tid not in ids:
                ids.append(tid)
    return ids


def rule_techniques(rules):
    covered: dict[str, list[str]] = {}
    for path, doc in rules:
        for t in (doc.get("tags") or []):
            m = TECHNIQUE_IN_TAG.match(str(t))
            if m:
                covered.setdefault("T" + m.group(1), []).append(path.name)
    return covered


def check_sysmon(rules):
    problems = []
    if not SYSMON_XML.is_file():
        return [f"missing {SYSMON_XML}"]
    raw = SYSMON_XML.read_text(encoding="utf-8")
    # ElementTree does not resolve external entities but is still exposed to
    # entity-expansion exhaustion. This input is our own committed config rather
    # than attacker-supplied data, so a cheap refusal to parse any DTD is
    # proportionate: a Sysmon config has no legitimate reason to declare one.
    if re.search(r"<!DOCTYPE|<!ENTITY", raw, re.I):
        return ["sysmon-ghost.xml declares a DTD or entity - refusing to parse it"]
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return [f"sysmon-ghost.xml is not well-formed XML: {exc}"]
    if root.tag != "Sysmon":
        problems.append("sysmon-ghost.xml root element is not <Sysmon>")

    # Every filter tag must be a real Sysmon event tag. A typo here is silent:
    # Sysmon rejects the config or ignores the element, and a rule written
    # against that event never fires. <RuleGroup> is a wrapper, not a filter.
    tags: set[str] = set()

    def collect_filters(el):
        for child in el:
            if child.tag == "RuleGroup":
                collect_filters(child)
            else:
                tags.add(child.tag)
                if child.tag not in SYSMON_TAGS:
                    problems.append(
                        f"sysmon-ghost.xml uses <{child.tag}>, which is not a "
                        f"Sysmon event filter tag - that element can never match")

    filtering = root.find("EventFiltering")
    if filtering is None:
        problems.append("sysmon-ghost.xml has no <EventFiltering> section")
    else:
        collect_filters(filtering)

    needed: dict[str, set[str]] = {}
    for path, doc in rules:
        det = doc.get("detection") or {}
        for name, body in det.items():
            if not isinstance(body, dict):
                continue
            eid = body.get("EventID")
            eids = {eid} if isinstance(eid, int) else set(eid or [])
            for e in eids:
                if e not in SYSMON_TAG_BY_EID:
                    problems.append(
                        f"{path.name}: EventID {e} is not a filterable Sysmon "
                        f"event id (documented table covers 1-29 minus 4 and 16)")
                    continue
                needed.setdefault(SYSMON_TAG_BY_EID[e], set()).add(str(e))
    for channel, eids in sorted(needed.items()):
        if channel not in tags:
            problems.append(
                f"rules match Sysmon event id(s) {sorted(eids, key=int)} but "
                f"sysmon-ghost.xml has no <{channel}> filter - those rules can never fire")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", action="store_true", help="print the coverage matrix")
    args = ap.parse_args()

    rules, problems = load_rules()
    problems += check_sysmon(rules)

    matrix = readme_techniques()
    covered = rule_techniques(rules)

    unruled = [t for t in matrix if t not in covered]
    unacknowledged = [t for t in unruled if t not in GAP_REASONS]
    stale = [t for t in GAP_REASONS if t not in matrix and t not in covered]

    for t in unacknowledged:
        problems.append(f"README section 16 lists {t} but no rule covers it "
                        f"and GAP_REASONS does not explain the gap")
    for t in stale:
        problems.append(f"GAP_REASONS mentions {t} which is in neither the README matrix nor any rule")

    print(f"rules parsed      : {len(rules)}")
    print(f"README techniques : {len(matrix)}")
    print(f"covered by rule   : {len(matrix) - len(unruled)}/{len(matrix)}")
    print(f"documented gaps   : {len([t for t in unruled if t in GAP_REASONS])}")
    print(f"unacknowledged    : {len(unacknowledged)}")

    if args.report:
        print("\nper-technique coverage")
        for t in matrix:
            if t in covered:
                print(f"  {t:<12} ruled     {', '.join(sorted(set(covered[t])))}")
            elif t in GAP_REASONS:
                print(f"  {t:<12} gap       {GAP_REASONS[t]}")
            else:
                print(f"  {t:<12} MISSING   no rule and no stated reason")
        print()

    if problems:
        print(f"\n[!] {len(problems)} finding(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\n[ok] detection artifacts structurally valid and coverage is fully accounted for")
    return 0


if __name__ == "__main__":
    sys.exit(main())
