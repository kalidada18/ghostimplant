#pragma once
#include <string>

// Windows Defender tampering test cases (T1562.001) and posture discovery
// (T1518.001) — implementation in src/defender.cpp.
//
// Command surface (dispatched from the table in src/c2.cpp):
//   !defender status
//   !defender exclude <add|remove> <path|proc|ext> <value>          (registry)
//   !defender exclude <ps-add|ps-remove> <path|proc|ext> <value>    (cmdlet)
//   !defender disable <realtime|behavior|ioav|script|all>
//   !defender asr <add|remove> <path>
//   !defender restore
//
// Every mutating action answers with the posture before and after, so the
// experiment records what changed rather than what was attempted. A block by
// tamper protection is reported as a result, not as an error.
std::wstring HandleDefender(const std::string& args);
