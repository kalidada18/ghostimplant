#pragma once
#include <string>

// Privilege-escalation and credential-access primitives — src/privesc.cpp.
//
//   !uac <command>                  UAC bypass via the ms-settings auto-elevate
//                                   handler (T1548.002)
//   !service <create|delete|start|stop> <name> [path]
//                                   Windows service create/modify (T1543.003)
//   !lsass                          bounded LSASS access + read statistics (T1003.001)
//
// Every one of these exists to produce the telemetry its detection rule needs:
// the registry hijack, the service key and the process-access event. Two
// deliberate boundaries are documented at the implementation:
//   * !lsass reads and reports statistics only — no dump file and no credential
//     parser ships, because the harvesting step is out of scope for a detection
//     test case;
//   * !service creates and removes services it names itself; it does not touch
//     existing ones unless explicitly asked.
std::wstring HandleUac(const std::string& args);
std::wstring HandleService(const std::string& args);
std::wstring HandleLsass(const std::string& args);
