#pragma once
#include <string>

// Raw disk access — read-only by construction (implementation: src/disk.cpp).
//
// `!diskread [lba]` opens \\.\PhysicalDrive0 for GENERIC_READ, reads exactly one
// 512-byte sector (sector 0 = the MBR by default) and reports the boot
// signature and partition-table entries.
//
// There is deliberately no write path, no sector-write parameter and no
// "corrupt" variant. The framework must not carry a wiper: it self-installs and
// persists, so destructive code in it is one command away from any machine it
// lands on — and it would produce *zero* measurable telemetry anyway, because
// Sysmon has no raw-write event (event id 9 is RawAccessRead only). See README
// section 18 and GAP_REASONS for T1561.002/T1542.003.
std::wstring HandleDiskRead(const std::string& args);
