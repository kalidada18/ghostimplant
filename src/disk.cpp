// disk.cpp — read-only raw disk access (T1006 Direct Volume Access).
//
// Why this module exists at all: the MBR/boot sector is where disk-structure
// wipes and bootkits act (T1561.002, T1542.003), and the *open and read* of the
// raw device is the only half of that behaviour Windows telemetry can see —
// Sysmon event id 9 (RawAccessRead). `!diskread` produces exactly that,
// reproducibly, without destroying anything: one 512-byte sector, GENERIC_READ,
// no write path in the binary.
//
// The write half is a documented gap, not an unfinished feature. Sysmon has no
// raw-write event, so an overwrite emits nothing in the lab's collection
// profile; detecting it needs kernel/EDR driver telemetry. And the lab's own
// boundary from detections/README.md applies unchanged — the high-confidence
// signals never require the payload to actually destroy anything.
//
// Output is written for before/after comparison in the VM: signature, a hex
// line of the first bytes, and the four partition-table entries, so an operator
// who *does* run a destructive trigger by hand (Atomic Red Team, or the VM's
// own tools — never this framework) has a record of what the disk looked like
// before and after.
#include "disk.hpp"

#include <windows.h>          // before config.hpp: it declares DWORD-typed constants

#include "config.hpp"
#include "utils.hpp"
#include "obfuscate.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

namespace {

constexpr DWORD kSectorSize = 512;

std::wstring HexLine(const BYTE* data, size_t len) {
    wchar_t buf[4];
    std::wstring out;
    for (size_t i = 0; i < len; ++i) {
        swprintf_s(buf, L"%02x", data[i]);
        out += buf;
        if ((i & 7) == 7) out += L' ';
    }
    return out;
}

uint32_t ReadLE32(const BYTE* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

std::wstring HandleDiskRead(const std::string& args) {
    if (!IsElevated())
        return L"[error: raw disk access needs an elevated token]";

    ULONGLONG lba = 0;
    if (!args.empty()) {
        try { lba = std::stoull(args); }
        catch (...) { return L"Usage: !diskread [lba]"; }
    }
    LARGE_INTEGER off = {};
    off.QuadPart = static_cast<LONGLONG>(lba) * kSectorSize;

    auto device = XSW(L"\\\\.\\PhysicalDrive0");
    HANDLE h = CreateFileW(device.str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED)
            return L"[error: access denied — run elevated (Administrator or SYSTEM)]";
        return L"[error: CreateFile \\\\.\\PhysicalDrive0 failed, code "
               + std::to_wstring(err) + L"]";
    }
    if (!SetFilePointerEx(h, off, nullptr, FILE_BEGIN)) {
        DWORD err = GetLastError();
        CloseHandle(h);
        return L"[error: seek to LBA " + std::to_wstring(lba)
               + L" failed, code " + std::to_wstring(err) + L"]";
    }

    BYTE sector[kSectorSize] = {};
    DWORD read = 0;
    BOOL ok = ReadFile(h, sector, kSectorSize, &read, nullptr);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);   // read-only handle; closing it is the whole cleanup
    if (!ok || read != kSectorSize)
        return L"[error: read of LBA " + std::to_wstring(lba)
               + L" failed, code " + std::to_wstring(err) + L"]";

    const bool isMbr = (lba == 0);
    std::wstring out = L"[disk] read-only sector dump (T1006 raw volume access)\r\n"
                       L"  device : \\\\.\\PhysicalDrive0  lba=" + std::to_wstring(lba) +
                       L"  bytes=" + std::to_wstring(read) + L"\r\n"
                       L"  first  : " + HexLine(sector, 32) + L"\r\n";

    if (isMbr) {
        const bool sigOk = sector[510] == 0x55 && sector[511] == 0xAA;
        out += L"  mbr sig: ";
        out += sigOk ? L"55 AA (intact)" : L"absent — partition table is not bootable";
        out += L"  (" + HexLine(sector + 510, 2) + L")\r\n";
        out += L"  partitions (type / bootable / start-lba / sectors):\r\n";
        int present = 0;
        for (int i = 0; i < 4; ++i) {
            const BYTE* e = sector + 446 + i * 16;
            const BYTE type = e[4];
            if (type == 0) continue;
            ++present;
            wchar_t line[160];
            swprintf_s(line, L"    [%d] type=0x%02x bootable=%s start=%u sectors=%u\r\n",
                       i, type, (e[0] == 0x80 ? L"yes" : L"no"),
                       ReadLE32(e + 8), ReadLE32(e + 12));
            out += line;
        }
        if (!present) out += L"    (none — empty or non-MBR disk)\r\n";
    }

    out += L"  note: this module has no write path by design; MBR writes (T1561.002/"
           L"T1542.003) emit no Sysmon event and stay a documented gap";
    return out;
}
