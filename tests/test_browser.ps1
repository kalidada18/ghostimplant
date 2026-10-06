# Test for the !browser recovery script (tests/browser_dump.ps1).
#
# Builds a SYNTHETIC browser profile in %TEMP% - a Login Data SQLite database
# created via winsqlite3, containing one v10 AES-GCM row and one legacy DPAPI
# row, plus a Local State with a DPAPI-protected master key. No real browser
# data is read or modified. Run: powershell -File tests/test_browser.ps1

$ErrorActionPreference = 'Stop'

# ── 1. Load the library part of browser_dump.ps1 (not the driver) ────────────
$scriptPath = Join-Path $PSScriptRoot 'browser_dump.ps1'
$full = Get-Content -LiteralPath $scriptPath -Raw
$idx = $full.IndexOf('# === DRIVER')
if ($idx -lt 0) { throw 'DRIVER marker not found in browser_dump.ps1' }
Invoke-Expression $full.Substring(0, $idx)

# ── 2. Encryption helper to BUILD synthetic v10 blobs (mirrors DecryptGcm) ───
$encCs = '
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class TestCrypt {
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
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlg, string pszAlgId, string pszImplementation, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptSetProperty(IntPtr hObject, string pszProp, byte[] pbInput, int cbInput, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptGenerateSymmetricKey(IntPtr hAlg, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref AuthInfo pInfo, IntPtr pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptDestroyKey(IntPtr hKey);
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)] private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlg, int dwFlags);

    public static byte[] EncryptGcm(byte[] key, byte[] nonce, byte[] plain) {
        IntPtr hAlg, hKey = IntPtr.Zero;
        if (BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0) != 0) { throw new InvalidOperationException("open failed"); }
        byte[] gcmName = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
        int st = BCryptSetProperty(hAlg, "ChainingMode", gcmName, gcmName.Length, 0);
        if (st == 0) { st = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0); }
        if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); throw new InvalidOperationException("key failed status=0x" + st.ToString("X")); }
        byte[] tag = new byte[16];
        byte[] ct = new byte[plain.Length];
        AuthInfo info = new AuthInfo();
        info.cbSize = Marshal.SizeOf(typeof(AuthInfo));
        info.dwInfoVersion = 1;
        info.pbNonce = Marshal.AllocHGlobal(12);
        Marshal.Copy(nonce, 0, info.pbNonce, 12);
        info.cbNonce = 12;
        info.pbTag = Marshal.AllocHGlobal(16);
        info.cbTag = 16;
        int done = 0;
        st = BCryptEncrypt(hKey, plain, plain.Length, ref info, IntPtr.Zero, 0, ct, ct.Length, out done, 0);
        if (st == 0) { Marshal.Copy(info.pbTag, tag, 0, 16); }
        Marshal.FreeHGlobal(info.pbNonce);
        Marshal.FreeHGlobal(info.pbTag);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (st != 0) { throw new InvalidOperationException("encrypt failed status=0x" + st.ToString("X")); }
        byte[] blob = new byte[3 + 12 + done + 16];
        blob[0] = (byte)118; blob[1] = (byte)49; blob[2] = (byte)48;  // "v10"
        Array.Copy(nonce, 0, blob, 3, 12);
        Array.Copy(ct, 0, blob, 15, done);
        Array.Copy(tag, 0, blob, 15 + done, 16);
        return blob;
    }
}
'
Add-Type -TypeDefinition $encCs

# ── 3. Build the synthetic profile ───────────────────────────────────────────
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('ghosttest_' + [Guid]::NewGuid().ToString('N'))
$prof = Join-Path $root 'Default'
New-Item -ItemType Directory -Path $prof -Force | Out-Null
$db = Join-Path $prof 'Login Data'

$key = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
$dpapiKey = [System.Security.Cryptography.ProtectedData]::Protect(
                $key, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$encKey = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('DPAPI') + $dpapiKey)
$localState = @{ os_crypt = @{ encrypted_key = $encKey } }
Set-Content -LiteralPath (Join-Path $root 'Local State') `
            -Value ($localState | ConvertTo-Json -Depth 5) -Encoding ASCII

[GhostSql]::Query($db, 'CREATE TABLE logins (origin_url TEXT, username_value TEXT, password_value BLOB)', 6) | Out-Null

# Row 1: modern v10 AES-GCM scheme
$nonce = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
$secret1 = [System.Text.Encoding]::UTF8.GetBytes('CorrectHorse1!')
$blob1 = [TestCrypt]::EncryptGcm($key, $nonce, $secret1)
$hex1 = ($blob1 | ForEach-Object { $_.ToString('x2') }) -join ''
[GhostSql]::Query($db, "INSERT INTO logins VALUES ('https://example.test/login', 'alice', X'$hex1')", 6) | Out-Null

# Row 2: legacy plain-DPAPI scheme (pre-v80)
$blob2 = [System.Security.Cryptography.ProtectedData]::Protect(
             [System.Text.Encoding]::UTF8.GetBytes('OldSchoolPass'), $null,
             [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$hex2 = ($blob2 | ForEach-Object { $_.ToString('x2') }) -join ''
[GhostSql]::Query($db, "INSERT INTO logins VALUES ('https://old.test', 'bob', X'$hex2')", 6) | Out-Null

# ── 4. Run the function under test and check results ─────────────────────────
$result = Get-GhostBrowserData $root
$result | ForEach-Object { Write-Host ("  got: " + $_) }

$pass = 0; $fail = 0
function Check($name, $cond) {
    if ($cond) { $script:pass++; Write-Host "  [ok] $name" }
    else       { $script:fail++; Write-Host "  [FAIL] $name" }
}
Check 'v10 GCM row recovered'   (($result -join "`n") -like '*alice | CorrectHorse1!*')
Check 'legacy DPAPI row recovered' (($result -join "`n") -like '*bob | OldSchoolPass*')
Check 'url captured'            (($result -join "`n") -like '*https://example.test/login*')

Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("$pass passed, $fail failed")
if ($fail -gt 0) { exit 1 }
