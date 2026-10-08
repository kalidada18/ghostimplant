#pragma once
#include <string>

// Lateral movement vectors — src/lateral.cpp.
//
//   !lateral wmi   <host> <command>   remote Win32_Process.Create (T1047)
//   !lateral winrm <host> <command>   WinRS remote shell        (T1021.006)
//   !lateral smb   <host> <command>   admin share + remote scheduled task (T1021.002)
//
// Each vector is the cheapest form of that technique that still produces the
// telemetry its rule keys on: WMI leaves a process parented by WmiPrvSE on the
// target, WinRS leaves a wsmprovhost parent, and the admin-share path leaves
// the net/schtasks command lines on the source. All three authenticate with the
// caller's current token — no credential material is passed around, so a lab
// run needs matching local accounts or a domain.
//
// Nothing is cleaned up implicitly: the scheduled task and the copied file stay
// on the target so the detection can be scored, and the output prints the exact
// revert commands.
std::wstring HandleLateral(const std::string& args);
