# Verifies the XSW chunks in HandleBrowser reconstruct tests/browser_dump.ps1 exactly.
src = open('src/c2.cpp', encoding='utf-8').read()
lo = src.find('BROWSER CREDENTIAL RECOVERY')
hi = src.find('STUB HANDLERS')
block = src[lo:hi]
BS = chr(92)

chunks = []
marker = 'XSW(L"'
pos = block.find(marker)
while pos != -1:
    i = pos + len(marker)
    cur = []
    while i < len(block):
        c = block[i]
        if c == BS and i + 1 < len(block):
            cur.append(c); cur.append(block[i + 1]); i += 2; continue
        if c == '"':
            break
        cur.append(c); i += 1
    chunks.append(''.join(cur))
    pos = block.find(marker, i)

def unesc(s):
    out, i = [], 0
    while i < len(s):
        if s[i] == BS and i + 1 < len(s):
            c = s[i + 1]
            if c == 'n':
                out.append(chr(10)); i += 2; continue
            if c == '"':
                out.append('"'); i += 2; continue
            if c == BS:
                out.append(BS); i += 2; continue
        out.append(s[i]); i += 1
    return ''.join(out)

recon = ''.join(unesc(c) for c in chunks)
expected = open('tests/browser_dump.ps1', encoding='utf-8').read()
print('chunks:', len(chunks))
print('round-trip exact match:', recon == expected)
if recon != expected:
    for i, (a, b) in enumerate(zip(recon, expected)):
        if a != b:
            print('first diff at', i)
            print('recon:', repr(recon[max(0, i - 30):i + 30]))
            print('want :', repr(expected[max(0, i - 30):i + 30]))
            break
    else:
        print('length diff:', len(recon), 'vs', len(expected))
