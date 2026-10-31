---
name: analyzing-ransomware-encryption-mechanisms
description: Analyzes encryption algorithms, key management, and file encryption routines used by ransomware families to assess decryption feasibility, identify implementation weaknesses, and support recovery efforts.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1486
- T1573.001
- T1573.002
- T1027
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: analyzing-ransomware-encryption-mechanisms@54a7988 Apache-2.0, modified by wesh
---
Not for: production data recovery operations without first verifying the decryption method on test copies of encrypted files.

## Prerequisites

- Ghidra or IDA Pro for reverse engineering ransomware binary
- Python 3.8+ with `pycryptodome` library for testing encryption/decryption routines
- Sample encrypted files and their corresponding plaintext originals (known-plaintext pairs)
- Access to ransomware binary (unpacked if applicable)
- Familiarity with symmetric (AES, ChaCha20) and asymmetric (RSA) cryptographic algorithms
- NoMoreRansom.org database for checking existing free decryptors

## Workflow

### Step 1: Identify Encryption Algorithm

Determine which cryptographic algorithm ransomware uses:

```python
# Check for Windows Crypto API usage in imports
import pefile
pe = pefile.PE("ransomware.exe")
crypto_apis = {
    "CryptAcquireContextA": "Windows CryptoAPI",
    "CryptAcquireContextW": "Windows CryptoAPI",
    "CryptGenKey": "Windows CryptoAPI key generation",
    "CryptEncrypt": "Windows CryptoAPI encryption",
    "CryptImportKey": "Windows CryptoAPI key import",
    "BCryptOpenAlgorithmProvider": "Windows CNG (modern crypto)",
    "BCryptEncrypt": "Windows CNG encryption",
    "BCryptGenerateKeyPair": "Windows CNG asymmetric key gen",
}
print("Crypto API Imports:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name and imp.name.decode() in crypto_apis:
            print(f"  {entry.dll.decode()} -> {imp.name.decode()}: {crypto_apis[imp.name.decode()]}")
```

```
Common Ransomware Encryption Schemes:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AES-256-CBC + RSA-2048:    Most common hybrid scheme (LockBit, REvil, Conti)
AES-256-CTR + RSA-4096:    Stream cipher mode variant (BlackCat/ALPHV)
ChaCha20 + RSA-4096:       Modern stream cipher (Hive, Royal)
Salsa20 + ECDH:            Curve25519 key exchange (Babuk)
AES-128-ECB:               Weak mode - potential decryption via known-plaintext
XOR-only:                  Trivial encryption - always recoverable
Custom algorithm:          Often contains implementation flaws
```

### Step 2: Analyze Key Generation and Management

Reverse engineer how encryption keys are generated and stored:

```
Key Management Patterns in Ransomware:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. STRONG (no recovery possible without key):
   - Per-file AES key generated with CryptGenRandom
   - AES key encrypted with embedded RSA public key
   - Encrypted key appended to each file or stored separately
   - RSA private key held only by attacker's C2 server
2. WEAK (potential recovery):
   - AES key derived from predictable seed (timestamp, PID)
   - Same AES key used for all files (single key compromise = full recovery)
   - Key transmitted to C2 before encryption starts (PCAP may contain key)
   - XOR with short repeating key (brute-forceable)
   - PRNG seeded with GetTickCount or time() (limited keyspace)
3. FLAWED IMPLEMENTATION:
   - ECB mode (preserves plaintext patterns)
   - Initialization vector (IV) reuse across files
   - Key stored in plaintext in memory (recoverable from memory dump)
   - Partial encryption (only first N bytes encrypted)
```

### Step 3: Examine File Encryption Routine

Reverse engineer file processing logic:

```c
// Typical ransomware file encryption flow (decompiled pseudo-code from Ghidra):
void encrypt_file(char *filepath) {
    // 1. Check file extension against target list
    if (!is_target_extension(filepath)) return;
    // 2. Generate per-file AES key (32 bytes for AES-256)
    BYTE aes_key[32];
    CryptGenRandom(hProv, 32, aes_key);
    // 3. Generate random IV (16 bytes)
    BYTE iv[16];
    CryptGenRandom(hProv, 16, iv);
    // 4. Read file contents
    HANDLE hFile = CreateFile(filepath, GENERIC_READ, ...);
    BYTE *plaintext = read_entire_file(hFile);
    // 5. Encrypt with AES-256-CBC
    aes_cbc_encrypt(plaintext, file_size, aes_key, iv);
    // 6. Encrypt AES key with RSA public key
    BYTE encrypted_key[256];  // RSA-2048 output
    rsa_encrypt(aes_key, 32, rsa_pubkey, encrypted_key);
    // 7. Write: encrypted_data + encrypted_key + IV to file
    write_file(filepath, encrypted_data, encrypted_key, iv);
    // 8. Rename file with ransomware extension
    rename_file(filepath, strcat(filepath, ".locked"));
}
```

### Step 4: Check for Cryptographic Weaknesses

Test implementation for exploitable flaws:

```python
from Crypto.Cipher import AES
import os
import struct
# Test 1: Check if same key is used for multiple files
# Compare encrypted versions of known files
def check_key_reuse(file1_enc, file2_enc):
    with open(file1_enc, "rb") as f:
        data1 = f.read()
    with open(file2_enc, "rb") as f:
        data2 = f.read()
    # Extract IVs (location depends on ransomware family)
    # If IVs are same and files share encrypted blocks -> same key
    iv1 = data1[-16:]  # Example: IV at end
    iv2 = data2[-16:]
    if iv1 == iv2:
        print("[!] Same IV detected - key reuse likely")
# Test 2: Check for predictable key derivation
# If key is derived from timestamp, iterate possible values
def brute_force_timestamp_key(encrypted_file, known_header, timestamp_range):
    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()
    for ts in timestamp_range:
        # Derive key the same way ransomware does
        import hashlib
        key = hashlib.sha256(str(ts).encode()).digest()
        iv = encrypted_data[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data[:16])
        if decrypted[:len(known_header)] == known_header:
            print(f"[!] Key found! Timestamp: {ts}")
            return key
    return None
# Test 3: Check for ECB mode (pattern preservation)
def check_ecb_mode(encrypted_file):
    with open(encrypted_file, "rb") as f:
        data = f.read()
    # ECB produces identical ciphertext for identical plaintext blocks
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    unique = len(set(blocks))
    total = len(blocks)
    if unique < total * 0.95:
        print(f"[!] ECB mode likely: {total-unique} duplicate blocks out of {total}")
```

### Step 5: Attempt Key Recovery

Use identified weaknesses for key recovery:

```python
# Recovery Method 1: Extract key from memory dump
# Volatility plugin to scan for AES key schedules
# vol3 -f memory.dmp windows.yarascan --yara-rule "aes_key_schedule"
# Recovery Method 2: Known-plaintext attack (weak algorithms)
def xor_key_recovery(encrypted_file, known_plaintext):
    """Recover XOR key from known plaintext-ciphertext pair"""
    with open(encrypted_file, "rb") as f:
        ciphertext = f.read()
    key = bytes(c ^ p for c, p in zip(ciphertext, known_plaintext))
    # Find repeating key length
    for key_len in range(1, 256):
        candidate = key[:key_len]
        if all(key[i] == candidate[i % key_len] for i in range(min(len(key), key_len * 4))):
            print(f"XOR key (length {key_len}): {candidate.hex()}")
            return candidate
    return None
# Recovery Method 3: Check NoMoreRansom for existing decryptors
# https://www.nomoreransom.org/en/decryption-tools.html
```

### Step 6: Document Encryption Analysis

Compile findings into structured report:

```
Analysis should document:
- Algorithm identified (AES, RSA, ChaCha20, custom)
- Key size and mode of operation (CBC, CTR, ECB, GCM)
- Key generation method (CSPRNG, predictable seed, static key)
- Key storage location (appended to file, registry, C2 transmission)
- File modification pattern (full encryption, partial, header-only)
- Targeted file extensions
- Ransom note format and payment infrastructure
- Decryption feasibility assessment (possible/impossible/partial)
- Recommended recovery approach
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Hybrid Encryption** | Combining symmetric (AES) for fast file encryption with asymmetric (RSA) for secure key wrapping; standard ransomware approach |
| **Key Wrapping** | Encrypting per-file symmetric key with attacker's RSA public key so only attacker's private key can decrypt it |
| **ECB Mode** | Electronic Codebook mode encrypts each block independently; preserves patterns in plaintext, critical weakness enabling partial recovery |
| **Known-Plaintext Attack** | Using known original file and its encrypted version to derive encryption key; effective against XOR and weak stream ciphers |
| **Key Schedule** | expanded form of AES key in memory; scannable in memory dumps to recover encryption keys before they are erased |
| **CSPRNG** | Cryptographically Secure Pseudo-Random Number Generator; ransomware using CryptGenRandom produces unpredictable keys |
| **Partial Encryption** | Some ransomware only encrypts first N bytes or every Nth block for speed; unencrypted portions may aid recovery |

## Tools & Systems

- **Ghidra**: Reverse engineering suite for analyzing ransomware encryption routines at assembly level
- **PyCryptodome**: Python cryptographic library for implementing and testing decryption routines
- **NoMoreRansom.org**: Free decryption tool repository maintained by Europol and security vendors for known ransomware families
- **Volatility**: Memory forensics framework for extracting encryption keys from RAM dumps of infected systems
- **CryptoTester**: Tool for identifying cryptographic algorithms based on constants and code patterns

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-ransomware-encryption-mechanisms
