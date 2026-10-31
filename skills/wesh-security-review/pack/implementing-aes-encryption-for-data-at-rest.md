---
name: implementing-aes-encryption-for-data-at-rest
description: Guides implementing AES-256 encryption in GCM mode (FIPS 197) for files and data stores at rest, covering key derivation, IV/nonce management, and authenticated encryption.
subdomain: cryptography
facing: source
mitre_attack:
- T1600
- T1573
- T1553
- T1486
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: implementing-aes-encryption-for-data-at-rest@54a7988 Apache-2.0, modified by wesh
---
## Codegraph (do this first)
1. `codegraph_explore "crypto usage"` — locate cipher/sign/verify/hash/KDF call sites; `impact` before changing algorithm, mode or key handling. Output = read.
2. Fixing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### AES Modes of Operation

| Mode | Authentication | Parallelizable | Use Case |
|------|---------------|----------------|----------|
| GCM | Yes (AEAD) | Yes | Network data, file encryption |
| CBC | No | Decrypt only | Legacy systems, disk encryption |
| CTR | No | Yes | Streaming encryption |
| CCM | Yes (AEAD) | No | IoT, constrained environments |

### Key Derivation

Never use raw passwords as encryption keys. Always derive keys using:
- **PBKDF2**: NIST-approved, widely supported (minimum 600,000 iterations as of 2024)
- **Argon2id**: Winner of Password Hashing Competition, memory-hard
- **scrypt**: Memory-hard, good alternative to Argon2

### Nonce/IV Management

- GCM requires 96-bit (12-byte) nonce that must NEVER be reused with same key
- Generate nonces using `os.urandom()` (CSPRNG)
- Store nonce alongside ciphertext (it is not secret)

## Workflow

1. Install the `cryptography` library: `pip install cryptography`
2. Generate or derive encryption key
3. Create random nonce for each encryption operation
4. Encrypt data using AES-256-GCM with key and nonce
5. Store nonce + ciphertext + authentication tag together
6. For decryption, extract nonce, verify tag, and decrypt

## Encrypted File Format

```
[salt: 16 bytes][nonce: 12 bytes][ciphertext: variable][tag: 16 bytes]
```

## Security Considerations

- Always use authenticated encryption (GCM, CCM) to prevent tampering
- Never reuse nonce with same key (catastrophic in GCM)
- Use at least 256-bit keys for long-term data protection
- Securely wipe keys from memory after use when possible
- Rotate encryption keys periodically per organizational policy
- For disk-level encryption, consider XTS mode (AES-XTS)

## Validation Criteria

- [ ] AES-256-GCM encryption produces valid ciphertext
- [ ] Decryption recovers original plaintext exactly
- [ ] Authentication tag detects any ciphertext modification
- [ ] Key derivation uses sufficient iterations/parameters
- [ ] Nonces are never reused for same key
- [ ] Large files (>1GB) can be processed via streaming
- [ ] Encrypted file format includes all necessary metadata

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-aes-encryption-for-data-at-rest
