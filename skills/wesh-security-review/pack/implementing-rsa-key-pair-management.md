---
name: implementing-rsa-key-pair-management
description: Generates, stores, rotates, and manages RSA key pairs following NIST SP 800-57 guidelines, covering serialization formats (PEM, DER, PKCS#8), passphrase protection, and key strength validation.
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
upstream: implementing-rsa-key-pair-management@54a7988 Apache-2.0, modified by wesh
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

### RSA Key Sizes and Security Strength

| Key Size (bits) | Security Strength (bits) | Recommended Until |
|-----------------|-------------------------|-------------------|
| 2048 | 112 | 2030 |
| 3072 | 128 | Beyond 2030 |
| 4096 | ~140 | Beyond 2030 |

### RSA Padding Schemes

| Scheme | Use Case | Standard |
|--------|----------|----------|
| OAEP | Encryption | PKCS#1 v2.2 (RFC 8017) |
| PSS | Signatures | PKCS#1 v2.2 (RFC 8017) |
| PKCS#1 v1.5 | Legacy only | Deprecated for new systems |

### Key Storage Formats

- **PEM**: Base64-encoded with headers, human-readable
- **DER**: Binary ASN.1 encoding, compact
- **PKCS#8**: Standard for private key encapsulation
- **PKCS#12/PFX**: Bundled key + certificate, password-protected

## Security Considerations

- Minimum 3072-bit keys for new deployments (NIST recommendation)
- Always protect private keys with AES-256-CBC passphrase encryption
- Use RSA-PSS for signatures (not PKCS#1 v1.5)
- Use RSA-OAEP for encryption (not PKCS#1 v1.5)
- Store private keys with restrictive file permissions (0600)
- Implement key rotation at least annually

## Validation Criteria

- [ ] Key generation produces valid RSA key pair
- [ ] Public key can be extracted from private key
- [ ] Private key is protected with passphrase
- [ ] RSA-PSS signature verification succeeds
- [ ] Tampered signature verification fails
- [ ] Key fingerprint is computed correctly
- [ ] Key rotation maintains old key access for verification

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-rsa-key-pair-management
