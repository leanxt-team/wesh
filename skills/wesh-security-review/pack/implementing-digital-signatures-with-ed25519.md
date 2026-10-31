---
name: implementing-digital-signatures-with-ed25519
description: Implements digital signatures using the Ed25519 algorithm (Curve25519), covering key-pair generation, signing, signature verification, and security tradeoffs versus RSA and ECDSA.
subdomain: cryptography
facing: source
mitre_attack:
- T1600
- T1573
- T1553
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: implementing-digital-signatures-with-ed25519@54a7988 Apache-2.0, modified by wesh
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

### Ed25519 vs RSA vs ECDSA

| Property | Ed25519 | RSA-3072 | ECDSA P-256 |
|----------|---------|----------|-------------|
| Security | 128-bit | 128-bit | 128-bit |
| Public key size | 32 bytes | 384 bytes | 64 bytes |
| Signature size | 64 bytes | 384 bytes | 64 bytes |
| Key generation | ~50 us | ~100 ms | ~1 ms |
| Sign | ~70 us | ~5 ms | ~200 us |
| Verify | ~200 us | ~200 us | ~500 us |
| Deterministic | Yes | No (PSS) | No (unless RFC 6979) |

### Key Properties

- **Deterministic**: Same message + key always produces same signature
- **Collision-resistant**: No separate hash function needed
- **Side-channel resistant**: Constant-time implementation
- **Small keys**: 32 bytes each (public and private)

## Security Considerations

- Ed25519 does not support key recovery from signatures
- Verify full message, not hash (Ed25519 hashes internally)
- Public keys must be validated before use (check for low-order points)
- Private keys should be stored encrypted at rest
- Ed25519 is not yet approved for all NIST use cases (Ed448 is preferred for federal)

## Validation Criteria

- [ ] Key pair generation produces valid Ed25519 keys
- [ ] Signature verification succeeds for valid message
- [ ] Signature verification fails for tampered message
- [ ] Signature verification fails for wrong public key
- [ ] Deterministic: same input produces same signature
- [ ] File signing and verification works correctly
- [ ] Performance meets or exceeds RSA-3072

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-digital-signatures-with-ed25519
