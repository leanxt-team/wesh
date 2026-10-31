---
name: implementing-end-to-end-encryption-for-messaging
description: Implements a simplified Signal Protocol-style end-to-end encryption scheme for messaging, covering key exchange, forward secrecy, and the core cryptographic components so no server or intermediary can decrypt messages.
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
upstream: implementing-end-to-end-encryption-for-messaging@54a7988 Apache-2.0, modified by wesh
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

### Signal Protocol Components

| Component | Purpose | Algorithm |
|-----------|---------|-----------|
| X3DH | Initial key agreement | X25519 |
| Double Ratchet | Ongoing key management | X25519 + HKDF + AES-GCM |
| Sending Chain | Per-message encryption keys | HMAC-SHA256 chain |
| Receiving Chain | Per-message decryption keys | HMAC-SHA256 chain |
| Root Chain | Derives new chain keys on DH ratchet | HKDF |

### Forward Secrecy

Each message uses unique encryption key derived from ratcheting chain. After key is used, it is deleted, ensuring that compromise of current state does not reveal previously sent/received messages.

## Security Considerations

- Delete message keys immediately after decryption
- Implement message ordering and replay protection
- Use authenticated encryption (AES-GCM) for all messages
- Protect identity keys with device-level security
- Verify identity keys out-of-band (safety numbers)

## Validation Criteria

- [ ] X25519 key exchange produces shared secret
- [ ] Messages encrypt and decrypt correctly between two parties
- [ ] Different messages produce different ciphertexts
- [ ] Forward secrecy: old keys cannot decrypt new messages
- [ ] Out-of-order messages can be decrypted
- [ ] Tampered messages are rejected by authentication

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-end-to-end-encryption-for-messaging
