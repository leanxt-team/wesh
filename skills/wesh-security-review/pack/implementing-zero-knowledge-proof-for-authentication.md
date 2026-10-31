---
name: implementing-zero-knowledge-proof-for-authentication
description: Implements the Schnorr identification protocol and a simplified Zero-Knowledge Password Proof (ZKPP) over the discrete logarithm problem, letting a prover authenticate by demonstrating knowledge of a secret without ever revealing it to the server.
subdomain: cryptography
facing: config
mitre_attack:
- T1600
- T1573
- T1553
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: implementing-zero-knowledge-proof-for-authentication@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### ZKP Properties

| Property | Description |
|----------|------------|
| Completeness | Honest prover always convinces honest verifier |
| Soundness | Dishonest prover cannot convince verifier (except negligible probability) |
| Zero-Knowledge | Verifier learns nothing beyond statement's truth |

### Schnorr Protocol

1. **Setup**: Public generator g, prime p, q (order of g)
2. **Registration**: Prover computes y = g^x mod p (public key from secret x)
3. **Commitment**: Prover sends t = g^r mod p (random r)
4. **Challenge**: Verifier sends random c
5. **Response**: Prover sends s = r + c*x mod q
6. **Verify**: Check g^s == t * y^c mod p

## Security Considerations

- Use cryptographically secure random number generators
- Challenge must be unpredictable (from verifier's perspective)
- For non-interactive proofs, use Fiat-Shamir with collision-resistant hash
- ZKP alone does not provide forward secrecy; combine with TLS

## Validation Criteria

- [ ] Honest prover always verifies successfully (completeness)
- [ ] Random response without secret does not verify (soundness)
- [ ] Server never receives secret value
- [ ] Non-interactive proof is verifiable offline
- [ ] Multiple authentications produce different transcripts
- [ ] Protocol resists replay attacks

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-zero-knowledge-proof-for-authentication
