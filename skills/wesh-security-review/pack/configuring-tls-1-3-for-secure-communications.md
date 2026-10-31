---
name: configuring-tls-1-3-for-secure-communications
description: Configures TLS 1.3 (RFC 8446) on servers, covering cipher suite and key-exchange group selection, and validates the resulting configuration with openssl s_client and testssl.sh.
subdomain: cryptography
facing: config
mitre_attack:
- T1557
- T1040
- T1573.002
- T1539
- T1556.004
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: configuring-tls-1-3-for-secure-communications@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### TLS 1.3 Cipher Suites

| Cipher Suite | Key Exchange | Authentication | Encryption | Hash |
|-------------|-------------|----------------|------------|------|
| TLS_AES_256_GCM_SHA384 | ECDHE/DHE | Certificate | AES-256-GCM | SHA-384 |
| TLS_AES_128_GCM_SHA256 | ECDHE/DHE | Certificate | AES-128-GCM | SHA-256 |
| TLS_CHACHA20_POLY1305_SHA256 | ECDHE/DHE | Certificate | ChaCha20-Poly1305 | SHA-256 |

### TLS 1.3 vs 1.2 Improvements

- **1-RTT Handshake**: Full handshake completes in one round trip (vs 2 in TLS 1.2)
- **0-RTT Resumption**: Resumed connections can send data immediately
- **No RSA Key Exchange**: Only ephemeral Diffie-Hellman (mandatory PFS)
- **Simplified Cipher Suites**: Removed CBC, RC4, 3DES, static RSA, SHA-1
- **Encrypted Handshake**: Server certificate is encrypted after ServerHello

### Key Exchange Groups

- **x25519**: Curve25519 ECDH (preferred, fast)
- **secp256r1**: NIST P-256 ECDH (widely supported)
- **secp384r1**: NIST P-384 ECDH (higher security margin)
- **x448**: Curve448 ECDH (highest security)

## Workflow

1. Verify OpenSSL version supports TLS 1.3 (1.1.1+)
2. Generate or obtain TLS certificate and private key
3. Configure server to use TLS 1.3 cipher suites
4. Disable TLS 1.0 and 1.1 (optionally keep 1.2 for compatibility)
5. Set preferred key exchange groups
6. Enable OCSP stapling for certificate validation
7. Test configuration with openssl s_client and testssl.sh
8. Configure HSTS header for HTTP Strict Transport Security

## Security Considerations

- 0-RTT data is vulnerable to replay attacks; limit to idempotent requests
- Always include TLS 1.2 fallback if legacy client support is required
- Use ECDSA certificates for better performance (vs RSA)
- Enable OCSP stapling to improve client certificate validation
- Set HSTS header with long max-age and includeSubDomains
- Monitor for certificate transparency logs

## Validation Criteria

- [ ] TLS 1.3 handshake completes successfully
- [ ] Only approved cipher suites are offered
- [ ] Perfect forward secrecy is enforced
- [ ] TLS 1.0 and 1.1 are rejected
- [ ] OCSP stapling is functional
- [ ] Certificate chain is valid and complete
- [ ] testssl.sh reports no vulnerabilities

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/configuring-tls-1-3-for-secure-communications
