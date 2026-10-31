---
name: configuring-hsm-for-key-storage
description: Configures Hardware Security Modules for cryptographic key storage using the PKCS#11 standard interface, covering key generation, signing, encryption, and key management on physical HSMs and SoftHSM2 for development.
subdomain: cryptography
facing: config
mitre_attack:
- T1552.004
- T1555
- T1078
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: configuring-hsm-for-key-storage@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### HSM Compliance Levels

| FIPS Level | Protection | Use Case |
|-----------|-----------|----------|
| FIPS 140-2 Level 1 | Software only | Development |
| FIPS 140-2 Level 2 | Tamper-evident, role-based auth | General production |
| FIPS 140-2 Level 3 | Tamper-resistant, identity-based auth | Financial, government |
| FIPS 140-2 Level 4 | Physical tamper response | Military, classified |

### PKCS#11 Architecture

```
Application --> PKCS#11 API --> HSM Provider --> Hardware HSM
                                    |
                              (SoftHSM2 for dev)
```

### Key Objects in PKCS#11

| Object Type | Description | Operations |
|-------------|-------------|-----------|
| CKO_SECRET_KEY | Symmetric keys (AES) | Encrypt, Decrypt, Wrap |
| CKO_PUBLIC_KEY | Public keys (RSA, EC) | Verify, Encrypt, Wrap |
| CKO_PRIVATE_KEY | Private keys (RSA, EC) | Sign, Decrypt, Unwrap |
| CKO_CERTIFICATE | X.509 certificates | Storage, retrieval |

## Security Considerations

- Never export private keys from HSM (use CKA_EXTRACTABLE=False)
- Use separate slots/partitions for different applications
- Implement multi-person key ceremony for CA root keys
- Enable audit logging for all HSM operations
- Implement HSM backup and disaster recovery
- Use strong PINs and enable SO (Security Officer) PIN

## Validation Criteria

- [ ] SoftHSM2 initializes with token and user PIN
- [ ] AES key generates inside HSM
- [ ] RSA key pair generates inside HSM
- [ ] Encryption/decryption uses HSM-resident keys
- [ ] Signing/verification uses HSM-resident keys
- [ ] Keys cannot be exported (non-extractable)
- [ ] Key listing shows all HSM-stored objects

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/configuring-hsm-for-key-storage
