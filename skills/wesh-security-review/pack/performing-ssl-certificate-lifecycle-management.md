---
name: performing-ssl-certificate-lifecycle-management
description: Automates the full SSL/TLS certificate lifecycle, including generating Certificate Signing Requests, issuing, deploying, monitoring, renewing, and revoking X.509 certificates, using Python and ACME protocol tools.
subdomain: cryptography
facing: config
mitre_attack:
- T1600
- T1573
- T1553
- T1040
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: performing-ssl-certificate-lifecycle-management@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### Certificate Lifecycle Stages

1. **Request**: Generate key pair and CSR
2. **Issuance**: CA validates and issues certificate
3. **Deployment**: Install certificate on servers
4. **Monitoring**: Track expiration and health
5. **Renewal**: Request new certificate before expiry
6. **Revocation**: Invalidate compromised certificates

### Certificate Types

| Type | Validation | Use Case |
|------|-----------|----------|
| DV (Domain Validation) | Domain ownership | Websites, APIs |
| OV (Organization Validation) | Domain + org identity | Business sites |
| EV (Extended Validation) | Full legal verification | E-commerce, banking |
| Wildcard | *.domain.com | Multi-subdomain |
| SAN/UCC | Multiple domains | Multi-domain hosting |

## Security Considerations

- Set up automated monitoring for all certificates
- Use ECDSA (P-256) certificates for better performance over RSA
- Enable OCSP stapling on all servers
- Implement Certificate Transparency log monitoring
- Maintain inventory of all certificates and their locations
- Plan for CA compromise scenarios (key pinning, backup CAs)

## Validation Criteria

- [ ] CSR generation produces valid PKCS#10 request
- [ ] Certificate parsing extracts all relevant fields
- [ ] Expiration monitoring detects certificates within threshold
- [ ] Certificate chain validation verifies trust path
- [ ] OCSP checking detects revoked certificates
- [ ] Certificate inventory tracks all deployed certificates

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-ssl-certificate-lifecycle-management
