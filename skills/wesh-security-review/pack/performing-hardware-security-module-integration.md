---
name: performing-hardware-security-module-integration
description: Integrates Hardware Security Modules (HSMs) via the PKCS#11 interface using python-pkcs11, performing key generation, signing, encryption, verification, and token/slot queries against SoftHSM2, AWS CloudHSM, or YubiHSM2.
subdomain: cryptography
facing: config
mitre_attack:
- T1600
- T1573
- T1553
- T1078.004
- T1530
nist_csf:
- PR.DS-01
- PR.DS-02
- PR.DS-10
upstream: performing-hardware-security-module-integration@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- HSM device or software HSM (SoftHSM2 for testing)
- PKCS#11 shared library (.so/.dll) for HSM vendor
- Python 3.9+ with `python-pkcs11`
- Token initialized with SO PIN and user PIN
- For AWS CloudHSM: `cloudhsm-pkcs11` provider configured

## Steps

1. Load PKCS#11 library and enumerate available slots and tokens
2. Open session and authenticate with user PIN
3. Generate RSA 2048-bit or EC P-256 key pairs on HSM
4. Perform signing and verification using on-device keys
5. List all objects (keys, certificates) stored on token
6. Query mechanism list to verify supported algorithms
7. Generate compliance report with key inventory and algorithm audit

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-hardware-security-module-integration
