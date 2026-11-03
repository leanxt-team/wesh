---
name: performing-hash-cracking-with-hashcat
description: Cracks password hashes with Hashcat, covering hash-type identification, dictionary/brute-force/rule-based attack modes, custom rule creation, GPU benchmarking, and password-strength/compliance reporting.
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
upstream: performing-hash-cracking-with-hashcat@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Familiarity with cryptography concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### Hashcat Attack Modes

| Mode | Flag | Description | Use Case |
|------|------|-------------|----------|
| Dictionary | -a 0 | Wordlist attack | Known password patterns |
| Combination | -a 1 | Combine two wordlists | Compound passwords |
| Brute-force | -a 3 | Mask-based enumeration | Short passwords |
| Rule-based | -a 0 -r | Dictionary + transformation rules | Complex variations |
| Hybrid | -a 6/7 | Wordlist + mask | Passwords with appended numbers |

### Common Hash Types

| Hash Mode | Type | Example Use |
|-----------|------|-------------|
| 0 | MD5 | Legacy web apps |
| 100 | SHA-1 | Legacy systems |
| 1000 | NTLM | Windows credentials |
| 1800 | sha512crypt | Linux /etc/shadow |
| 3200 | bcrypt | Modern web apps |
| 13100 | Kerberos TGS-REP | Active Directory |

## Security Considerations

- Only perform hash cracking with explicit written authorization
- Secure all captured hash data in transit and at rest
- Report all cracked passwords immediately to asset owners
- Use results to improve password policies, not exploit users
- Destroy cracked password data after engagement concludes
- Follow rules of engagement for penetration test scope

## Validation Criteria

- [ ] Hash type identification is correct
- [ ] Dictionary attack cracks weak passwords
- [ ] Rule-based attack cracks policy-compliant passwords
- [ ] Mask attack cracks short passwords
- [ ] Results report shows password strength distribution
- [ ] All operations performed within authorized scope

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-hash-cracking-with-hashcat
