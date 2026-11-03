---
name: performing-active-directory-forest-trust-attack
description: Enumerate and audit Active Directory forest trust relationships using Impacket for SID filtering analysis, trust key extraction, cross-forest SID history abuse detection, and inter-realm Kerberos ticket assessment.
subdomain: red-team
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1558.003
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: performing-active-directory-forest-trust-attack@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Prerequisites

- Python 3.9+ with `impacket`, `ldap3`
- Domain credentials with read access to AD trust objects
- Network access to Domain Controllers (ports 389, 445, 88)
- Authorized penetration testing engagement or lab environment

## Steps

1. Enumerate forest trust relationships via LDAP trusted domain objects
2. Query trust attributes and SID filtering status for each trust
3. Perform SID lookups across trust boundaries using LsarLookupNames3
4. Enumerate foreign security principals in trusted domains
5. Check for SID history on cross-forest accounts
6. Assess trust direction and transitivity for lateral movement paths
7. Generate trust security audit report with risk findings

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-active-directory-forest-trust-attack
