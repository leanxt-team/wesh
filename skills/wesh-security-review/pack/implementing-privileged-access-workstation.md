---
name: implementing-privileged-access-workstation
description: Design and implement Privileged Access Workstations (PAWs) using the tiered administration model, with device hardening, device compliance enforcement via Microsoft Intune or Group Policy, just-in-time (JIT) access provisioning, and integration with PAM platforms like CyberArk or BeyondTrust.
subdomain: identity-and-access-management
facing: config
mitre_attack:
- T1078
- T1190
- T1059
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
upstream: implementing-privileged-access-workstation@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Windows 10/11 Enterprise with Virtualization Based Security (VBS)
- Microsoft Intune or Active Directory Group Policy
- CyberArk Privileged Access Security or BeyondTrust Password Safe (optional)
- Python 3.9+ with `requests`, `subprocess`, `json`
- Administrative access to target endpoints

## Steps

1. Audit current privileged access patterns and identify Tier 0/1/2 assets
2. Configure device hardening baselines (AppLocker, Credential Guard, Device Guard)
3. Enforce compliance policies via Intune or GPO
4. Implement just-in-time access with time-limited admin group membership
5. Integrate with CyberArk/BeyondTrust for credential vaulting
6. Validate PAW configuration against CIS and Microsoft PAW guidance
7. Monitor privileged sessions and generate compliance reports

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-privileged-access-workstation
