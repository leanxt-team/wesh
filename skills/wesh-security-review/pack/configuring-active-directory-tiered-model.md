---
name: configuring-active-directory-tiered-model
description: Implement Microsoft's Enhanced Security Admin Environment (ESAE) tiered administration model for Active Directory, covering Tier 0/1/2 separation, privileged access workstations (PAWs), administrative forest design, and authentication policy silos.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1078.002
- T1550.002
- T1550.003
- T1003.001
- T1021
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
upstream: configuring-active-directory-tiered-model@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Account Management | AC-2 | Lifecycle management |
| Access Enforcement | AC-3 | Policy-based access control |
| Least Privilege | AC-6 | Minimum necessary permissions |
| Audit Logging | AU-3 | Authentication and access events |
| Identification | IA-2 | User and service identification |

## Verification
- [ ] Implementation tested in non-production environment
- [ ] Security policies configured and enforced
- [ ] Audit logging enabled and forwarding to SIEM
- [ ] Documentation and runbooks complete
- [ ] Compliance evidence generated

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/configuring-active-directory-tiered-model
