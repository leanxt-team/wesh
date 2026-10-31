---
name: implementing-just-in-time-access-provisioning
description: Implements Just-In-Time (JIT) access provisioning to eliminate standing privileges by granting temporary, time-bound access, covering approval workflows, automatic expiration/revocation, and PAM/IGA integration.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1078
- T1110
- T1556
- T1098
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
upstream: implementing-just-in-time-access-provisioning@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with identity access management concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Key Concepts

### JIT Access Models
1. **Broker and Remove**: Grant access through approval, auto-remove after time window
2. **Elevation on Demand**: User has base access, elevates to privileged upon request
3. **Account Creation/Deletion**: Temporary account created, destroyed after use
4. **Group Membership Toggle**: Add to privileged group temporarily, auto-remove

### Zero Standing Privilege (ZSP) Principle
- No user has permanent privileged access
- All privileged access requires explicit request with business justification
- Access automatically expires after defined time window
- All access events logged and auditable

## Workflow

### Step 1: Identify Eligible Access Types
- Privileged admin access (domain admin, root, DBA)
- Production environment access
- Sensitive data access (PII, financial, healthcare)
- Emergency/break-glass access
- Third-party vendor access

### Step 2: Design Approval Workflows
- Self-service request portal with justification requirement
- Auto-approve for pre-authorized low-risk access (< 1 hour)
- Single approver for medium-risk (manager or resource owner)
- Dual approval for high-risk (manager + security team)
- Emergency bypass with post-facto review

### Step 3: Implement Time-Bound Access
- Configure maximum access duration per resource type
- Implement countdown timer with extension request capability
- Auto-revoke at expiration regardless of session state
- Grace period notification (15 min before expiry)
- Automatic session termination on access expiry

### Step 4: Integration Architecture
- Connect to IAM/IGA platform for provisioning/de-provisioning
- Integrate with PAM for privileged credential checkout
- Connect to ITSM for ticket correlation
- Forward events to SIEM for monitoring
- API integration for programmatic access requests

### Step 5: Monitoring and Compliance
- Log all JIT requests, approvals, grants, and revocations
- Alert on access used beyond approved scope
- Track access not used (request but never connected)
- Measure mean time to access (request to grant)
- Report on access patterns for baseline optimization

## Security Controls
| Control | NIST 800-53 | Description |
|---------|-------------|-------------|
| Temporary Access | AC-2(2) | Automated temporary account management |
| Least Privilege | AC-6 | Time-bound minimum access |
| Access Enforcement | AC-3 | Automated access grant/revoke |
| Audit | AU-3 | Complete JIT access audit trail |
| Risk Assessment | RA-3 | Risk-based approval routing |

## Common Pitfalls
- Setting time windows too long, negating JIT benefits
- Not implementing automatic revocation at expiration
- Complex approval workflows causing access delays for legitimate needs
- Not providing emergency bypass for critical incidents
- Failing to audit approved but unused JIT access

## Verification
- [ ] JIT request workflow functional end-to-end
- [ ] Access automatically revoked at expiration
- [ ] Approval routing correct for all risk levels
- [ ] Emergency access bypass works with post-review
- [ ] All JIT events logged to SIEM
- [ ] Standing privileges reduced by measurable percentage
- [ ] Mean time to access meets business SLA

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-just-in-time-access-provisioning
