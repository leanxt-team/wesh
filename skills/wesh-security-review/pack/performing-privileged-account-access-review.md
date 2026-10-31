---
name: performing-privileged-account-access-review
description: Conducts systematic reviews of privileged accounts to validate access rights, identify excessive or stale permissions, and enforce least privilege across PAM infrastructure.
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
upstream: performing-privileged-account-access-review@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- PAM solution deployed (CyberArk, BeyondTrust, Delinea, or equivalent)
- Identity governance platform (SailPoint, Saviynt, or equivalent)
- Complete inventory of privileged accounts across all platforms
- Defined access review policy with SLAs and escalation procedures
- Designated reviewers (account owners, managers, security team)

## Core Concepts

### Privileged Account Categories

| Category | Examples | Risk Level | Review Frequency |
|----------|----------|------------|-----------------|
| Domain Admins | Enterprise Admin, Domain Admin, Schema Admin | Critical | Monthly |
| Service Accounts | SQL service, backup agents, monitoring agents | High | Quarterly |
| Cloud IAM | AWS root, Azure Global Admin, GCP Owner | Critical | Monthly |
| Database Admin | DBA accounts, sa/sys accounts | High | Quarterly |
| Application Admin | App admin roles, API keys with admin scope | Medium | Semi-annually |
| Emergency/Break-glass | Firecall accounts, emergency access | Critical | After each use |

### Four-Pillar Review Framework

```
DISCOVER                    VALIDATE                    REMEDIATE                 MONITOR
    │                           │                           │                       │
    ├─ Enumerate all            ├─ Verify business          ├─ Remove excess        ├─ Continuous
    │  privileged accounts      │  justification            │  privileges           │  monitoring
    │                           │                           │                       │
    ├─ Identify orphaned        ├─ Confirm account          ├─ Disable orphaned     ├─ Anomaly
    │  accounts                 │  ownership                │  accounts             │  detection
    │                           │                           │                       │
    ├─ Map permissions to       ├─ Check compliance         ├─ Enforce password     ├─ Session
    │  business roles           │  with policies            │  rotation             │  recording
    │                           │                           │                       │
    └─ Classify by risk         └─ Review last usage        └─ Implement JIT        └─ Audit
       level                       and activity                access                  logging
```

## Workflow

### Step 1: Account Discovery and Inventory

Enumerate all privileged accounts across environment:

**Active Directory:**
- Domain Admins, Enterprise Admins, Schema Admins groups
- Accounts with AdminCount=1 attribute
- Service accounts with SPN (Service Principal Names)
- Accounts with delegation rights (Unconstrained/Constrained)

**Cloud Platforms:**
- AWS: IAM users/roles with AdministratorAccess, PowerUserAccess, or `iam:*` permissions
- Azure: Global Administrator, Privileged Role Administrator, Security Administrator roles
- GCP: Owner, Editor roles at organization/project level

**Databases:**
- SQL Server: sysadmin, db_owner, securityadmin fixed roles
- Oracle: DBA, SYSDBA, SYSOPER privileges
- PostgreSQL: superuser, createrole, createdb attributes

### Step 2: Establish Review Criteria

Each privileged account must be evaluated against:

1. **Business Justification**: Does user's current role require this privilege?
2. **Least Privilege**: Can task be performed with lower privileges?
3. **Account Activity**: Has account been active in last 90 days?
4. **Compliance Status**: Does account meet password policy, MFA requirements?
5. **Separation of Duties**: Does access create SoD conflicts?
6. **Ownership**: Is responsible owner assigned and active?

### Step 3: Conduct Review

For each account, designated reviewer must:

1. Review account details, permissions, and last activity date
2. Approve (certify) access if still required with documented justification
3. Revoke access if no longer needed or reviewer cannot justify privilege
4. Flag for investigation if anomalous activity or policy violations are detected
5. Escalate if reviewer cannot make determination

Decision matrix:

| Condition | Action |
|-----------|--------|
| Active user, justified privilege | Certify - maintain access |
| Active user, excessive privilege | Remediate - reduce to least privilege |
| Inactive > 90 days | Disable account, notify owner |
| No owner identified | Disable account, escalate to security |
| SoD conflict detected | Remediate - reassign or add compensating controls |
| Break-glass account | Verify last use was authorized, reset credentials |

### Step 4: Remediation and Enforcement

After reviews are completed:

- Revoke access for accounts that were not certified within SLA period
- Implement automatic revocation for accounts not reviewed within 14 days
- Rotate credentials for all certified privileged accounts
- Convert standing privileges to just-in-time (JIT) access where possible
- Update PAM vault with current account inventory

### Step 5: Reporting and Documentation

Generate review reports including:

- Total accounts reviewed vs. total in scope
- Certification rate (approved vs. revoked)
- Average review completion time
- Overdue reviews and escalations
- Remediation actions taken
- Comparison with previous review cycle

## Validation Checklist

- [ ] Complete inventory of all privileged accounts documented
- [ ] All accounts assigned to responsible owner/reviewer
- [ ] Review criteria and decision matrix defined
- [ ] Reviewers completed certification within SLA (14 days)
- [ ] Revoked accounts disabled and credentials rotated
- [ ] Orphaned accounts identified and disabled
- [ ] Service accounts reviewed for least privilege
- [ ] Break-glass accounts audited for authorized use only
- [ ] Review report generated with metrics and trends
- [ ] Remediation tickets created and tracked to completion
- [ ] Evidence preserved for compliance audit

## References

- [NIST SP 800-53 AC-2: Account Management](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/)
- [CIS Controls v8 - Control 5: Account Management](https://www.cisecurity.org/controls/account-management)
- [Netwrix PAM Best Practices Guide](https://netwrix.com/en/resources/guides/privileged-account-management-best-practices/)
- [StrongDM PAM Best Practices 2025](https://www.strongdm.com/blog/privileged-access-management-best-practices)

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-privileged-account-access-review
