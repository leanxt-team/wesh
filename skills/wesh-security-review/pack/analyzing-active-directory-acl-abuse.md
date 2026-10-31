---
name: analyzing-active-directory-acl-abuse
description: Detect dangerous ACL misconfigurations in Active Directory using ldap3 to identify GenericAll, WriteDACL, and WriteOwner abuse paths
subdomain: identity-security
facing: defense
mitre_attack:
- T1098
- T1098.007
- T1484.001
- T1222.001
- T1078.002
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.AA-06
upstream: analyzing-active-directory-acl-abuse@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9 or later with ldap3 library (`pip install ldap3`)
- Domain user credentials with read access to AD objects
- Network connectivity to Domain Controller on port 389 (LDAP) or 636 (LDAPS)
- Understanding of Active Directory security model and SDDL format

## Steps

1. **Connect to Domain Controller**: Establish LDAP connection using ldap3 with NTLM or simple authentication. Use LDAPS (port 636) for encrypted connections in production.

2. **Query target objects**: Search target OU or entire domain for objects including users, groups, computers, and OUs. Request the `nTSecurityDescriptor`, `distinguishedName`, `objectClass`, and `sAMAccountName` attributes.

3. **Parse security descriptors**: Convert binary nTSecurityDescriptor into its SDDL string representation. Parse each ACE in DACL to extract trustee SID, access mask, and ACE type (allow/deny).

4. **Resolve SIDs to principals**: Map security identifiers (SIDs) to human-readable account names using LDAP lookups against domain. Identify well-known SIDs for built-in groups.

5. **Check for dangerous permissions**: Compare each ACE's access mask against dangerous permission bitmasks: GenericAll (0x10000000), WriteDACL (0x00040000), WriteOwner (0x00080000), GenericWrite (0x40000000), and WriteProperty for specific extended rights.

6. **Filter non-admin trustees**: Exclude expected administrative trustees (Domain Admins, Enterprise Admins, SYSTEM, Administrators) and flag ACEs where non-privileged users or groups hold dangerous permissions.

7. **Map attack paths**: For each finding, document potential attack chain (e.g., GenericAll on user allows password reset, WriteDACL on group allows adding self to group).

8. **Generate remediation report**: Output JSON report with all dangerous ACEs, affected objects, non-admin trustees, and recommended remediation steps.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-active-directory-acl-abuse
