---
name: hunting-for-dcsync-attacks
description: Detect DCSync attacks (MITRE ATT&CK T1003.006) by analyzing Windows Event ID 4662 (AccessMask 0x100) for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All requests issued by non-domain-controller accounts.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1003
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-dcsync-attacks@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Windows Security Event Log forwarding enabled (Event ID 4662)
- Audit Directory Service Access enabled via Group Policy
- Domain Computers SACL configured on Domain Object for machine account detection
- SIEM with Windows event data ingested (Splunk, Elastic, Sentinel)
- Knowledge of legitimate domain controller accounts and replication partners

## Workflow

1. **Enable Auditing**: Ensure Audit Directory Service Access is enabled on domain controllers.
2. **Collect Events**: Gather Windows Event ID 4662 with AccessMask 0x100 (Control Access).
3. **Filter Replication GUIDs**: Search for DS-Replication-Get-Changes and DS-Replication-Get-Changes-All.
4. **Identify Non-DC Sources**: Flag events where SubjectUserName is not domain controller machine account.
5. **Correlate with Network**: Cross-reference source IPs against known DC addresses.
6. **Validate Findings**: Exclude legitimate replication tools (Azure AD Connect, SCCM).
7. **Respond**: Disable compromised accounts, reset krbtgt, investigate lateral movement.

## Key Concepts

| Concept | Description |
|---------|-------------|
| DCSync | Technique abusing AD replication protocol to extract password hashes |
| Event ID 4662 | Directory Service Access audit event |
| DS-Replication-Get-Changes | GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| AccessMask 0x100 | Control Access right indicating extended rights verification |
| T1003.006 | OS Credential Dumping: DCSync |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Windows Event Viewer | Direct event log analysis |
| Splunk | SIEM correlation of Event 4662 |
| Elastic Security | Detection rules for DCSync patterns |
| Mimikatz lsadump::dcsync | Attack tool used to perform DCSync |
| Impacket secretsdump.py | Python-based DCSync implementation |
| BloodHound | Identify accounts with replication rights |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-dcsync-attacks
