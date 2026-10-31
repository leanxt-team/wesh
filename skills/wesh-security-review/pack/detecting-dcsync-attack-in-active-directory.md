---
name: detecting-dcsync-attack-in-active-directory
description: Detect DCSync attacks (MITRE T1003.006) where adversaries abuse Active Directory replication privileges to extract password hashes, by auditing Event ID 4662 for the DS-Replication-Get-Changes GUIDs and flagging non-domain-controller accounts issuing DsGetNCChanges RPC calls.
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
upstream: detecting-dcsync-attack-in-active-directory@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Windows Security Event Logs with Event ID 4662 (Object Access) enabled
- Advanced Audit Policy: Audit Directory Service Access enabled
- Domain Controller event forwarding to SIEM
- Knowledge of legitimate domain controller hostnames and IPs
- Directory Service Access auditing with SACL on domain object

## Workflow

1. **Identify Legitimate Replication Sources**: Document all domain controllers in environment by hostname, IP, and computer account. Only these should perform directory replication.
2. **Enable Required Auditing**: Configure Advanced Audit Policy to capture Event ID 4662 on domain controllers with specific GUID monitoring for replication rights.
3. **Monitor Replication Rights Access**: Track access to three critical GUIDs -- DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2), DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2), and DS-Replication-Get-Changes-In-Filtered-Set (89e95b76-444d-4c62-991a-0facbeda640c).
4. **Detect Non-DC Replication Requests**: Alert when any account NOT associated with domain controller requests replication rights.
5. **Correlate with Network Traffic**: DCSync generates replication traffic (MS-DRSR/RPC) from attacker's machine to DC. Monitor for DrsGetNCChanges RPC calls from non-DC IP addresses.
6. **Investigate Source Context**: Examine process, user account, and machine originating replication request.
7. **Check for Credential Abuse**: After DCSync detection, audit for subsequent use of extracted hashes (pass-the-hash, golden ticket creation).

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1003.006 | OS Credential Dumping: DCSync |
| DCSync | Mimicking domain controller replication to extract credentials |
| DsGetNCChanges | RPC function used to request AD replication data |
| DS-Replication-Get-Changes | AD permission required (GUID: 1131f6aa-...) |
| DS-Replication-Get-Changes-All | Permission including confidential attributes (GUID: 1131f6ad-...) |
| MS-DRSR | Microsoft Directory Replication Service Remote Protocol |
| KRBTGT Hash | Key target of DCSync enabling Golden Ticket attacks |
| Event ID 4662 | Directory service object access audit event |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Mimikatz (lsadump::dcsync) | Primary DCSync attack tool |
| Impacket secretsdump.py | Python-based DCSync implementation |
| DSInternals | PowerShell module for AD replication |
| BloodHound | Map accounts with replication rights |
| Splunk / Elastic | SIEM correlation of 4662 events |
| Microsoft Defender for Identity | Native DCSync detection |
| CrowdStrike Falcon | EDR-based DCSync detection |

## Detection Queries

### Splunk -- DCSync Detection via Event 4662
```spl
index=wineventlog EventCode=4662
| where Properties IN ("*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*",
    "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*",
    "*89e95b76-444d-4c62-991a-0facbeda640c*")
| where NOT match(SubjectUserName, ".*\\$$")
| where NOT SubjectUserName IN ("known_svc_account1", "known_svc_account2")
| stats count values(Properties) as ReplicationRights by SubjectUserName SubjectDomainName Computer
| where count > 0
| table SubjectUserName SubjectDomainName Computer count ReplicationRights
```

### KQL -- Microsoft Sentinel DCSync Detection
```kql
SecurityEvent
| where EventID == 4662
| where Properties has "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    or Properties has "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
| where SubjectUserName !endswith "$"
| where SubjectUserName !in ("AzureADConnect", "MSOL_*")
| project TimeGenerated, SubjectUserName, SubjectDomainName, Computer, Properties
| sort by TimeGenerated desc
```

### Sigma Rule -- DCSync Activity
```yaml
title: DCSync Activity Detected - Non-DC Replication Request
status: stable
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter_dc:
        SubjectUserName|endswith: '$'
    condition: selection and not filter_dc
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-dcsync-attack-in-active-directory
