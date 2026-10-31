---
name: detecting-golden-ticket-attacks-in-kerberos-logs
description: Detect Golden Ticket attacks in Active Directory using Splunk and KQL queries against domain controller event logs, looking for Kerberos TGT anomalies such as mismatched encryption types, impossible ticket lifetimes, non-existent accounts, and forged PAC signatures.
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
upstream: detecting-golden-ticket-attacks-in-kerberos-logs@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Windows Security Event IDs 4768, 4769, 4771 on domain controllers
- Kerberos policy configuration knowledge (max ticket lifetime, encryption types)
- Domain controller audit policy enabling Kerberos Service Ticket Operations
- SIEM with ability to correlate Kerberos events across multiple DCs

## Workflow

1. **Monitor TGT Requests (Event 4768)**: Track Kerberos authentication service requests. Golden Tickets bypass AS-REQ/AS-REP exchange entirely, so absence of 4768 before 4769 is suspicious.
2. **Detect Encryption Type Anomalies**: Golden Tickets often use RC4 (0x17) encryption. If your domain enforces AES (0x12), any RC4 TGT is red flag. Monitor TicketEncryptionType in Event 4769.
3. **Check Ticket Lifetime Anomalies**: Default Kerberos TGT lifetime is 10 hours with 7-day renewal. Golden Tickets can be forged with 10-year lifetimes. Detect tickets with durations exceeding policy.
4. **Hunt for Non-Existent SIDs**: Golden Tickets can include arbitrary SIDs (including non-existent accounts or groups). Correlate TGS requests against known AD SID inventory.
5. **Detect TGS Without Prior TGT**: When service ticket (4769) appears without preceding TGT request (4768) from same IP/account, this may indicate pre-existing Golden Ticket.
6. **Monitor KRBTGT Password Age**: Track when KRBTGT was last reset. If KRBTGT hash hasn't changed since known compromise, Golden Tickets from that period remain valid.
7. **Validate PAC Signatures**: With KB5008380+ and PAC validation enforcement, domain controllers reject forged PACs. Monitor for Kerberos failures indicating PAC validation errors.

## Detection Queries

### Splunk -- RC4 Encryption in Kerberos TGS
```spl
index=wineventlog EventCode=4769
| where TicketEncryptionType="0x17"
| where ServiceName!="krbtgt"
| stats count by TargetUserName ServiceName IpAddress TicketEncryptionType Computer
| where count > 5
| sort -count
```

### Splunk -- TGS Without Prior TGT
```spl
index=wineventlog (EventCode=4768 OR EventCode=4769)
| stats earliest(_time) as first_tgt by TargetUserName IpAddress EventCode
| eventstats earliest(eval(if(EventCode=4768, first_tgt, null()))) as tgt_time by TargetUserName IpAddress
| where EventCode=4769 AND (isnull(tgt_time) OR first_tgt < tgt_time)
| table TargetUserName IpAddress first_tgt tgt_time
```

### KQL -- Golden Ticket Indicators
```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName != "krbtgt"
| summarize Count=count() by TargetUserName, IpAddress, ServiceName
| where Count > 5
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-golden-ticket-attacks-in-kerberos-logs
