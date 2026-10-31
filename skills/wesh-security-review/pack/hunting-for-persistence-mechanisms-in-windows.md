---
name: hunting-for-persistence-mechanisms-in-windows
description: Systematically hunts for adversary persistence mechanisms across Windows endpoints, covering registry Run/RunOnce keys, services, startup folders, scheduled tasks, and WMI event subscriptions.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1547
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-persistence-mechanisms-in-windows@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Sysmon deployed with Event IDs 12/13/14 (Registry), 19/20/21 (WMI), 1 (Process Creation)
- Windows Security Event forwarding for 4697 (Service Install), 4698 (Scheduled Task)
- EDR with registry and file monitoring capabilities
- PowerShell script block logging enabled (Event ID 4104)
- Autoruns or equivalent baseline of legitimate persistent entries

## Workflow

1. **Enumerate Known Persistence Locations**: Build comprehensive list of Windows persistence points (Run keys, services, scheduled tasks, WMI, startup folder, DLL search order, COM hijacks, AppInit DLLs, Image File Execution Options).
2. **Collect Endpoint Data**: Use EDR, Sysmon, or Velociraptor to collect current persistence artifacts from endpoints across environment.
3. **Baseline Legitimate Persistence**: Compare collected data against known-good baselines (Autoruns snapshots, GPO-deployed entries, SCCM configurations).
4. **Identify Anomalies**: Flag new, unsigned, or unknown entries in persistence locations that deviate from baseline.
5. **Investigate Suspicious Entries**: For each anomaly, examine binary it points to, its digital signature, file hash, and creation timestamp.
6. **Correlate with Process Activity**: Link persistence entries to process execution, network activity, and user login events.
7. **Document and Remediate**: Record findings, remove malicious persistence, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1547.001 | Registry Run Keys / Startup Folder |
| T1543.003 | Windows Service (Create or Modify) |
| T1053.005 | Scheduled Task |
| T1546.003 | WMI Event Subscription |
| T1546.015 | Component Object Model (COM) Hijacking |
| T1546.012 | Image File Execution Options Injection |
| T1546.010 | AppInit DLLs |
| T1547.004 | Winlogon Helper DLL |
| T1547.005 | Security Support Provider |
| T1574.001 | DLL Search Order Hijacking |
| TA0003 | Persistence Tactic |
| Autoruns | Sysinternals tool showing persistent entries |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysinternals Autoruns | Comprehensive persistence enumeration |
| Velociraptor | Endpoint-wide persistence artifact collection |
| CrowdStrike Falcon | Real-time persistence monitoring |
| Sysmon | Registry and WMI event monitoring |
| OSQuery | SQL-based persistence queries |
| RECmd | Registry Explorer for forensic analysis |
| Splunk | SIEM correlation of persistence events |

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-persistence-mechanisms-in-windows
