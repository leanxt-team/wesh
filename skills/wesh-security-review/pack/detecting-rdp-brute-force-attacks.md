---
name: detecting-rdp-brute-force-attacks
description: Detect RDP brute force attacks by parsing Windows Security Event Logs (EVTX files, via python-evtx) for failed logon patterns (Event ID 4625, Logon Type 10/3), correlating with successful logons (Event ID 4624), and analyzing NLA failures and source IP frequency.
subdomain: threat-detection
facing: defense
mitre_attack:
- T1021.001
- T1110.001
- T1110.003
- T1078
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
upstream: detecting-rdp-brute-force-attacks@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml` libraries
- Windows Security EVTX log files (exported from Event Viewer or collected via WEF)
- Understanding of Windows authentication Event IDs (4624, 4625, 4776)
- Familiarity with RDP Logon Types (Type 3 for NLA, Type 10 for RemoteInteractive)

## Steps

### Step 1: Export Security Event Logs
Export Windows Security logs to EVTX format using Event Viewer or wevtutil:
```
wevtutil epl Security C:\logs\security.evtx
```

### Step 2: Parse Failed Logon Events
Use python-evtx to parse Event ID 4625 entries, extracting source IP, target username, failure reason (Sub Status), and Logon Type fields.

### Step 3: Analyze Attack Patterns
Identify brute force patterns by:
- Counting failed logons per source IP within time windows
- Detecting username spray attacks (many usernames from one IP)
- Correlating 4625 failures with subsequent 4624 success from same IP

### Step 4: Generate Detection Report
Produce JSON report with top attacking IPs, targeted accounts, time-based analysis, and compromise indicators.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-rdp-brute-force-attacks
