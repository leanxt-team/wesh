---
name: implementing-siem-correlation-rules-for-apt
description: Write multi-event correlation rules in Splunk SPL and Sigma format that detect APT lateral movement by chaining Windows authentication events (4624, 4648), process execution (4688, Sysmon Event 1), and network connections (Sysmon Event 3) across hosts within sliding time windows.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1021
- T1550
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-siem-correlation-rules-for-apt@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with security operations concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests pyyaml sigma-cli`
2. Connect to Splunk REST API and define correlation searches that chain multiple event types across hosts.
3. Build Sigma rules in YAML that express multi-step detection logic for lateral movement patterns:
   - RDP logon (4624 LogonType=10) followed by service installation (7045) on same target within 15 minutes
   - Pass-the-Hash: NTLM logon (4624 LogonType=3) followed by process creation (4688) of admin tools
   - PsExec-style: Named pipe creation (Sysmon 17/18) correlated with remote service creation (7045)
4. Convert Sigma rules to Splunk SPL using `sigma-cli convert`.
5. Deploy correlation searches to Splunk ES via REST API.
6. Run agent to generate and install correlation rules, then audit existing rules for coverage gaps.

```bash
python scripts/agent.py --splunk-url https://localhost:8089 --username admin --password changeme --output correlation_report.json
```

## Examples

### Detect RDP Lateral Movement Chain
```
index=wineventlog (EventCode=4624 Logon_Type=10) OR (EventCode=7045)
| transaction Computer maxspan=15m startswith=(EventCode=4624) endswith=(EventCode=7045)
| where eventcount >= 2
| table _time Computer Account_Name ServiceName
```

### Sigma Rule for PsExec Lateral Movement
```yaml
title: PsExec Lateral Movement Detection
logsource:
  product: windows
  service: sysmon
detection:
  pipe_created:
    EventID: 17
    PipeName|startswith: '\PSEXESVC'
  service_installed:
    EventID: 7045
    ServiceFileName|contains: 'PSEXESVC'
  timeframe: 5m
  condition: pipe_created | near service_installed
level: high
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-siem-correlation-rules-for-apt
