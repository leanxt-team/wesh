---
name: hunting-for-process-injection-techniques
description: Detects process injection techniques (MITRE T1055) — including CreateRemoteThread injection, process hollowing, and DLL injection — by analyzing Sysmon Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess) alongside EDR process telemetry.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1055
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-process-injection-techniques@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Sysmon installed with Event IDs 8 and 10 enabled
- Process creation logs (Sysmon Event ID 1 or Windows 4688)
- Python 3.8+ with standard library
- JSON-formatted Sysmon event logs

## Steps

1. **Parse Sysmon Events** — Ingest Event IDs 1, 8, and 10 from JSON log files
2. **Detect CreateRemoteThread** — Flag Event ID 8 with suspicious source-target process pairs
3. **Analyze ProcessAccess Rights** — Identify Event ID 10 with dangerous access masks (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD)
4. **Build Process Relationship Graph** — Map source-to-target injection relationships
5. **Filter Known Legitimate Pairs** — Exclude known benign injection patterns (AV, debuggers, system processes)
6. **Score Injection Severity** — Apply risk scoring based on source process, target process, and access rights
7. **Generate Hunt Report** — Produce structured report with MITRE sub-technique mapping

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-process-injection-techniques
