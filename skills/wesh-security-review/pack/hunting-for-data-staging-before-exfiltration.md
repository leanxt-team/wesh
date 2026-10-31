---
name: hunting-for-data-staging-before-exfiltration
description: Detect data-staging activity (MITRE ATT&CK T1074) by analyzing EDR/Sysmon process-creation and file-system telemetry (Event ID 4688, Sysmon 1/11) for 7-Zip/RAR/tar archive creation, unusual temp or hidden folder access, and anomalous consolidation of files from multiple directories.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1048
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-data-staging-before-exfiltration@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- EDR or Sysmon telemetry with process creation and file system events
- Windows Event Logs (Event ID 4688) or Sysmon Event ID 1, 11
- Python 3.8+ with standard library
- Access to process creation logs in JSON/CSV format

## Steps

1. **Detect Archive Tool Execution** — Monitor for 7z.exe, rar.exe, tar, zip, and WinRAR process creation with compression arguments
2. **Identify Staging Directories** — Flag file writes to common staging locations (Recycle Bin, %TEMP%, ProgramData, hidden directories)
3. **Detect Large File Consolidation** — Identify patterns of multiple file reads followed by writes to single directory
4. **Monitor Sensitive Path Access** — Track bulk reads from document directories, database paths, and network shares
5. **Analyze Archive Metadata** — Extract and analyze archive file sizes, creation times, and source paths
6. **Score Staging Risk** — Apply heuristic scoring based on archive size, source diversity, staging path suspicion, and timing
7. **Generate Hunt Report** — Produce structured report with staging event timeline and MITRE ATT&CK mapping

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-data-staging-before-exfiltration
