---
name: analyzing-powershell-empire-artifacts
description: Detect PowerShell Empire post-exploitation framework artifacts in Windows Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103), including the default launcher string, Base64-encoded WebClient/FromBase64String payloads, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast), and staging URL patterns.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1059.001
- T1071.001
- T1003.001
- T1558.003
- T1027.010
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: analyzing-powershell-empire-artifacts@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with access to Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Detection Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-powershell-empire-artifacts
