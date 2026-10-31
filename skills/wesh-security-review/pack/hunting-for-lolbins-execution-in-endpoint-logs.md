---
name: hunting-for-lolbins-execution-in-endpoint-logs
description: Hunts for LOLBins (Living Off the Land Binaries) abuse, mapped to MITRE T1218, by analyzing endpoint process-creation logs for suspicious execution patterns of legitimate Windows system binaries used for malicious purposes.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1027
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-lolbins-execution-in-endpoint-logs@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Sysmon Event ID 1 (Process Creation) with full command-line logging
- Windows Security Event ID 4688 with command-line auditing enabled
- EDR telemetry with parent-child process relationships
- SIEM platform for query and correlation (Splunk, Elastic, Microsoft Sentinel)
- LOLBAS project reference (lolbas-project.github.io) for known abuse patterns

## Workflow

1. **Build LOLBin Watchlist**: Compile list of high-risk LOLBins from LOLBAS project, prioritizing: certutil.exe, mshta.exe, rundll32.exe, regsvr32.exe, msbuild.exe, installutil.exe, cmstp.exe, wmic.exe, wscript.exe, cscript.exe, bitsadmin.exe, and powershell.exe.
2. **Baseline Normal Usage**: Establish what normal LOLBin usage looks like in your environment by profiling command-line arguments, parent processes, and user contexts for each binary over 30 days.
3. **Hunt for Anomalous Arguments**: Search for LOLBins executed with unusual command-line arguments indicating abuse -- certutil with `-urlcache -decode -encode`, mshta with URL arguments, rundll32 loading DLLs from temp/user directories, regsvr32 with `/s /n /u /i:URL`.
4. **Analyze Parent-Child Relationships**: Identify unexpected parent processes spawning LOLBins -- e.g., outlook.exe spawning mshta.exe, or winword.exe spawning certutil.exe indicates weaponized document delivery.
5. **Check Execution from Unusual Paths**: LOLBins executed from non-standard paths (copies placed in %TEMP%, user profile directories) suggest renamed binary abuse.
6. **Correlate with Network Activity**: Map LOLBin execution to outbound network connections (Sysmon Event ID 3) to identify download cradles and C2 callbacks.
7. **Score and Prioritize**: Rank findings by anomaly severity, combining suspicious arguments, unusual parent process, non-standard path, and network activity indicators.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1218 | System Binary Proxy Execution |
| T1218.001 | Compiled HTML File (mshta.exe) |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32 (Squiblydoo) |
| T1218.011 | Rundll32 |
| T1127.001 | MSBuild |
| T1197 | BITS Jobs (bitsadmin.exe) |
| T1140 | Deobfuscate/Decode Files (certutil.exe) |
| T1059.001 | PowerShell |
| T1059.005 | Visual Basic (wscript/cscript) |
| LOLBAS | Living Off Land Binaries, Scripts and Libraries project |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Process creation with command-line and hash logging |
| CrowdStrike Falcon | EDR with LOLBin detection analytics |
| Microsoft Defender for Endpoint | Built-in LOLBin abuse detection |
| Splunk | SPL-based process hunting and anomaly detection |
| Elastic Security | Pre-built LOLBin detection rules |
| LOLBAS Project | Reference database of LOLBin abuse techniques |
| Sigma Rules | Community detection rules for LOLBin abuse |

## Detection Queries

### Splunk -- High-Risk LOLBin Execution
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|installutil|cmstp|bitsadmin)\.exe$")
| eval suspicious=case(
    match(CommandLine, "(?i)certutil.*(-urlcache|-decode|-encode)"), "certutil_download_decode",
    match(CommandLine, "(?i)mshta.*(http|https|javascript|vbscript)"), "mshta_remote_exec",
    match(CommandLine, "(?i)rundll32.*\\\\(temp|appdata|users)"), "rundll32_unusual_dll",
    match(CommandLine, "(?i)regsvr32.*/s.*/n.*/u.*/i:"), "regsvr32_squiblydoo",
    match(CommandLine, "(?i)msbuild.*\\\\(temp|appdata|users)"), "msbuild_unusual_project",
    match(CommandLine, "(?i)bitsadmin.*/transfer"), "bitsadmin_download",
    match(CommandLine, "(?i)cmstp.*/s.*/ni"), "cmstp_uac_bypass",
    1=1, "normal"
)
| where suspicious!="normal"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine suspicious
```

### KQL -- Microsoft Sentinel LOLBin Hunting
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe", "cmstp.exe", "bitsadmin.exe")
| where ProcessCommandLine matches regex @"(?i)(urlcache|decode|encode|http://|https://|javascript:|vbscript:|/s\s+/n|/transfer)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Sigma Rule -- Suspicious LOLBin Command Line
```yaml
title: Suspicious LOLBin Execution with Malicious Arguments
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'javascript:'
    selection_regsvr32:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all:
            - '/s'
            - '/i:'
    condition: 1 of selection_*
level: high
tags:
    - attack.defense_evasion
    - attack.t1218
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-lolbins-execution-in-endpoint-logs
