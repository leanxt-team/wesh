---
name: detecting-t1548-abuse-elevation-control-mechanism
description: Detect abuse of elevation control mechanisms (T1548), including Windows UAC bypass via auto-elevating binaries like fodhelper.exe and Linux sudo/setuid/setgid exploitation, by monitoring registry changes, integrity-level transitions, and parent-child process relationships via Sysmon and Windows Security events.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1548.002
- T1548.001
- T1548.003
- T1548.004
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: detecting-t1548-abuse-elevation-control-mechanism@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Sysmon Event ID 1 with command-line and parent process logging
- Windows Security Event ID 4688 with process tracking
- Registry auditing for UAC-related keys (HKCU\Software\Classes)
- Sysmon Event ID 12/13 (Registry key/value modification)
- EDR with elevation monitoring capabilities

## Workflow

1. **Monitor UAC Registry Modifications**: Many UAC bypasses modify registry keys under `HKCU\Software\Classes\ms-settings\shell\open\command` or `HKCU\Software\Classes\mscfile\shell\open\command`. Track Sysmon Events 12/13 for these changes.
2. **Detect Auto-Elevating Process Abuse**: Certain Windows binaries auto-elevate without UAC prompts (fodhelper.exe, computerdefaults.exe, eventvwr.exe). Hunt for these being launched by non-standard parent processes.
3. **Track Process Integrity Level Changes**: Monitor for processes escalating from medium to high integrity level without corresponding UAC consent events.
4. **Hunt for Elevated Process Spawning**: Detect when auto-elevating processes spawn unexpected children (cmd.exe, powershell.exe) -- indicating UAC bypass exploitation.
5. **Monitor Linux Elevation Abuse**: Track sudo misconfiguration exploitation, setuid binary abuse, and capability manipulation.
6. **Correlate with Privilege Escalation Chain**: Map elevation abuse to broader attack chain, identifying what was done with escalated privileges.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1548.002 | Bypass User Account Control |
| T1548.001 | Setuid and Setgid (Linux) |
| T1548.003 | Sudo and Sudo Caching |
| T1548.004 | Elevated Execution with Prompt (macOS) |
| UAC Auto-Elevation | Windows binaries that elevate without prompt |
| fodhelper.exe | Common UAC bypass vector via registry hijack |
| eventvwr.exe | MSC file handler UAC bypass |
| Integrity Level | Windows process trust level (Low/Medium/High/System) |

## Detection Queries

### Splunk -- UAC Bypass via Registry Modification
```spl
index=sysmon (EventCode=12 OR EventCode=13)
| where match(TargetObject, "(?i)HKCU\\\\Software\\\\Classes\\\\(ms-settings|mscfile|exefile|Folder)\\\\shell\\\\open\\\\command")
| table _time Computer User EventCode TargetObject Details Image
```

### Splunk -- Auto-Elevating Process Abuse
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(fodhelper|computerdefaults|eventvwr|sdclt|slui|cmstp)\.exe$")
| where NOT match(ParentImage, "(?i)(explorer|svchost|services)\.exe$")
| table _time Computer User Image CommandLine ParentImage ParentCommandLine
```

### KQL -- UAC Bypass Detection
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("ms-settings\\shell\\open\\command", "mscfile\\shell\\open\\command")
| where ActionType == "RegistryValueSet"
| project Timestamp, DeviceName, RegistryKey, RegistryValueData, InitiatingProcessFileName
```

### Sigma Rule
```yaml
title: UAC Bypass via Registry Modification
status: stable
logsource:
    product: windows
    category: registry_set
detection:
    selection:
        TargetObject|contains:
            - '\ms-settings\shell\open\command'
            - '\mscfile\shell\open\command'
            - '\exefile\shell\open\command'
    condition: selection
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548.002
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-t1548-abuse-elevation-control-mechanism
