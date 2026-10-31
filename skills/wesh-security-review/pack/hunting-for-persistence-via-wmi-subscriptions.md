---
name: hunting-for-persistence-via-wmi-subscriptions
description: Hunts for adversary persistence via WMI event subscriptions (MITRE T1546.003) by monitoring the creation of WMI event filters, consumers, and filter-to-consumer bindings that trigger malicious code execution on system events.
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
upstream: hunting-for-persistence-via-wmi-subscriptions@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Sysmon Event ID 19, 20, 21 (WMI Event Filter/Consumer/Binding) enabled
- Windows Event ID 5861 (WMI activity logging) from Microsoft-Windows-WMI-Activity
- PowerShell logging enabled (Script Block Logging, Module Logging)
- WMI repository access for enumeration
- SIEM platform for event correlation

## Workflow

1. **Enumerate Existing WMI Subscriptions**: Query all permanent WMI event subscriptions on target systems. clean system typically has few or zero permanent subscriptions, making anomalies easy to spot.
2. **Monitor WMI Event Creation (Sysmon 19/20/21)**: Sysmon Event 19 captures WmiEventFilter activity, Event 20 captures WmiEventConsumer activity, and Event 21 captures WmiEventConsumerToFilter binding.
3. **Analyze Consumer Types**: Focus on ActiveScriptEventConsumer (runs VBScript/JScript) and CommandLineEventConsumer (executes commands) -- these are dangerous types used for persistence.
4. **Check Event Filter Triggers**: Examine what triggers subscription. Common malicious triggers include system startup (Win32_ProcessStartTrace), user logon, or timer-based execution intervals.
5. **Investigate WmiPrvSe.exe Child Processes**: When WMI subscription fires, action is executed by WmiPrvSe.exe. Hunt for unusual child processes of WmiPrvSe.exe.
6. **Correlate with MOF Compilation**: Detect `mofcomp.exe` usage which compiles MOF files to create WMI subscriptions programmatically.
7. **Validate and Respond**: Confirm malicious subscriptions, remove them, and trace back to initial infection vector.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1546.003 | Event Triggered Execution: WMI Event Subscription |
| __EventFilter | WMI class defining trigger condition |
| __EventConsumer | WMI class defining action to perform |
| __FilterToConsumerBinding | Links filter to consumer |
| ActiveScriptEventConsumer | Consumer that runs VBScript or JScript |
| CommandLineEventConsumer | Consumer that executes command lines |
| WmiPrvSe.exe | WMI Provider Host that executes subscription actions |
| MOF File | Managed Object Format used to define WMI objects |

## Detection Queries

### Splunk -- WMI Subscription Creation via Sysmon
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "FilterToConsumerBinding")
| table _time Computer User event_type EventNamespace Name Query Destination Operation
```

### Splunk -- WMI Subscription via Windows Event 5861
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time Computer NamespaceName Operation PossibleCause
```

### PowerShell -- Enumerate WMI Subscriptions
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### KQL -- WmiPrvSe.exe Spawning Suspicious Children
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Sigma Rule
```yaml
title: WMI Event Subscription Persistence
status: stable
logsource:
    product: windows
    category: wmi_event
detection:
    selection_consumer:
        EventID: 20
        Destination|contains:
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    condition: selection_consumer
level: high
tags:
    - attack.persistence
    - attack.t1546.003
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-persistence-via-wmi-subscriptions
