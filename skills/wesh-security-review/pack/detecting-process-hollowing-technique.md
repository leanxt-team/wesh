---
name: detecting-process-hollowing-technique
description: Detect process hollowing (MITRE T1055.012) by analyzing memory-mapped sections, hollowed process indicators, and parent-child anomalies using EDR telemetry, Volatility's malfind plugin, pe-sieve, Hollows Hunter, and Sysmon Event ID 25.
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
upstream: detecting-process-hollowing-technique@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- EDR with memory protection monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon with Event IDs 1 (Process Create), 8 (CreateRemoteThread), 25 (ProcessTampering)
- Windows ETW providers for process hollowing (Microsoft-Windows-Kernel-Process)
- Memory forensics capabilities (Volatility, WinDbg)
- Process integrity monitoring tools

## Workflow

1. **Understand Hollowing Mechanics**: Process hollowing involves creating legitimate process in suspended state, unmapping its memory, writing malicious code, then resuming execution.
2. **Monitor Suspended Process Creation**: Hunt for processes created with CREATE_SUSPENDED flag followed by memory writes and thread resumption.
3. **Detect Memory Section Anomalies**: Identify processes where in-memory image differs from on-disk binary (image mismatch).
4. **Analyze Parent-Child Process Trees**: Flag processes whose behavior does not match their binary name (e.g., svchost.exe making unusual network connections).
5. **Check Process Integrity**: Compare process memory sections against legitimate binary on disk.
6. **Correlate with Network Activity**: Hollowed processes often establish C2 connections - correlate suspicious process behavior with network logs.
7. **Document and Contain**: Report findings, isolate affected endpoints, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1055.012 | Process Injection: Process Hollowing |
| T1055 | Process Injection (parent technique) |
| T1055.001 | DLL Injection |
| T1055.003 | Thread Execution Hijacking |
| T1055.004 | Asynchronous Procedure Call |
| CREATE_SUSPENDED | Windows flag to create process in suspended state |
| NtUnmapViewOfSection | API to unmap process memory sections |
| WriteProcessMemory | API to write into another process's memory |
| ResumeThread | API to resume suspended thread |
| Image Mismatch | Process memory content differs from on-disk binary |
| Process Doppelganging | Related technique using NTFS transactions (T1055.013) |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| CrowdStrike Falcon | Memory protection and hollowing detection |
| Microsoft Defender for Endpoint | ProcessTampering alerts |
| Sysmon v13+ | Event ID 25 ProcessTampering detection |
| Volatility | Memory forensics - malfind plugin |
| pe-sieve | Process memory scanner for hollowed processes |
| Hollows Hunter | Automated hollowed process detection |
| Process Hacker | Live process memory inspection |
| API Monitor | Monitor NtUnmapViewOfSection calls |

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-process-hollowing-technique
