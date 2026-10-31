---
name: detecting-dll-sideloading-attacks
description: Detect DLL side-loading and search-order hijacking (MITRE T1574) where adversaries plant malicious DLLs for legitimate signed applications to load, by analyzing Sysmon Event ID 7 DLL-load events, checking signatures/hashes against known-good versions, and flagging path anomalies with EDR tools like CrowdStrike, MDE, or SentinelOne.
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
upstream: detecting-dll-sideloading-attacks@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- EDR with DLL load monitoring (CrowdStrike, MDE, SentinelOne)
- Sysmon Event ID 7 (Image Loaded) with hash verification
- Application whitelisting or DLL integrity monitoring
- Software inventory of legitimate applications and expected DLL paths
- Code signing verification capabilities

## Workflow

1. **Identify Sideloading Targets**: Research known vulnerable applications that load DLLs without full path qualification (LOLBAS, DLL-sideload databases).
2. **Monitor DLL Load Events**: Query Sysmon Event ID 7 for DLL loads where DLL path differs from application's expected directory.
3. **Check DLL Signatures**: Flag unsigned or untrusted DLLs loaded by signed executables.
4. **Detect Path Anomalies**: Identify legitimate executables running from unusual locations (Temp, AppData, Public) that may be decoy wrappers.
5. **Hash Verification**: Compare loaded DLL hashes against known-good versions and threat intel feeds.
6. **Correlate with Process Behavior**: Check if host process exhibits unusual behavior (network connections, child processes) after loading suspicious DLL.
7. **Document and Remediate**: Report sideloading instances, quarantine malicious DLLs, and update detection rules.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1574.002 | DLL Side-Loading |
| T1574.001 | DLL Search Order Hijacking |
| T1574.006 | Dynamic Linker Hijacking |
| T1574.008 | Path Interception by Search Order Hijacking |
| DLL Search Order | Windows DLL loading priority path |
| Side-Loading | Placing malicious DLL where legitimate app loads it |
| Phantom DLL | DLL that legitimate apps try to load but does not exist |
| DLL Proxying | Malicious DLL forwarding calls to legitimate DLL |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Sysmon | Event ID 7 DLL load monitoring |
| CrowdStrike Falcon | DLL load detection with process context |
| Microsoft Defender for Endpoint | DLL load anomaly detection |
| Process Monitor | Real-time DLL load tracing |
| DLL Export Viewer | Verify DLL export functions |
| Sigcheck | Digital signature verification |
| pe-sieve | PE analysis for proxied DLLs |

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-dll-sideloading-attacks
