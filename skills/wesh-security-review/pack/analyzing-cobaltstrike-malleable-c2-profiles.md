---
name: analyzing-cobaltstrike-malleable-c2-profiles
description: Parse and analyze Cobalt Strike Malleable C2 profiles with dissect.cobaltstrike (profiles and beacon-payload configs) and pyMalleableC2 (AST parsing) to extract HTTP/DNS transforms, URIs, headers, sleep/jitter, and injection behavior, then generate network detection signatures.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1071.001
- T1573.002
- T1001.003
- T1090.004
- T1102
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: analyzing-cobaltstrike-malleable-c2-profiles@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with `dissect.cobaltstrike` and/or `pyMalleableC2`
- Sample Malleable C2 profiles (available from public repositories)
- Understanding of HTTP protocol and Cobalt Strike beacon communication model
- Network monitoring tools (Suricata/Snort) for signature deployment
- PCAP analysis tools for traffic validation

## Steps

1. Install libraries: `pip install dissect.cobaltstrike` or `pip install pyMalleableC2`
2. Parse profile with `C2Profile.from_path("profile.profile")`
3. Extract HTTP GET/POST block configurations (URIs, headers, parameters)
4. Identify user agent strings and spoof targets
5. Extract sleep time, jitter percentage, and DNS beacon settings
6. Analyze process injection settings (spawn-to, allocation technique)
7. Generate Suricata/Snort signatures from extracted network indicators
8. Compare profile against known threat actor profile collections
9. Extract staging URIs and payload delivery mechanisms
10. Produce detection report with IOCs and recommended network signatures

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-cobaltstrike-malleable-c2-profiles
