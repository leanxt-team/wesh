---
name: hunting-for-command-and-control-beaconing
description: Detect C2 beaconing patterns in network traffic using frequency analysis, jitter detection, and domain reputation to identify compromised endpoints communicating with adversary infrastructure.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1071
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-command-and-control-beaconing@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Network proxy/firewall logs with full URL and timing data
- DNS query logs (passive DNS, DNS server logs, or Sysmon Event ID 22)
- Zeek/Bro network connection logs or NetFlow data
- SIEM with statistical analysis capabilities (Splunk, Elastic)
- Threat intelligence feeds for domain/IP reputation

## Workflow

1. **Identify Beaconing Characteristics**: Define what constitutes beaconing (regular intervals, small payload sizes, consistent destinations, jitter patterns).
2. **Collect Network Telemetry**: Aggregate proxy logs, DNS queries, and connection metadata for analysis.
3. **Apply Frequency Analysis**: Identify connections with regular intervals using statistical methods (standard deviation, coefficient of variation).
4. **Filter Known-Good Traffic**: Exclude legitimate periodic traffic (Windows Update, AV updates, heartbeat services, NTP).
5. **Analyze Domain/IP Reputation**: Check identified beaconing destinations against threat intel, WHOIS data, and certificate transparency logs.
6. **Investigate Endpoint Context**: Correlate beaconing activity with process creation, user context, and file system changes on source endpoints.
7. **Confirm and Respond**: Validate C2 activity, block communication, and initiate incident response.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071 | Application Layer Protocol (HTTP/HTTPS/DNS C2) |
| T1071.001 | Web Protocols (HTTP/S beaconing) |
| T1071.004 | DNS (DNS tunneling C2) |
| T1573 | Encrypted Channel |
| T1572 | Protocol Tunneling |
| T1568 | Dynamic Resolution (DGA, fast-flux) |
| T1132 | Data Encoding in C2 |
| T1095 | Non-Application Layer Protocol |
| Beacon Interval | Time between C2 check-ins |
| Jitter | Random variation in beacon interval |
| DGA | Domain Generation Algorithm |
| Fast-Flux | Rapidly changing DNS resolution |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| RITA (Real Intelligence Threat Analytics) | Automated beacon detection in Zeek logs |
| Splunk | Statistical beacon analysis with SPL |
| Elastic Security | ML-based anomaly detection for beaconing |
| Zeek/Bro | Network connection metadata collection |
| Suricata | Network IDS with JA3/JA4 fingerprinting |
| VirusTotal | Domain and IP reputation checking |
| PassiveDNS | Historical DNS resolution data |
| Flare | C2 profile detection |

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-command-and-control-beaconing
