---
name: analyzing-network-packets-with-scapy
description: Use Scapy to craft, send, sniff, and dissect TCP/UDP/ICMP/DNS packets, analyze pcap files, implement SYN scans, and detect anomalous traffic such as fragmented or malformed packets.
subdomain: network-security
facing: defense
mitre_attack:
- T1040
- T1071
- T1046
- T1557
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: analyzing-network-packets-with-scapy@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.8+ with `scapy` library installed (`pip install scapy`)
- Root/administrator privileges for raw socket operations (sniffing, sending)
- Npcap (Windows) or libpcap (Linux) for packet capture
- Authorization to perform packet operations on target network

## Steps

1. Read and parse pcap/pcapng files with `rdpcap()` for offline analysis
2. Extract protocol layers (IP, TCP, UDP, DNS, HTTP) and field values
3. Compute traffic statistics: top talkers, protocol distribution, port frequency
4. Detect SYN flood patterns by analyzing TCP flag ratios
5. Identify DNS exfiltration indicators via query length and entropy analysis
6. Craft custom probe packets for authorized network testing
7. Export findings as structured JSON report

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-network-packets-with-scapy
