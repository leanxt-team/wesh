---
name: performing-network-traffic-analysis-with-tshark
description: Automate network traffic analysis using tshark (Wireshark CLI) and pyshark to compute protocol distribution statistics, detect suspicious flows such as port scans and beaconing, extract IOCs (IPs, domains, URLs), and identify DNS tunneling patterns from PCAP files.
subdomain: network-security
facing: defense
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1005
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: performing-network-traffic-analysis-with-tshark@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- tshark (Wireshark CLI) installed and in PATH
- Python 3.8+ with pyshark library
- PCAP or PCAPNG capture file for analysis

## Steps

1. **Extract Protocol Statistics** — Generate protocol hierarchy and conversation statistics from capture
2. **Identify Top Talkers** — Rank source/destination IPs by volume and connection count
3. **Detect Suspicious Flows** — Flag port scanning patterns, unusual port usage, and high-frequency connections
4. **Extract Network IOCs** — Pull unique IPs, domains from DNS queries, and URLs from HTTP traffic
5. **Analyze DNS Traffic** — Detect DNS tunneling via high-entropy subdomain queries and excessive TXT records
6. **Generate Analysis Report** — Produce structured report with flow summaries and threat indicators

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-network-traffic-analysis-with-tshark
