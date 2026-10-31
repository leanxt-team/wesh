---
name: implementing-network-traffic-baselining
description: Builds network traffic baselines from NetFlow/IPFIX CSV or JSON exports using Python pandas, computing hourly/daily volume distributions, per-host and protocol/port statistics, and top-talker profiles, then flags outliers via z-score and IQR anomaly detection.
subdomain: network-security
facing: defense
mitre_attack:
- T1046
- T1040
- T1557
- T1071
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: implementing-network-traffic-baselining@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- NetFlow v5/v9 or IPFIX flow data exported as CSV or JSON
- Python 3.8+ with pandas and numpy libraries
- Historical flow data (minimum 7 days recommended for baseline)

## Steps

1. Ingest NetFlow/IPFIX records from CSV or JSON exports
2. Compute hourly and daily traffic volume distributions (bytes, packets, flows)
3. Build per-source-IP baseline profiles with mean, median, standard deviation
4. Calculate protocol and port distribution baselines
5. Apply z-score anomaly detection to identify statistical outliers
6. Flag flows exceeding IQR-based thresholds as potential anomalies
7. Generate baseline report with anomaly alerts

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-network-traffic-baselining
