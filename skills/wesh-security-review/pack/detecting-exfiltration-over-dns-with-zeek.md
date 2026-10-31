---
name: detecting-exfiltration-over-dns-with-zeek
description: Detect DNS-based data exfiltration by analyzing Zeek dns.log for high-entropy subdomains, oversized TXT/NULL records, and anomalous query volume or patterns.
subdomain: network-security
facing: defense
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1048
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: detecting-exfiltration-over-dns-with-zeek@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9 or later with math and collections modules (stdlib)
- Zeek dns.log files in TSV format with standard field headers
- Network capture data processed by Zeek 5.0+ or later
- Understanding of DNS protocol structure and query types

## Steps

1. **Parse Zeek dns.log headers**: Read TSV file, extract the `#fields` header line to identify column positions for `ts`, `id.orig_h`, `query`, `qtype_name`, `rcode_name`, and `answers`.

2. **Extract and decompose queries**: For each DNS query, split FQDN into subdomain labels and parent domain. Skip queries to known safe domains and internal zones.

3. **Compute Shannon entropy**: Calculate information entropy of each subdomain label. Legitimate subdomains typically have entropy below 3.5, while encoded/encrypted data produces entropy above 4.0.

4. **Detect long labels**: Flag DNS labels exceeding 52 characters (approaching 63-character maximum). Long labels are strong indicator of data tunneling.

5. **Count unique subdomains per domain**: Track how many distinct subdomains each parent domain receives. Domains with more than 50 unique subdomains within log window are suspicious.

6. **Identify query volume anomalies**: Calculate queries-per-minute per source IP per domain. Exfiltration tools generate sustained high-volume query streams that differ from normal browsing.

7. **Score and rank domains**: Combine entropy, label length, uniqueness count, and query volume into composite risk score. Rank domains by score and output top suspicious domains.

8. **Generate detection report**: Produce JSON report with flagged domains, their evidence indicators, originating source IPs, and recommended response actions.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-exfiltration-over-dns-with-zeek
