---
name: hunting-for-dns-based-persistence
description: Hunts for DNS-based persistence mechanisms such as DNS hijacking, dangling CNAME records enabling subdomain takeover, wildcard DNS abuse, and unauthorized zone or NS delegation changes, using passive DNS history (SecurityTrails API), Route53/Azure DNS/Cloudflare audit logs, and zone transfer analysis.
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
upstream: hunting-for-dns-based-persistence@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- SecurityTrails API key (free tier provides 50 queries/month)
- Access to DNS provider audit logs (Route53, Azure DNS, Cloudflare, or on-premises DNS)
- Python 3.9+ with requests library
- DNS zone file access or AXFR capability for internal zones
- Historical DNS baseline for comparison

## Steps

### Step 1: Baseline DNS Records

Export current DNS zone records and establish baseline for all authorized A, AAAA, CNAME, MX, NS, and TXT records.

### Step 2: Query Passive DNS History

Use SecurityTrails API to retrieve historical DNS records and identify unauthorized changes, new subdomains, and CNAME records pointing to decommissioned services (dangling CNAMEs).

### Step 3: Detect Anomalies

Compare current records against baseline to identify unauthorized modifications, wildcard records that resolve all subdomains, NS delegation changes, and MX record hijacking.

### Step 4: Investigate Findings

Correlate DNS anomalies with threat intelligence feeds, check resolution targets against known malicious infrastructure, and validate record ownership.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-dns-based-persistence
