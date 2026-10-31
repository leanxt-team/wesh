---
name: detecting-shadow-it-cloud-usage
description: Detect unauthorized SaaS and cloud service usage (shadow IT) by parsing proxy access logs, DNS query logs, and firewall/netflow data with Python pandas to aggregate traffic by domain, classify domains against known SaaS categories, and score risk by data volume and user count.
subdomain: cloud-security
facing: config
mitre_attack:
- T1567.002
- T1526
- T1078.004
- T1213
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: detecting-shadow-it-cloud-usage@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with `pandas`, `tldextract`
- Proxy logs (Squid, Zscaler, or Palo Alto format) or DNS query logs
- SaaS application catalog/blocklist for classification
- Network firewall logs with FQDN resolution (optional)

## Steps

1. Parse proxy access logs and extract destination domains with traffic volumes
2. Parse DNS query logs to identify resolved cloud service domains
3. Aggregate traffic by domain using pandas — total bytes, request counts, unique users
4. Classify domains against known SaaS categories (storage, email, dev tools, AI)
5. Flag unauthorized services not on approved application list
6. Calculate risk scores based on data volume, user count, and service category
7. Generate shadow IT discovery report with remediation recommendations

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-shadow-it-cloud-usage
