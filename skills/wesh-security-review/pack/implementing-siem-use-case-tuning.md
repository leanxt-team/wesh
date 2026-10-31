---
name: implementing-siem-use-case-tuning
description: Tune SIEM detection rules in Splunk and Elastic to reduce false positives by analyzing alert volumes, creating context-aware exclusion lists, adjusting thresholds against environmental baselines, and measuring precision/recall efficacy metrics.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1685.002
- T1685.005
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-siem-use-case-tuning@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Splunk Enterprise/Cloud with ES or Elastic SIEM with detection rules enabled
- Historical alert data (minimum 30 days) for baseline analysis
- Python 3.8+ with `requests` library
- SIEM admin credentials or API tokens

## Steps

1. Export current alert volumes per detection rule from SIEM
2. Calculate false positive rate per rule using analyst disposition data
3. Identify top noise-generating rules by volume and FP rate
4. Build environmental baselines for thresholds (e.g., login counts, process spawns)
5. Create whitelist entries for known-good entities (service accounts, scanners)
6. Adjust rule thresholds using statistical analysis (mean + N standard deviations)
7. Measure tuning impact via before/after precision and alert-to-incident ratio

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-siem-use-case-tuning
