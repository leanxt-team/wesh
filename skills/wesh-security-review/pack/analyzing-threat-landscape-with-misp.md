---
name: analyzing-threat-landscape-with-misp
description: Query a MISP (Malware Information Sharing Platform) instance via PyMISP to compute event statistics, IOC type breakdowns, threat actor galaxy clusters, and tag trends, and generate threat landscape reports with temporal trends.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1566
- T1071.001
- T1568
- T1583.001
- T1102
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
upstream: analyzing-threat-landscape-with-misp@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with threat intelligence concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install pymisp`
2. Configure MISP URL and API key.
3. Run agent to generate threat landscape analysis:
   - Pull event statistics by threat level and date range
   - Analyze attribute type distributions (IP, domain, hash, URL)
   - Identify top MITRE ATT&CK techniques from event tags
   - Track threat actor activity via galaxy clusters
   - Generate temporal trend analysis of IOC submissions

```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## Examples

### Threat Landscape Summary
```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-threat-landscape-with-misp
