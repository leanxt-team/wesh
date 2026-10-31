---
name: performing-osint-with-spiderfoot
description: Automate OSINT collection with the SpiderFoot REST API and CLI (sf.py/spiderfoot-cli) across 200+ modules, selecting scan modes (footprint, investigate, passive) and parsing results for domains, IPs, emails, leaked credentials, and DNS records into a target intelligence profile.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1591
- T1592
- T1593
- T1589
- T1595
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
upstream: performing-osint-with-spiderfoot@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- SpiderFoot 4.0+ installed or SpiderFoot HX cloud account
- Python 3.8+ with requests library
- SpiderFoot server running on default port 5001
- Optional: API keys for VirusTotal, Shodan, HaveIBeenPwned modules

## Steps

1. Connect to SpiderFoot REST API or use CLI interface
2. Create new scan with target specification (domain, IP, email, name)
3. Select scan modules by use case (all, footprint, investigate, passive)
4. Monitor scan progress via API polling
5. Retrieve and parse scan results by data element type
6. Extract key findings: subdomains, IPs, emails, leaked credentials
7. Generate structured OSINT intelligence report

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-osint-with-spiderfoot
