---
name: performing-red-team-phishing-with-gophish
description: Automates GoPhish phishing simulation campaigns using the Python gophish library, creating email templates with tracking pixels, configuring SMTP sending profiles, building target groups from CSV, launching campaigns, and analyzing results such as open rates, click rates, and credential submission statistics.
subdomain: security-operations
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: performing-red-team-phishing-with-gophish@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install gophish requests`
2. Deploy GoPhish server and obtain API key from Settings.
3. Use Python gophish library to automate campaign setup:
   - Create email templates with HTML body and tracking
   - Configure SMTP sending profiles
   - Import target groups from CSV
   - Create landing pages for credential capture
   - Launch and monitor campaigns
4. Analyze campaign results: opens, clicks, submitted data, reported.

```bash
# For authorized penetration testing and lab environments only
python scripts/agent.py --gophish-url https://localhost:3333 --api-key <key> --campaign-name "Q1 Awareness" --output phishing_report.json
```

## Examples

### Create Campaign via API

```python
from gophish import Gophish
from gophish.models import Campaign, Template, Group, SMTP, Page
api = Gophish("api_key", host="https://localhost:3333", verify=False)  # Self-signed cert on localhost lab
campaign = Campaign(name="Q1 Test", groups=[Group(name="Sales Team")],
    template=Template(name="IT Password Reset"), smtp=SMTP(name="Internal SMTP"),
    page=Page(name="Credential Page"))
api.campaigns.post(campaign)
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-red-team-phishing-with-gophish
