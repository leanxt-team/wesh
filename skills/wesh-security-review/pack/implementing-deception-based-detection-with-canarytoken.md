---
name: implementing-deception-based-detection-with-canarytoken
description: Deploys and monitors Canary Tokens via the Thinkst Canary REST API for deception-based breach detection, programmatically creating web bug, DNS, MS Word document, and AWS API key tokens and generating deception coverage reports from triggered alerts.
subdomain: deception-technology
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1078.004
- T1530
nist_csf:
- DE.CM-01
- DE.AE-06
- PR.IR-01
upstream: implementing-deception-based-detection-with-canarytoken@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Thinkst Canary Console or canarytokens.org account
- API auth token from Canary Console
- Python 3.9+ with `requests`
- File system access for deploying document and file tokens

## Steps

1. Authenticate to Canary Console API using auth_token
2. Create web bug (HTTP) tokens for embedding in documents and web pages
3. Create DNS tokens for monitoring DNS resolution attempts
4. Create MS Word document tokens for file share deployment
5. List all active tokens and their trigger history
6. Query recent alerts for triggered token events
7. Generate deception coverage report with deployment recommendations

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-deception-based-detection-with-canarytoken
