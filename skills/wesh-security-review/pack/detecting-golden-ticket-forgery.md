---
name: detecting-golden-ticket-forgery
description: Detect Kerberos Golden Ticket forgery (e.g.
subdomain: threat-detection
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1003
- T1110
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-06
- ID.RA-05
upstream: detecting-golden-ticket-forgery@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Windows Domain Controller with Kerberos audit logging enabled
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Python 3.8+ for offline event log analysis
- Knowledge of domain Kerberos encryption policy (AES vs RC4)

## Steps

1. Audit domain Kerberos encryption policy to establish AES-only baseline
2. Forward Event IDs 4768 and 4769 to SIEM platform
3. Detect RC4 (0x17) encryption in TGS requests where AES is enforced
4. Identify TGS requests without corresponding TGT requests (forged ticket indicator)
5. Alert on ticket lifetimes exceeding MaxTicketAge domain policy
6. Monitor krbtgt account password age and last reset date
7. Correlate findings with host/user context for risk scoring

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-golden-ticket-forgery
