---
name: implementing-web-application-logging-with-modsecurity
description: Configure ModSecurity WAF with the OWASP Core Rule Set (CRS) for web application audit logging, tuning SecRuleEngine, SecAuditEngine, and CRS paranoia levels to reduce false positives, and writing custom SecRules for application-specific threats.
subdomain: web-application-security
facing: config
mitre_attack:
- T1190
- T1059.007
- T1505.003
- T1083
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
upstream: implementing-web-application-logging-with-modsecurity@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Web server (Apache 2.4+ or Nginx) with ModSecurity v3 module
- OWASP CRS v4.x installed
- Log aggregation infrastructure (ELK, Splunk, or Wazuh)

## Steps

1. Install ModSecurity and configure SecRuleEngine in DetectionOnly mode
2. Deploy OWASP CRS v4 and set paranoia level (PL1-PL4)
3. Configure SecAuditEngine for relevant-only logging
4. Tune false positives with SecRuleRemoveById and rule exclusions
5. Switch to blocking mode (SecRuleEngine On) after tuning period
6. Forward audit logs to SIEM for correlation and alerting

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-web-application-logging-with-modsecurity
