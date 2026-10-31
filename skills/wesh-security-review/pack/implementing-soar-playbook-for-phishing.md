---
name: implementing-soar-playbook-for-phishing
description: Automates phishing incident response by calling the Splunk SOAR (Phantom) REST API to create containers, attach artifacts (emails, URLs, attachments), and trigger response playbooks.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1566
- T1598
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: implementing-soar-playbook-for-phishing@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9 or later with `requests` and `email` modules
- Splunk SOAR instance (Cloud or On-Premises) with REST API access
- SOAR API token with permissions to create containers and trigger playbooks
- Network connectivity to SOAR instance on port 443
- Configured phishing investigation playbook in SOAR

## Steps

1. **Parse phishing email**: Read email file (.eml format) and extract headers including From, To, Subject, Reply-To, Return-Path, Received, Message-ID, X-Mailer, and authentication results (SPF, DKIM, DMARC). Extract URLs and IP addresses from email body.

2. **Authenticate to SOAR REST API**: Use API token in the `ph-auth-token` header to authenticate all REST API requests to SOAR instance.

3. **Create container**: POST to `/rest/container` with incident label, name, description, severity, and status. container represents phishing incident and receives container ID in response.

4. **Add email header artifacts**: POST to `/rest/artifact` with `container_id` and CEF (Common Event Format) fields containing sender address (`fromAddress`), recipient (`toAddress`), subject, originating IP (`sourceAddress`), and Message-ID. Set `run_automation` to False for all but last artifact.

5. **Add URL artifacts**: For each URL extracted from email body, create artifact with CEF field `requestURL` and type `url`. These artifacts feed into URL reputation checks in playbook.

6. **Trigger playbook**: POST to `/rest/playbook_run` with playbook ID or name and container ID. This initiates automated investigation workflow.

7. **Poll action results**: GET `/rest/action_run` filtered by container ID to monitor playbook progress. Poll until all actions reach terminal state (success, failed, or cancelled).

8. **Compile response report**: Aggregate playbook action results into summary report with verdicts from URL reputation, domain reputation, IP geolocation, and email header analysis.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-soar-playbook-for-phishing
