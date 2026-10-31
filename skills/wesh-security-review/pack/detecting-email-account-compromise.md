---
name: detecting-email-account-compromise
description: Detect compromised O365 and Google Workspace email accounts by analyzing Unified Audit Logs and Azure AD sign-in logs for impossible travel, inbox rule creation/deletion (Set-InboxRule, New-InboxRule), external mail forwarding rules, and unusual Microsoft Graph API access or OAuth token use.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1490
- T1070
- T1078
- T1566
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: detecting-email-account-compromise@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Microsoft 365 with Unified Audit Logging enabled
- Azure AD P1/P2 for risk detection APIs
- Python 3.9+ with `requests`, `msal` libraries
- Microsoft Graph API application registration with Mail.Read, AuditLog.Read.All permissions
- Understanding of OAuth2 client credential flows

## Steps

1. Export audit logs or connect to Microsoft Graph API using MSAL authentication
2. Query inbox rules for all monitored mailboxes via `/users/{id}/mailFolders/inbox/messageRules`
3. Analyze rules for external forwarding (ForwardTo, RedirectTo external addresses)
4. Detect suspicious rule patterns: deletion rules, keyword-matching rules targeting financial terms
5. Query sign-in logs via `/auditLogs/signIns` for unusual locations and impossible travel
6. Check for suspicious user agent strings (python-requests, PowerShell, curl)
7. Identify OAuth application consent grants for suspicious third-party apps
8. Correlate findings across users to detect campaign-level compromise
9. Generate compromise indicators report with severity scores

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-email-account-compromise
