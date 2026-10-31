---
name: conducting-phishing-incident-response
description: Respond to phishing incidents by analyzing reported emails, extracting indicators, sandboxing URLs/attachments, assessing credential compromise, quarantining malicious messages organization-wide, and remediating affected accounts.
subdomain: incident-response
facing: defense
mitre_attack:
- T1566.001
- T1566.002
- T1204.002
- T1204.001
- T1114
- T1056.003
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: conducting-phishing-incident-response@54a7988 Apache-2.0, modified by wesh
---
Not for: business email compromise (BEC) involving compromised internal accounts; use BEC response procedures which focus on account takeover investigation.

## Prerequisites

- Email security gateway with message trace and quarantine capabilities (Microsoft Defender for Office 365, Proofpoint, Mimecast)
- Microsoft 365 admin access or Google Workspace admin for mailbox search and purge
- Malware sandbox for attachment and URL analysis (ANY.RUN, Joe Sandbox, Hybrid Analysis)
- Email header analysis tools (MXToolbox Header Analyzer, Google Admin Toolbox)
- Identity provider access for account remediation (Azure AD, Okta, Duo)
- Phishing report intake process (dedicated mailbox or integrated report button)

## Workflow

### Step 1: Receive and Triage Phishing Report

Evaluate reported email to determine if it is malicious:

- Extract email as an .EML or .MSG file (preserves headers)
- Analyze email headers to determine true sender, relay path, and authentication results

```
Email Header Analysis Checklist:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Return-Path:     billing@spoofed-domain[.]com
From:            "IT Support" <support@corp-lookalike[.]com>
Reply-To:        attacker@gmail[.]com (different from From)
SPF:             FAIL (sender IP not authorized for domain)
DKIM:            FAIL (signature invalid)
DMARC:           FAIL (policy: none - no enforcement)
Received:        from mail.attacker-infra[.]net [45.33.x.x]
X-Originating-IP: 45.33.x.x
Message-ID:      <random@attacker-infra.net>
```

Classification criteria:
- **Confirmed Phishing**: Malicious URL/attachment, spoofed sender, credential harvesting page
- **Suspicious**: Anomalous headers but no confirmed malicious content
- **Spam/Marketing**: Unwanted but not malicious
- **Legitimate**: Not phishing email (false report)

### Step 2: Analyze Malicious Content

Examine URLs and attachments in safe environment:

**URL Analysis:**
- Check URL against VirusTotal, URLscan.io, and Google Safe Browsing
- Open URL in sandbox browser to capture landing page
- Check if URL redirects to credential harvesting page
- Identify phishing kit type (Microsoft 365 login clone, Okta clone, generic)
- Determine if phishing page is still active

**Attachment Analysis:**
- Calculate file hash (SHA-256) and check against VirusTotal
- Detonate in sandbox (ANY.RUN, Joe Sandbox)
- Analyze document for macros (olevba for Office files)
- Check for embedded exploits (CVE exploitation in document parsers)

### Step 3: Determine Scope of Impact

Identify all recipients and assess who interacted with phishing email:

```
Scope Assessment:
━━━━━━━━━━━━━━━━
Total Recipients:     47 users
Delivered to Inbox:   38 users (9 caught by email gateway)
Opened Email:         24 users (email tracking pixel data)
Clicked Link:         8 users (proxy/firewall logs)
Entered Credentials:  3 users (phishing page submitted form data)
Opened Attachment:    2 users (EDR process execution telemetry)
```

Search methods:
- Microsoft 365: Use Threat Explorer or Content Search to find all instances of email
- Google Workspace: Use Admin Console > Investigation tool for message search
- Proxy logs: Search for connections to phishing URL from internal IPs
- EDR: Search for attachment file hash execution across all endpoints

### Step 4: Contain Threat

Execute containment actions based on impact assessment:

**Email Containment:**
- Purge phishing email from all mailboxes using Microsoft 365 Content Search and Purge or Google Workspace Admin delete
- Block sender domain at email gateway
- Add phishing URL to web proxy blocklist
- Add attachment hash to email gateway and EDR blocklists

**Account Containment (for users who entered credentials):**
- Force password reset immediately
- Revoke all active sessions and OAuth tokens
- Enable or re-verify MFA enrollment
- Review mailbox rules for attacker-created forwarding rules
- Check for unauthorized OAuth application grants
- Review recent sign-in activity for suspicious locations

```powershell
# Microsoft 365: Revoke sessions and reset password
Connect-AzureAD
Revoke-AzureADUserAllRefreshToken -ObjectId "user@corp.com"
Set-AzureADUserPassword -ObjectId "user@corp.com" -ForceChangePasswordNextLogin $true
# Check for mailbox forwarding rules
Get-InboxRule -Mailbox "user@corp.com" | Where-Object {$_.ForwardTo -or $_.RedirectTo}
# Remove suspicious forwarding rules
Remove-InboxRule -Mailbox "user@corp.com" -Identity "Rule Name"
```

### Step 5: Eradicate and Recover

Remove all traces of phishing attack:

- Confirm email purge completed successfully across all mailboxes
- Verify compromised accounts have been secured (password changed, sessions revoked, MFA verified)
- Remove any malware installed via phishing attachments from affected endpoints
- Monitor compromised accounts for 72 hours for signs of continued unauthorized access
- Check for data exfiltration from compromised accounts during exposure window

### Step 6: Post-Incident Actions

Strengthen defenses against similar phishing attacks:

- Report phishing URL to Google Safe Browsing and Microsoft SmartScreen
- Submit phishing domain for takedown via domain registrar abuse contact
- Update email gateway filtering rules based on observed evasion techniques
- Send targeted security awareness notification to affected users
- Update phishing simulation program to include observed technique

## Key Concepts

| Term | Definition |
|------|------------|
| **Spear Phishing** | Targeted phishing attack crafted for specific individual or organization using personalized content |
| **Credential Harvesting** | Phishing technique that mimics legitimate login page to capture usernames and passwords |
| **SPF (Sender Policy Framework)** | Email authentication protocol that specifies which mail servers are authorized to send email for domain |
| **DKIM (DomainKeys Identified Mail)** | Email authentication method using cryptographic signatures to verify that email was not altered in transit |
| **DMARC** | Policy framework that uses SPF and DKIM to determine email authenticity and instructs receivers on handling failures |
| **OAuth Consent Phishing** | Attack that tricks users into granting malicious OAuth applications access to their email and data |
| **Email Header** | Metadata embedded in every email containing routing, authentication, and sender information used for forensic analysis |

## Tools & Systems

- **Microsoft Defender for Office 365**: Email threat protection with Threat Explorer for investigation and automated purge
- **Proofpoint TAP (Targeted Attack Protection)**: Email security platform with URL rewriting and attachment sandboxing
- **URLscan.io**: Online service that scans URLs and captures screenshots of phishing pages for evidence
- **PhishTool**: Phishing analysis platform that automates header analysis, URL inspection, and IOC extraction
- **GoPhish**: Open-source phishing simulation platform for security awareness testing

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-phishing-incident-response
