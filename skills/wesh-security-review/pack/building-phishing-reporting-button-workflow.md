---
name: building-phishing-reporting-button-workflow
description: Implement a phishing report button (Microsoft 365 built-in Report button or third-party like KnowBe4/Cofense) in email clients with a SOAR-driven automated triage workflow that classifies reported emails, extracts IOCs, takes remediation actions, and gives feedback to reporters.
subdomain: phishing-defense
facing: defense
mitre_attack:
- T1566.001
- T1566.002
- T1598.003
- T1204.001
- T1534
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
upstream: building-phishing-reporting-button-workflow@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- Microsoft 365 or Google Workspace with administrative access
- SOAR platform or automation capability (Microsoft Sentinel, Splunk SOAR, Cortex XSOAR)
- Dedicated reporting mailbox for phishing submissions
- Email security gateway with message retraction capability
- Security awareness training platform for feedback loop

## Workflow

### Step 1: Deploy Phishing Report Button
- Enable Microsoft built-in Report button via Security & Compliance Center
- Configure user reported settings: route to reporting mailbox and Microsoft
- For third-party: deploy KnowBe4 Phish Alert Button or Cofense Reporter
- Verify button appears in Outlook desktop, web, and mobile clients
- Configure report options: Report Phishing, Report Junk, Report Not Junk

### Step 2: Build Automated Triage Pipeline
- Configure reporting mailbox monitored by SOAR platform
- Auto-extract IOCs from reported emails: URLs, attachments, sender info, headers
- Submit URLs to VirusTotal, URLScan.io for reputation check
- Submit attachments to sandbox for dynamic analysis
- Check sender against known threat intelligence feeds
- Auto-classify: confirmed phishing, spam, simulation, legitimate

### Step 3: Implement Response Actions
- Confirmed phishing: auto-retract from all inboxes, block sender domain
- Confirmed spam: move to junk for all recipients
- Simulation email: mark as correctly reported, credit user
- Legitimate email: return to inbox, notify reporter
- Generate IOC report for threat intelligence team

### Step 4: Create Feedback Loop
- Send automated thank-you response to reporter within 5 minutes
- Include classification result when analysis completes
- Track reporter accuracy and engagement metrics
- Recognize top reporters in monthly security newsletter
- Feed reporting metrics into security awareness training program

### Step 5: Measure and Optimize
- Track mean time to triage (target: under 10 minutes automated)
- Monitor report volume trends and false positive rates
- Measure user reporting rate in phishing simulations
- Report on confirmed threats caught by user reports vs. gateway
- Optimize automation rules based on classification accuracy

## Tools & Resources
- **Microsoft Report Button**: Built-in Outlook phishing reporting
- **Cofense Reporter + Triage**: Enterprise phishing reporting and automated analysis
- **KnowBe4 Phish Alert Button**: Integrated reporting with simulation platform
- **Microsoft Sentinel**: SOAR automation for triage workflow
- **Proofpoint CLEAR**: Closed-loop email analysis and response

## Validation
- Report button visible and functional across all Outlook platforms
- Reported email arrives in dedicated mailbox within 60 seconds
- Automated triage classifies test phishing email correctly
- Auto-retraction removes confirmed phishing from all inboxes
- Reporter receives feedback notification with classification
- Metrics dashboard shows report volume and accuracy trends

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/building-phishing-reporting-button-workflow
