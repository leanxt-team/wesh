---
name: executing-phishing-simulation-campaign
description: Executes authorized phishing simulation campaigns to assess an organization's susceptibility to email-based social engineering attacks.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1003
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: executing-phishing-simulation-campaign@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: without explicit written authorization from the organization's leadership, for actual credential theft beyond the authorized scope, for targeting individuals personally rather than professionally, or for sending phishing emails that could cause psychological harm or legal liability.

## Prerequisites

- Written authorization from executive leadership specifying campaign scope, target groups, and escalation procedures
- Coordination with IT/security team to whitelist sending infrastructure (or test whether it bypasses controls, depending on scope)
- GoPhish or equivalent phishing platform configured with sending domain, SMTP relay, and landing page infrastructure
- Phishing domain registered and configured with SPF, DKIM, and DMARC records to maximize deliverability
- Employee email list from HR, organized by department for targeted campaigns
- Incident response team briefed on campaign timeline and escalation procedures

## Workflow

### Step 1: Campaign Planning and Pretext Development

Design realistic phishing scenarios based on threats relevant to target organization:

- **Pretext selection**: Choose scenarios that mirror real-world attacks:
  - IT support: Password expiration notice requiring immediate action
  - HR department: Benefits enrollment, policy acknowledgment, W-2/tax document
  - Executive impersonation: Urgent request from CEO/CFO to review document
  - Vendor/supplier: Invoice requiring review, delivery notification
  - Cloud services: Microsoft 365 shared document, Google Drive access, Zoom meeting invitation
- **Target segmentation**: Divide employees into groups by department, role, or access level. High-value targets (finance, IT admin, executives) may receive more sophisticated pretexts.
- **Timing**: Schedule sends during business hours, preferably Tuesday-Thursday when email engagement is highest. Avoid holidays, mass layoff periods, or other sensitive times.
- **Success metrics**: Define what constitutes campaign success: email open rate, link click rate, credential submission rate, report rate (employees who report phish to IT)

### Step 2: Infrastructure Setup

Configure phishing infrastructure:

- **Domain registration**: Register domain that resembles target organization's domain (typosquatting, homograph, or brand-adjacent). Examples: `target-corp.com`, `targetcorp-portal.com`, `targetsupport.net`
- **SSL certificate**: Obtain TLS certificate for phishing domain (Let's Encrypt) to display padlock icon
- **GoPhish configuration**:
  - Set up GoPhish server on VPS with phishing domain
  - Configure SMTP sending profile with phishing domain's mail server
  - Create email template with tracking pixel and link to landing page
  - Build credential harvesting landing page that mirrors target's login portal
  - Import target email list and create user groups
- **Email authentication**: Configure SPF, DKIM, and DMARC records for phishing domain to pass email authentication checks and improve delivery rates
- **Test delivery**: Send test emails to controlled inbox to verify rendering, link tracking, and landing page functionality

### Step 3: Campaign Execution

Launch phishing campaign:

- Send emails in batches to avoid triggering rate limits or spam filters (e.g., 50 emails per hour)
- Monitor GoPhish dashboard in real-time for delivery failures, bounces, and early interactions
- Track metrics as they come in: emails sent, emails opened (tracking pixel fired), links clicked, credentials submitted
- If IT security team or SOC detects campaign (if this is part of test), document detection time and response actions
- Maintain emergency stop procedure: if employee becomes distressed or campaign creates unintended consequences, pause immediately
- Run campaign for 48-72 hours before closing landing page, as most interactions occur within first 24 hours

### Step 4: Credential Capture and Access Demonstration

Process captured credentials to demonstrate impact (if authorized):

- Review all captured credentials in GoPhish. Do not test credentials against real systems unless explicitly authorized.
- If authorized for full exploitation: test captured credentials against organization's actual login portal (VPN, OWA, SSO)
- Document any accounts that were successfully compromised, what data they could access, and whether MFA was present
- If MFA blocks access, document that MFA prevented compromise and recommend maintaining MFA enforcement
- Identify patterns in credential submissions: which departments, roles, or locations are most susceptible

### Step 5: Analysis and Reporting

Analyze campaign results and produce assessment report:

- **Metrics analysis**:
  - Email delivery rate: percentage of emails that reached inboxes
  - Open rate: percentage of recipients who opened email
  - Click rate: percentage who clicked phishing link
  - Submission rate: percentage who submitted credentials
  - Report rate: percentage who reported email to IT security
- **Departmental comparison**: Compare susceptibility rates across departments to identify groups needing targeted training
- **Email security effectiveness**: Document whether phishing emails bypassed secure email gateway, whether DMARC/SPF prevented delivery, and whether link scanning tools detected phishing URL
- **Recommendations**: Provide actionable recommendations including security awareness training topics, technical controls improvements, and policy changes

## Key Concepts

| Term | Definition |
|------|------------|
| **Pretext** | Fabricated scenario and social context used to persuade target to take desired action such as clicking link or entering credentials |
| **Credential Harvesting** | Collecting usernames and passwords through fake login pages that mimic legitimate services |
| **GoPhish** | Open-source phishing simulation platform that manages email templates, landing pages, target groups, and campaign tracking |
| **Spear Phishing** | Targeted phishing directed at specific individuals using personalized information gathered through reconnaissance |
| **Typosquatting** | Registering domains that are visually similar to legitimate domains through character substitution, addition, or omission |
| **Security Awareness** | Training programs designed to educate employees about social engineering threats and proper reporting procedures |
| **DMARC** | Domain-based Message Authentication, Reporting, and Conformance; email authentication protocol that prevents unauthorized use of domain for sending email |

## Tools & Systems

- **GoPhish**: Open-source phishing simulation framework providing campaign management, email templates, landing pages, and detailed analytics
- **Evilginx2**: Advanced phishing framework capable of capturing session tokens and bypassing multi-factor authentication through reverse proxy technique
- **King Phisher**: Phishing campaign toolkit with advanced features including two-factor authentication testing and geolocation tracking
- **SET (Social Engineering Toolkit)**: Framework for social engineering attacks including phishing, credential harvesting, and payload delivery

### Scenario: Enterprise Phishing Simulation for Security Awareness Baseline

**Context**: A 2,000-employee company has never conducted phishing simulation. CISO wants to establish baseline susceptibility rate before deploying new security awareness training program. Campaign should test all employees using realistic but not overly sophisticated pretext.

**Approach**:
1. Develop Microsoft 365 password expiration pretext: "Your password expires in 24 hours. Click here to update."
2. Register `m365-targetcorp.com`, set up GoPhish, and build landing page cloning Microsoft 365 login portal
3. Import all 2,000 employee emails and schedule sends in batches of 100 over 20 hours
4. Campaign results after 72 hours: 1,847 delivered (92.4%), 1,243 opened (67.3%), 487 clicked (26.4%), 312 submitted credentials (16.9%), 23 reported to IT (1.2%)
5. Analysis reveals Finance (28% submission) and Marketing (24% submission) have highest susceptibility; IT department has lowest (4%)
6. Recommend targeted training for high-susceptibility departments, phishing report button deployment, and quarterly simulation cadence

**Pitfalls**:
- Using overly aggressive or threatening pretexts that cause employee anxiety or legal issues
- Not coordinating with HR and legal before launching campaign, risking employee relations problems
- Sending all emails simultaneously, overwhelming email server or triggering bulk-send detection
- Focusing only on click and submission rates while ignoring critically low report rate (1.2%)

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/executing-phishing-simulation-campaign
