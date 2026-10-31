---
name: performing-insider-threat-investigation
description: Investigates insider threat incidents involving employees, contractors, or trusted partners who misuse authorized access to steal data, sabotage systems, or violate security policies, combining digital forensics, user behavior analytics, and HR/legal coordination to build an evidence-based case.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1490
- T1070
- T1078
- T1048
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: performing-insider-threat-investigation@54a7988 Apache-2.0, modified by wesh
---
Not for: external attacker investigations where compromised credentials are used without insider collusion; use standard incident response procedures instead.

## Prerequisites

- Legal counsel approval before initiating any monitoring or investigation of employee
- HR partnership with defined investigation procedures and employee privacy guidelines
- DLP platform with content inspection and policy enforcement (Symantec DLP, Microsoft Purview, Digital Guardian)
- User behavior analytics platform (Microsoft Sentinel UEBA, Exabeam, Securonix)
- Forensic imaging capability for endpoint examination
- Chain of custody procedures for evidence that may be used in legal proceedings
- Clear authority and scope documentation approved by legal and HR

## Workflow

### Step 1: Receive and Validate Allegation

Document initial report and validate before proceeding:

- Record source of allegation (DLP alert, UBA detection, HR referral, manager report)
- Confirm with legal counsel that investigation is authorized
- Define investigation scope: what activity is being investigated, time period, systems involved
- Establish investigation team: security, legal, HR (never investigate alone)
- Create restricted case file accessible only to investigation team

```
Investigation Authorization:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Case ID:           INV-2025-042
Subject:           [Employee Name] - [Title] - [Department]
Allegation:        Unauthorized transfer of proprietary data to personal cloud storage
Reported By:       DLP system alert + manager concern
Legal Approval:    [Counsel Name] - 2025-11-15
HR Liaison:        [HR Name]
Scope:             File access and transfer activity from 2025-10-01 to present
Systems in Scope:  Workstation, email, cloud storage, VPN, DLP logs
```

### Step 2: Collect Evidence Covertly

Gather evidence without alerting subject to investigation:

**Log-Based Evidence (non-intrusive):**
- DLP logs: file transfers, policy violations, content matches
- Cloud access logs: SharePoint, OneDrive, Google Drive activity
- Email logs: messages to personal accounts, large attachments, forwarding rules
- VPN and authentication logs: access times, locations, devices
- Badge access logs: physical access patterns
- Print logs: large print jobs of sensitive documents
- USB device connection logs: device type, serial number, connection times

**User Activity Monitoring (requires legal approval):**
- Screen capture or session recording (only if legally authorized and documented)
- Keystroke logging (jurisdiction-dependent, requires explicit legal approval)
- Network traffic capture for subject's workstation

**Endpoint Forensics (if warranted by evidence):**
- Create forensic image of subject's workstation
- Analyze browser history, download history, and installed applications
- Examine deleted files and Recycle Bin contents
- Review cloud sync application logs (Dropbox, Google Drive desktop client)

### Step 3: Analyze User Behavior Patterns

Build behavioral profile comparing normal vs. anomalous activity:

```
Behavioral Analysis:
━━━━━━━━━━━━━━━━━━
Normal Baseline (6-month average):
- Login time: 08:30-09:00 weekdays
- Files accessed: 15-25 per day (marketing department files)
- Email volume: 45 sent, 80 received per day
- Data transferred: 50MB per day average
- USB usage: None
Investigation Period (last 30 days):
- Login time: 22:00-02:00 (after hours, multiple occasions)
- Files accessed: 200+ per day (finance, engineering, executive files)
- Email volume: 120 sent per day (30% to personal gmail)
- Data transferred: 2.5GB per day average
- USB usage: 3 unique devices connected (Kingston DataTraveler)
- Print jobs: 847 pages (competitor analysis, customer lists, source code)
Anomaly Score: 94/100 (Critical)
```

### Step 4: Reconstruct Activity Timeline

Build chronological timeline of subject's actions:

```
Timeline of Activity:
2025-10-15  Subject submits resignation (2-week notice)
2025-10-16  First after-hours login at 23:15, accessed engineering Git repository
2025-10-17  USB device (Kingston DT 64GB) first connected at 23:30
2025-10-18  DLP alert: 450 files copied to USB, including CAD drawings
2025-10-19  200+ emails forwarded to personal Gmail account
2025-10-20  Google Drive desktop client installed, syncing corporate SharePoint
2025-10-22  Accessed executive SharePoint site (not normally accessed)
2025-10-25  Second USB device connected, 2.1GB transferred
2025-10-28  Print job: 847 pages including customer contact database
```

### Step 5: Assess Impact and Determine Response

Evaluate severity and coordinate response with HR and legal:

**Impact Assessment:**
- What data was accessed or exfiltrated (classification level, business impact)
- Was data shared externally (competitors, public, personal storage)
- Regulatory implications (PII, PHI, financial data, export-controlled)
- Contractual implications (NDA violations, IP assignment agreements)
- Potential financial damage to organization

**Response Options (determined by legal and HR):**
- Confront subject with evidence during interview (HR-led)
- Terminate employment and revoke all access immediately
- Pursue civil litigation for breach of NDA or trade secret theft
- Refer to law enforcement for criminal prosecution (theft of trade secrets, CFAA violation)
- Negotiate settlement with return/destruction of data

### Step 6: Preserve Evidence for Legal Proceedings

Ensure all evidence meets legal admissibility standards:

- Maintain strict chain of custody for all physical and digital evidence
- Document all analysis steps in detail (reproducible by another examiner)
- Hash all evidence files and maintain integrity log
- Store evidence in secure, access-controlled repository with audit logging
- Retain evidence per legal hold requirements (do not destroy during active investigation or litigation)

## Key Concepts

| Term | Definition |
|------|------------|
| **Insider Threat** | Risk posed by individuals with authorized access who intentionally or unintentionally cause harm to organization |
| **User Behavior Analytics (UBA)** | Technology that analyzes user activity patterns to detect anomalies indicating potential insider threats |
| **Data Loss Prevention (DLP)** | Technology that monitors, detects, and blocks unauthorized transfer of sensitive data outside organization |
| **Legal Hold** | Directive to preserve all relevant evidence and suspend normal document destruction policies during investigation |
| **Need to Know** | Information access principle restricting insider threat investigation details to only authorized team members |
| **Exfiltration Vector** | Method used to move data outside organization: USB, email, cloud storage, print, screen capture, photography |

## Tools & Systems

- **Microsoft Purview (formerly Compliance Center)**: Insider risk management, DLP, eDiscovery, and content search
- **Exabeam / Securonix**: User and entity behavior analytics (UEBA) platforms for anomaly detection
- **Digital Guardian**: DLP and insider threat detection platform with endpoint agent
- **Magnet AXIOM**: Digital forensics platform supporting endpoint, cloud, and mobile evidence analysis
- **Relativity**: eDiscovery platform for legal review of collected evidence in insider threat cases

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-insider-threat-investigation
