---
name: triaging-security-incident
description: Performs initial triage of security incidents using the NIST SP 800-61r3 and SANS PICERL frameworks, classifying incident type, assigning priority by business impact, and routing to the appropriate response team.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1490
- T1070
- T1078
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: triaging-security-incident@54a7988 Apache-2.0, modified by wesh
---
Not for: routine vulnerability scanning results or compliance audit findings that do not represent active security incidents.

## Prerequisites

- Access to SIEM platform (Splunk, Elastic, Microsoft Sentinel) with current alert data
- Incident classification taxonomy aligned to NIST SP 800-61r3 categories
- Predefined severity matrix mapping asset criticality to threat type
- Contact roster for escalation paths (Tier 1 through Tier 3 and CIRT)
- Asset inventory with business criticality ratings

## Workflow

### Step 1: Collect Initial Alert Data

Gather all available context from triggering alert before making classification decisions:

- **Alert source**: Which detection system generated alert (EDR, SIEM, IDS/IPS, firewall, user report)
- **Timestamp**: When event occurred and when it was detected (dwell time gap)
- **Affected assets**: Hostnames, IP addresses, user accounts involved
- **Alert fidelity**: Historical true-positive rate for this detection rule
- **Raw evidence**: Log entries, packet captures, process execution chains

```
Example SIEM alert context:
Source:       CrowdStrike Falcon
Detection:    Suspicious PowerShell Execution (T1059.001)
Host:         WORKSTATION-FIN-042
User:         jsmith@corp.example.com
Timestamp:    2025-11-15T14:23:17Z
Severity:     High (detection rule confidence: 92%)
Process:      powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
Parent:       outlook.exe (PID 4812)
```

### Step 2: Classify Incident Type

Map alert to standard incident category per NIST SP 800-61r3:

| Category | Examples |
|----------|----------|
| Unauthorized Access | Compromised credentials, privilege escalation, IDOR |
| Denial of Service | Volumetric DDoS, application-layer flood, resource exhaustion |
| Malicious Code | Malware execution, ransomware detonation, cryptominer |
| Improper Usage | Policy violation, insider data exfiltration, shadow IT |
| Reconnaissance | Port scanning, directory enumeration, credential spraying |
| Web Application Attack | SQL injection, XSS, SSRF exploitation |

### Step 3: Assign Severity Using Impact Matrix

Calculate severity by combining asset criticality with threat severity:

```
Severity = f(Asset Criticality, Threat Type, Data Sensitivity, Lateral Movement Potential)
Critical (P1): Crown jewel systems compromised, active data exfiltration, ransomware spreading
High (P2):     Production system compromise, confirmed malware execution, privileged account takeover
Medium (P3):   Non-production compromise, unsuccessful exploitation attempt, single endpoint malware
Low (P4):      Reconnaissance activity, policy violation, benign true positive
```

Response SLA targets:
- P1: Acknowledge within 15 minutes, containment within 1 hour
- P2: Acknowledge within 30 minutes, containment within 4 hours
- P3: Acknowledge within 2 hours, investigation within 24 hours
- P4: Acknowledge within 8 hours, investigation within 72 hours

### Step 4: Perform Initial Enrichment

Before escalation, enrich alert with contextual data:

- **Threat intelligence**: Check IOCs (IP, hash, domain) against TI platforms (VirusTotal, OTX, MISP)
- **Asset context**: Query CMDB for asset owner, business function, data classification
- **User context**: Check identity provider for recent authentication anomalies, MFA status
- **Historical correlation**: Search for related alerts on same host/user in past 30 days
- **Network context**: Verify if source/destination IPs are internal, known partners, or external threat actors

### Step 5: Document and Escalate

Create structured triage record and route to appropriate response tier:

```
Incident Triage Record
━━━━━━━━━━━━━━━━━━━━━
Ticket ID:       INC-2025-1547
Triage Analyst:  [analyst name]
Triage Time:     2025-11-15T14:35:00Z (12 min from alert)
Classification:  Malicious Code - Macro-based initial access
Severity:        P2 - High
Affected Assets: WORKSTATION-FIN-042 (Finance dept, handles PII)
Affected Users:  jsmith@corp.example.com
IOCs Identified: powershell.exe spawned by outlook.exe, encoded command
TI Matches:      Base64 payload matches known Qakbot loader pattern
Escalation:      Tier 2 - Malware IR team
Recommended:     Isolate endpoint, preserve memory dump, block sender domain
```

### Step 6: Initiate Containment Hold

If severity is P1 or P2, initiate immediate containment actions while awaiting full investigation:

- Network-isolate affected endpoint via EDR (CrowdStrike contain, Defender isolate)
- Disable compromised user accounts in Active Directory or identity provider
- Block identified malicious IPs/domains at firewall and DNS sinkhole
- Preserve volatile evidence (memory dump) before any remediation

## Key Concepts

| Term | Definition |
|------|------------|
| **Triage** | Rapid assessment process to classify and prioritize security incidents based on severity and business impact |
| **PICERL** | SANS incident response framework: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned |
| **Dwell Time** | Duration between initial compromise and detection; average is 10 days per Mandiant M-Trends 2025 |
| **True Positive Rate** | Percentage of alerts from detection rule that represent genuine security incidents |
| **Crown Jewel Assets** | Systems and data critical to business operations whose compromise would cause severe organizational impact |
| **Alert Fatigue** | Degraded analyst performance caused by high volumes of low-fidelity or false-positive alerts |
| **Mean Time to Acknowledge (MTTA)** | Average time from alert generation to analyst acknowledgment; key SOC performance metric |

## Tools & Systems

- **Splunk Enterprise Security**: SIEM platform for alert aggregation, correlation, and triage workflow management
- **CrowdStrike Falcon**: EDR platform providing endpoint telemetry, detection, and one-click host containment
- **TheHive**: Open-source incident response platform for case management, task tracking, and team collaboration
- **MISP**: Threat intelligence sharing platform for IOC enrichment during triage
- **Cortex XSOAR**: SOAR platform for automating enrichment playbooks and triage decision trees

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/triaging-security-incident
