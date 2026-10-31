---
name: collecting-indicators-of-compromise
description: Systematically collects, categorizes, and distributes indicators of compromise (IOCs) during and after security incidents to enable detection, blocking, and threat intelligence sharing.
subdomain: incident-response
facing: defense
mitre_attack:
- T1071.001
- T1071.004
- T1053.005
- T1547.001
- T1059.001
- T1041
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: collecting-indicators-of-compromise@54a7988 Apache-2.0, modified by wesh
---
Not for: behavioral TTP analysis without accompanying technical indicators; use MITRE ATT&CK mapping for behavioral characterization.

## Prerequisites

- Access to incident evidence sources: SIEM logs, EDR telemetry, memory dumps, disk images, network captures
- Threat intelligence platform (MISP, OpenCTI, ThreatConnect) for IOC management and sharing
- IOC enrichment tools: VirusTotal, OTX (AlienVault Open Threat Exchange), Shodan, DomainTools
- STIX 2.1 knowledge for structured IOC representation
- Sharing agreements with relevant ISACs (FS-ISAC, H-ISAC, IT-ISAC) or sector partners

## Workflow

### Step 1: Identify IOC Categories

Collect indicators across all categories from incident evidence:

**Network Indicators:**
- IP addresses (C2 servers, staging servers, exfiltration destinations)
- Domain names (C2 domains, phishing domains, DGA domains)
- URLs (malware download, C2 check-in, exfiltration endpoints)
- JA3/JA3S hashes (TLS client/server fingerprints)
- User-Agent strings (custom or unusual HTTP headers)
- DNS query patterns (tunneling signatures, DGA patterns)

**Host Indicators:**
- File hashes (MD5, SHA-1, SHA-256 of malware, tools, scripts)
- File paths (known malware installation directories)
- Registry keys (persistence mechanisms, configuration storage)
- Scheduled tasks and service names (persistence)
- Mutex/event names (malware instance synchronization)
- Named pipes (C2 communication channels, e.g., Cobalt Strike)

**Email Indicators:**
- Sender addresses and domains (spoofed or attacker-controlled)
- Subject lines and body content patterns
- Attachment names and hashes
- Embedded URLs
- Email header anomalies (SPF/DKIM/DMARC failures)

### Step 2: Extract IOCs from Evidence Sources

Systematically extract indicators from each evidence source:

**From SIEM/Log Analysis:**
```
# Extract unique destination IPs from firewall logs
index=firewall action=blocked
| stats count by dest_ip
| where count > 100
# Extract domains from DNS query logs
index=dns query=*evil* OR query=*c2*
| stats count by query
```

**From Memory Forensics:**
```bash
# Extract network connections
vol -f memory.raw windows.netscan | grep ESTABLISHED
# Extract strings from suspicious process memory
vol -f memory.raw windows.memmap --pid 3847 --dump
strings -n 8 pid.3847.dmp | grep -E "(http|https)://"
```

**From Malware Analysis:**
```
Sandbox Report IOC Extraction:
- Dropped files:      3 (hashes extracted)
- DNS queries:        update.evil[.]com, cdn.malware[.]net
- HTTP connections:   POST to https://185.220.101[.]42/gate.php
- Registry modified:  HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svcupdate
- Mutex created:      Global\MTX_0x1234ABCD
- Named pipe:         \\.\pipe\MSSE-1234-server
```

### Step 3: Enrich IOCs with Context

Add threat intelligence context to each indicator:

```
IOC Enrichment Report:
━━━━━━━━━━━━━━━━━━━━━
IP: 185.220.101.42
  VirusTotal:     12/89 vendors flag as malicious
  Shodan:         Open ports: 443, 8443, 80
  Geolocation:    Netherlands, AS208476
  First Seen:     2025-10-01
  Threat Intel:   Associated with Qakbot C2 infrastructure
  Confidence:     High
  TLP:            AMBER
Domain: update.evil[.]com
  Registration:   2025-10-28 (recently registered)
  Registrar:      Namecheap
  WHOIS Privacy:  Yes
  VirusTotal:     8/89 vendors flag as malicious
  DNS History:    Resolved to 185.220.101.42, 91.215.85.17
  Confidence:     High
  TLP:            AMBER
```

### Step 4: Score and Prioritize IOCs

Assign confidence and risk scores to each indicator:

| Score | Confidence Level | Criteria |
|-------|-----------------|----------|
| 90-100 | Confirmed Malicious | Multiple TI sources confirm, observed in active attack |
| 70-89 | Suspicious | Single TI source confirms, behavioral analysis supports |
| 50-69 | Suspicious | Limited TI data, contextually suspicious |
| 30-49 | Unconfirmed | No TI matches, but anomalous in environment |
| 0-29 | Likely Benign | False positive indicators or legitimate infrastructure |

### Step 5: Distribute IOCs for Detection and Blocking

Push IOCs to defensive systems for immediate protection:

- **Firewall/IPS**: Block C2 IPs and domains
- **DNS**: Sinkhole malicious domains
- **EDR**: Add file hashes to blocklist, create custom IOC watchlists
- **Email Gateway**: Block sender domains, attachment hashes, malicious URLs
- **SIEM**: Create correlation searches for IOC matches
- **Web Proxy**: Block URLs and domains in web filtering policy

### Step 6: Share IOCs with Partners

Package IOCs in STIX 2.1 format for sharing:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "created": "2025-11-15T18:00:00Z",
  "modified": "2025-11-15T18:00:00Z",
  "name": "Qakbot C2 Server IP",
  "indicator_types": ["malicious-activity"],
  "pattern": "[ipv4-addr:value = '185.220.101.42']",
  "pattern_type": "stix",
  "valid_from": "2025-11-15T14:23:00Z",
  "confidence": 95,
  "labels": ["c2", "qakbot"],
  "object_marking_refs": ["marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"]
}
```

Submit to MISP, ISAC portals, and TAXII servers per sharing agreements.

## Key Concepts

| Term | Definition |
|------|------------|
| **IOC (Indicator of Compromise)** | Technical artifact observed during security incident that indicates adversary presence (hash, IP, domain, etc.) |
| **TLP (Traffic Light Protocol)** | Standard for classifying sharing restrictions of threat intelligence: WHITE, GREEN, AMBER, AMBER+STRICT, RED |
| **STIX (Structured Threat Information Expression)** | Standard language for representing cyber threat intelligence in structured, machine-readable format |
| **TAXII (Trusted Automated Exchange of Intelligence Information)** | Transport protocol for sharing STIX-formatted threat intelligence between organizations |
| **Confidence Score** | Numerical rating (0-100) indicating analyst's certainty that indicator is truly malicious |
| **IOC Lifecycle** | Process of creating, validating, distributing, and eventually retiring indicators as they lose relevance |
| **Defanging** | Practice of modifying malicious URLs and domains in reports to prevent accidental clicks (e.g., evil[.]com) |

## Tools & Systems

- **MISP**: Open-source threat intelligence sharing platform for managing, storing, and distributing IOCs
- **VirusTotal**: Multi-engine malware scanning and threat intelligence platform for IOC enrichment
- **OpenCTI**: Open-source cyber threat intelligence platform supporting STIX 2.1 natively
- **Yeti**: Open-source platform for organizing observables, indicators, and TTPs
- **CyberChef**: GCHQ's data transformation tool useful for decoding, defanging, and formatting IOCs

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/collecting-indicators-of-compromise
