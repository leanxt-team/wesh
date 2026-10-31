---
name: performing-dynamic-analysis-with-any-run
description: Perform interactive dynamic malware analysis using the ANY.RUN cloud sandbox to detonate samples, observe real-time execution behavior, interact with malware prompts such as dialogs and CAPTCHAs, and capture process trees, network traffic, and system changes.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1027
- T1055
- T1140
- T1497
- T1591
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: performing-dynamic-analysis-with-any-run@54a7988 Apache-2.0, modified by wesh
---
Not for: highly sensitive samples that cannot be uploaded to cloud services; use an on-premises sandbox like Cuckoo instead.

## Prerequisites

- ANY.RUN account (free community tier or paid subscription at https://any.run)
- Modern web browser with WebSocket support for interactive session streaming
- Sample file ready for upload (max 100 MB for free tier, 256 MB for paid)
- Understanding of sample type to select appropriate execution environment
- VPN or secure network for accessing ANY.RUN portal during analysis sessions

## Workflow

### Step 1: Configure Analysis Environment

Set up ANY.RUN task with appropriate parameters:

```
ANY.RUN Task Configuration:
━━━━━━━━━━━━━━━━━━━━━━━━━━
OS Selection:        Windows 10 x64 (recommended default)
                     Windows 7 x64 (for legacy malware)
                     Windows 11 x64 (for modern samples)
Execution Time:      60 seconds (default) / 120-300 for slow-acting malware
Network:             Connected (captures real C2 traffic)
                     Residential Proxy (bypasses geo-blocking)
Privacy:             Public (free tier) / Private (paid - not indexed)
MITM Proxy:          Enable for HTTPS traffic decryption
Fake Net:            Enable to simulate internet services if sample checks connectivity
```

**API-based submission (paid tier):**
```bash
# Submit file via ANY.RUN API
curl -X POST "https://api.any.run/v1/analysis" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -F "file=@suspect.exe" \
  -F "env_os=windows" \
  -F "env_version=10" \
  -F "env_bitness=64" \
  -F "opt_timeout=120" \
  -F "opt_network_connect=true" \
  -F "opt_privacy_type=bylink"
# Check task status
curl "https://api.any.run/v1/analysis/$TASK_ID" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" | jq '.data.status'
```

### Step 2: Interact with Malware During Execution

Use interactive session to trigger malware behavior:

```
Interactive Actions During Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Document Macros:   Click "Enable Content" / "Enable Editing" when prompted
2. Installer Screens: Click through installation dialogs
3. UAC Prompts:       Click "Yes" to allow elevation (observe privilege escalation)
4. Credential Harvests: Enter fake credentials to observe phishing behavior
5. Browser Redirects:  Navigate to URLs if malware opens browser windows
6. File Dialogs:       Select target files if malware presents file picker
7. Timeout Extension:  Extend analysis time if malware has delayed execution
```

### Step 3: Analyze Process Tree

Review complete process execution chain:

```
Process Tree Analysis Points:
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Parent-Child Relationships:
  - WINWORD.EXE -> cmd.exe -> powershell.exe (macro execution chain)
  - explorer.exe -> suspect.exe -> svchost.exe (process injection)
Process Events to Note:
  - Process creation with suspicious command-line arguments
  - PowerShell with encoded commands (-enc / -encodedcommand)
  - cmd.exe executing script files (.bat, .vbs, .js)
  - Legitimate processes spawned from unusual parents
  - Process termination (self-deletion behavior)
```

### Step 4: Review Network Activity

Examine DNS, HTTP/HTTPS, and TCP/UDP connections:

```
ANY.RUN Network Panel Analysis:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DNS Requests:
  - Domain resolutions with threat intelligence tags
  - Fast-flux or DGA domain patterns
  - DNS over HTTPS (DoH) detection
HTTP/HTTPS Traffic (with MITM enabled):
  - Full request/response bodies for HTTP
  - Decrypted HTTPS traffic showing C2 commands
  - Downloaded payloads and their content types
  - POST data containing exfiltrated information
Connection Map:
  - Geographic visualization of C2 server locations
  - Connection timeline showing beacon patterns
  - Suricata alerts triggered on network traffic
```

### Step 5: Examine IOCs and Threat Intelligence

Extract indicators and map to known threats:

```
ANY.RUN IOC Categories:
━━━━━━━━━━━━━━━━━━━━━━
Files:       Dropped files with hashes, YARA matches, VirusTotal results
Network:     IPs, domains, URLs contacted during execution
Registry:    Keys created/modified for persistence
Processes:   Suspicious process names and command lines
Mutex:       Named mutexes created (used for single-instance checking)
Signatures:  Suricata rules triggered, behavioral signatures matched
MITRE ATT&CK Mapping:
  - ANY.RUN automatically maps observed behaviors to ATT&CK techniques
  - Review the ATT&CK matrix tab for technique coverage
  - Export ATT&CK Navigator layer for reporting
```

### Step 6: Export Analysis Results

Download comprehensive reports and artifacts:

```bash
# Download report via API
curl "https://api.any.run/v1/analysis/$TASK_ID/report" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o report.json
# Download PCAP
curl "https://api.any.run/v1/analysis/$TASK_ID/pcap" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o capture.pcap
# Download dropped files
curl "https://api.any.run/v1/analysis/$TASK_ID/files" \
  -H "Authorization: API-Key $ANYRUN_API_KEY" \
  -o dropped_files.zip
# Available exports from ANY.RUN web interface:
# - HTML Report (shareable standalone page)
# - PCAP file (network traffic capture)
# - Process dump (memory dumps of processes)
# - Dropped files (all files created during execution)
# - MITRE ATT&CK Navigator JSON
# - IOC export (STIX/JSON/CSV format)
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Interactive Sandbox** | Analysis environment allowing real-time analyst interaction with executing sample, enabling triggering of user-dependent behaviors |
| **MITM Proxy** | Man-in-the-middle TLS interception in ANY.RUN that decrypts HTTPS traffic for visibility into encrypted C2 communications |
| **Residential Proxy** | ANY.RUN feature routing malware traffic through residential IP addresses to bypass geo-IP and datacenter-IP evasion checks |
| **Suricata Alerts** | Network IDS signatures triggered during execution, providing immediate identification of known malicious traffic patterns |
| **Process Tree** | Hierarchical visualization of parent-child process relationships showing complete execution chain from initial sample to final payloads |
| **Behavioral Tags** | ANY.RUN classification labels automatically applied based on observed behavior (e.g., "trojan", "stealer", "ransomware") |

## Tools & Systems

- **ANY.RUN**: Cloud-based interactive malware sandbox providing real-time execution monitoring, process trees, network capture, and MITRE ATT&CK mapping
- **ANY.RUN API**: REST API for programmatic sample submission, status checking, and report/artifact retrieval
- **Suricata**: Integrated network IDS within ANY.RUN providing signature-based detection of malicious network traffic
- **MITRE ATT&CK Navigator**: Framework integration mapping observed malware behaviors to adversary techniques and tactics
- **VirusTotal Integration**: Automatic hash lookup of sample and dropped files against VirusTotal detection results

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-dynamic-analysis-with-any-run
