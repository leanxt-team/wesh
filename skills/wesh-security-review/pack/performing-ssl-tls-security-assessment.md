---
name: performing-ssl-tls-security-assessment
description: Assess SSL/TLS server configurations using the sslyze Python scanning library to evaluate supported protocol versions, cipher suite strength, certificate chain validation, HSTS enforcement, OCSP stapling, and known vulnerabilities such as Heartbleed and ROBOT.
subdomain: network-security
facing: defense
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1553
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: performing-ssl-tls-security-assessment@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with `sslyze` library (pip install sslyze)
- Network access to target HTTPS servers on port 443
- Understanding of TLS protocol versions and cipher suite classifications

## Steps

### Step 1: Configure Server Scan
Create ServerScanRequest with ServerNetworkLocation specifying target hostname and port.

### Step 2: Execute TLS Scan
Use sslyze Scanner to queue and execute scans for all TLS check commands concurrently.

### Step 3: Analyze Results
Evaluate accepted cipher suites, certificate validity, protocol versions, and vulnerability scan results.

### Step 4: Generate Security Report
Produce JSON report with compliance findings and remediation recommendations.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-ssl-tls-security-assessment
