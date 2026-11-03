---
name: executing-red-team-exercise
description: Run a stealthy, MITRE ATT&CK-mapped adversary emulation against an organization's people, processes, and technology, using C2 infrastructure (Cobalt Strike, Sliver, Brute Ratel, Mythic) through the full attack lifecycle to test SOC detection and response rather than just find vulnerabilities.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1592
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: executing-red-team-exercise@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

Not for: without executive-level authorization and a detailed Rules of Engagement document, against systems where disruption could affect safety or critical operations, or as a replacement for basic vulnerability management (fix known vulnerabilities first).

## Prerequisites

- Executive-level written authorization with clearly defined objectives, scope, and off-limits systems
- Red team command and control (C2) infrastructure: primary and backup C2 channels with domain fronting or redirectors
- Operator workstations with OPSEC-hardened toolsets (Cobalt Strike, Sliver, Brute Ratel, or Mythic)
- Threat intelligence on adversary groups relevant to target organization for adversary emulation planning
- Trusted agent (white cell) within target organization who manages exercise boundaries without alerting defenders
- MITRE ATT&CK matrix for mapping planned and executed techniques

## Workflow

### Step 1: Adversary Emulation Planning

Develop operation plan based on realistic threat model:

- **Threat actor selection**: Select adversary group relevant to organization's industry. For financial services, emulate FIN7 or Lazarus Group. For healthcare, emulate APT41 or FIN12. Map selected adversary's known TTPs from MITRE ATT&CK.
- **Objective definition**: Define measurable objectives such as "Access customer financial data from core banking system" or "Demonstrate ability to deploy ransomware across domain"
- **Attack plan development**: Create step-by-step operation plan mapping each phase to ATT&CK tactics:
  1. Initial Access (TA0001): Phishing, exploiting public-facing applications, or supply chain compromise
  2. Execution (TA0002): PowerShell, scripting, exploitation for client execution
  3. Persistence (TA0003): Scheduled tasks, registry modifications, implant deployment
  4. Privilege Escalation (TA0004): Token impersonation, exploitation for privilege escalation
  5. Defense Evasion (TA0005): Process injection, timestomping, indicator removal
  6. Credential Access (TA0006): LSASS dumping, Kerberoasting, credential stuffing
  7. Lateral Movement (TA0008): Remote services, pass-the-hash, remote desktop
  8. Collection/Exfiltration (TA0009/TA0010): Data staging, exfiltration over C2
- **Deconfliction plan**: Establish procedures for white cell to distinguish red team activity from actual threats

### Step 2: Infrastructure Preparation

Build OPSEC-hardened attack infrastructure:

- **C2 infrastructure**: Deploy primary C2 server behind redirectors that filter Blue Team investigation traffic. Use domain fronting or legitimate cloud services (Azure CDN, CloudFront) to blend C2 traffic with normal web traffic.
- **Phishing infrastructure**: Register aged domains (30+ days old), configure SPF/DKIM/DMARC, and build credential harvesting or payload delivery pages
- **Payload development**: Create custom implants or configure C2 framework payloads with:
  - AMSI bypass for PowerShell execution
  - ETW patching to evade security product telemetry
  - Sleep masking and memory encryption to defeat memory scanning
  - Signed binary proxy execution (rundll32, msbuild, regsvr32) for defense evasion
- **Staging infrastructure**: Set up file hosting for second-stage payloads, exfiltration drop servers, and backup communication channels
- **OPSEC verification**: Test entire infrastructure against same EDR/AV products deployed in target environment before going live

### Step 3: Initial Access

Gain initial foothold in target environment:

- **Phishing campaign**: Send targeted spear-phishing emails to selected employees with weaponized documents or credential harvesting links. Use pretexts based on OSINT gathered during reconnaissance.
- **External exploitation**: Exploit vulnerabilities in internet-facing applications (VPN portals, web applications, email servers) identified during reconnaissance
- **Physical access**: If in scope, attempt physical access to deploy network implants (LAN Turtle, Bash Bunny) or USB drops
- **Supply chain**: If in scope, compromise vendor or supplier relationship to gain indirect access
- Upon successful initial access, establish first C2 beacon and confirm communication with C2 server. Immediately implement persistence (multiple mechanisms) to survive reboots and credential changes.

### Step 4: Post-Exploitation and Objective Completion

Operate within target environment while maintaining stealth:

- **Internal reconnaissance**: Enumerate domain, identify high-value targets, and map network using BloodHound and internal scanning, with traffic designed to blend with normal administrative activity
- **Privilege escalation**: Escalate from initial user to local admin, then to domain admin, using least detectable techniques (Kerberoasting over pass-the-hash, living-off-the-land over custom tools)
- **Lateral movement**: Move to target systems using legitimate protocols (RDP, WinRM, SMB) with stolen credentials. Vary techniques to test multiple detection signatures.
- **Defense evasion**: Continuously adapt to avoid detection. If technique triggers alert, note detection and switch to alternative approach.
- **Objective execution**: Complete defined objectives (access target data, demonstrate ransomware staging, exfiltrate data) and document evidence of achievement
- **Detection timeline**: Record timestamps for every technique executed to later compare against Blue Team's detection timeline

### Step 5: Purple Team Integration and Reporting

Convert red team findings into defensive improvements:

- **Detection gap analysis**: Compare red team's technique timeline against Blue Team's detection log. Identify which techniques were detected, which were missed, and mean time to detect (MTTD) for each.
- **ATT&CK coverage mapping**: Create ATT&CK Navigator heatmap showing which techniques were tested and whether they were detected, missed, or partially detected
- **Purple team sessions**: Conduct collaborative sessions where red team reveals each technique step-by-step while Blue Team identifies where detection should have occurred and writes new detection rules
- **Report**: Deliver comprehensive report including operation narrative, technique-by-technique analysis with detection status, and prioritized recommendations for improving detection and response

## Key Concepts

| Term | Definition |
|------|------------|
| **Adversary Emulation** | Simulating specific TTPs of known threat actor to test defenses against realistic threats relevant to organization |
| **C2 (Command and Control)** | Infrastructure and communication channels used by red team to remotely control implants deployed on compromised systems |
| **OPSEC** | Operational Security; practices employed by red team to avoid detection by defending team during exercise |
| **Domain Fronting** | Technique for hiding C2 traffic behind legitimate CDN domains to evade network-based detection and domain blocking |
| **Purple Teaming** | Collaborative exercise where red and blue teams work together to improve detection by sharing attack techniques and defensive gaps |
| **White Cell** | Trusted agent or exercise control group that manages exercise, handles deconfliction, and mediates between red and blue teams |
| **Implant** | Software deployed by red team on compromised systems to maintain access, execute commands, and facilitate lateral movement |
| **MTTD/MTTR** | Mean Time to Detect / Mean Time to Respond; metrics measuring how long it takes defending team to identify and contain threats |

## Tools & Systems

- **Cobalt Strike**: Commercial adversary simulation platform providing beacons, malleable C2 profiles, and post-exploitation capabilities
- **Sliver**: Open-source C2 framework supporting multiple protocols (mTLS, WireGuard, HTTP/S, DNS) with cross-platform implants
- **MITRE ATT&CK Navigator**: Tool for visualizing ATT&CK technique coverage, enabling comparison of planned vs. executed vs. detected techniques
- **Mythic**: Open-source C2 framework with modular agent architecture and web-based operator interface

### Scenario: Adversary Emulation of FIN7 Against Retail Company

**Context**: National retail chain wants to test its defenses against FIN7, financially motivated threat group known for targeting retail and hospitality organizations with point-of-sale malware, phishing, and data exfiltration.

**Approach**:
1. Emulate FIN7 TTPs: spear-phishing with malicious document containing VBA macros that execute PowerShell
2. Initial access achieved through spear-phishing marketing employee; macro drops Cobalt Strike beacon using rundll32 proxy execution
3. Internal reconnaissance with BloodHound reveals path from compromised user to service account with access to POS management server
4. Kerberoast service account, crack password, and move laterally to POS management system
5. Demonstrate data access to cardholder data environment, staging simulated card data for exfiltration
6. Exfiltrate staged data over DNS C2 channel to simulate data theft
7. SOC detected lateral movement at hour 47 but did not detect initial phishing, macro execution, or Kerberoasting

**Pitfalls**:
- Operating too aggressively and getting detected immediately, providing no value for testing Blue Team's advanced detection capabilities
- Using exclusively custom tools instead of living-off-the-land techniques that real adversaries prefer
- Not recording detailed timestamps for every action, making post-exercise analysis and detection gap mapping impossible
- Failing to establish backup C2 channels, getting burned by single detection, and losing access without completing objectives

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/executing-red-team-exercise
