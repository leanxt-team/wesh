---
name: performing-ransomware-response
description: Executes a structured ransomware incident response from detection through containment, forensic analysis, decryption assessment, recovery, and post-incident hardening, covering ransom negotiation, backup integrity verification, and regulatory notification.
subdomain: incident-response
facing: defense
mitre_attack:
- T1486
- T1490
- T1070
- T1078
- T1489
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: performing-ransomware-response@54a7988 Apache-2.0, modified by wesh
---
Not for: general malware incidents that do not involve file encryption or extortion; use malware incident response procedures instead.

## Prerequisites

- Ransomware-specific incident response playbook reviewed and approved by executive leadership
- Tested and verified offline backup strategy with air-gapped or immutable copies
- Incident retainer with specialized ransomware response firm (e.g., Mandiant, CrowdStrike Services, Kroll)
- Legal counsel pre-engaged for OFAC sanctions screening and regulatory notification
- Cyber insurance carrier contact information and policy coverage details
- Bitcoin/cryptocurrency analysis capability or third-party engagement for payment tracing

## Workflow

### Step 1: Detect and Confirm Ransomware

Validate that incident is ransomware and determine variant:

- Identify ransomware by analyzing ransom note filename, extension appended to encrypted files, and note content
- Upload ransom note and sample encrypted file to ID Ransomware (id-ransomware.malwarehunterteam.com)
- Check NoMoreRansom.org for available free decryptors
- Determine ransomware deployment method from EDR/SIEM logs
- Identify ransomware group (e.g., LockBit, BlackCat/ALPHV, Royal, Akira, Play)

```
Ransomware Identification:
━━━━━━━━━━━━━━━━━━━━━━━━━
Variant:          LockBit 3.0 (Black)
Extension:        .lockbit3
Ransom Note:      README-LOCKBIT.txt
Tor Site:         lockbit[redacted].onion
Deployment:       Group Policy Object pushing ransomware.exe to all domain-joined systems
Initial Access:   VPN credential compromise (no MFA)
Dwell Time:       12 days
Data Exfiltration: Yes - 47GB uploaded to MEGA via rclone prior to encryption
```

### Step 2: Immediate Containment

Stop ransomware propagation before assessing damage:

- **Priority 1**: Disconnect affected network segments from core infrastructure (pull network cable, not shutdown)
- **Priority 2**: Isolate all domain controllers immediately if GPO-based deployment is suspected
- **Priority 3**: Disable compromised accounts used for deployment
- **Priority 4**: Block lateral movement protocols (SMB TCP/445, RDP TCP/3389, WinRM TCP/5985-5986)
- **Priority 5**: Preserve at least one encrypted system live (do not power off) for memory forensics
- **Do NOT**: Shut down encrypted systems; keep them powered on to preserve encryption keys in memory

### Step 3: Assess Damage and Scope

Quantify impact to inform recovery and business decisions:

- Count number of encrypted systems (workstations, servers, domain controllers)
- Determine which business-critical systems and data are affected
- Verify backup integrity: check that backups were not encrypted, deleted, or corrupted
- Assess whether data exfiltration occurred (check for rclone, WinSCP, MEGA, cloud storage activity)
- Determine ransom demand amount and payment deadline
- Check OFAC sanctions lists to verify ransomware group is not sanctioned entity (paying is legally risky)

```
Impact Assessment:
Encrypted Systems:      187 of 340 endpoints (55%)
Encrypted Servers:      12 of 28 (43%) - includes 2 file servers, 1 database server
Domain Controllers:     2 of 3 encrypted
Backup Status:          Veeam repository intact (offline copy verified clean)
Data Exfiltration:      Confirmed - 47GB to MEGA (file listing under analysis)
Ransom Demand:          $2.5M in Bitcoin (72-hour deadline)
OFAC Screening:         LockBit - not currently sanctioned entity (verify with counsel)
```

### Step 4: Recovery Decision Matrix

Evaluate recovery options in consultation with legal, executive leadership, and cyber insurance:

| Option | Pros | Cons | Recommended When |
|--------|------|------|-----------------|
| Restore from backup | No payment, no legal risk | Recovery time may be days | Clean backups available |
| Free decryptor | No payment, fast | Rare availability | Variant has published decryptor |
| Negotiate and pay | Potentially faster | No guarantee, legal risk, funds threat actors | No backups, business survival at stake |
| Rebuild from scratch | Clean environment | Longest timeline, data loss | Backups compromised, willing to accept data loss |

### Step 5: Execute Recovery

Implement chosen recovery strategy:

**If restoring from backup:**
1. Build clean isolated network segment for recovery operations
2. Rebuild domain controllers first from clean media (do NOT restore DC backups older than dwell time)
3. Reset ALL user and service account passwords before joining any system to new domain
4. Restore servers in priority order: authentication, DNS, DHCP, then business-critical applications
5. Restore workstations via reimaging, not file-level restore
6. Restore data from verified clean backups to rebuilt file servers
7. Reconnect to production network only after validation

**If using decryptor:**
1. Test decryptor on non-critical system first
2. Decrypt in order of business priority
3. Scan all decrypted systems for residual malware before reconnection

### Step 6: Post-Ransomware Hardening

Implement controls to prevent recurrence:

- Enforce MFA on all remote access (VPN, RDP, cloud portals)
- Implement 3-2-1-1-0 backup strategy (3 copies, 2 media types, 1 offsite, 1 immutable, 0 errors)
- Deploy application whitelisting on servers
- Implement network segmentation between workstation and server VLANs
- Enable Protected Users security group for privileged accounts
- Disable NTLM authentication where possible
- Deploy LAPS (Local Administrator Password Solution) for local admin accounts

## Key Concepts

| Term | Definition |
|------|------------|
| **Double Extortion** | Ransomware tactic combining file encryption with data exfiltration and threat to publish stolen data |
| **Immutable Backup** | Backup storage that cannot be modified or deleted for defined retention period, protecting against ransomware targeting backups |
| **OFAC Sanctions** | U.S. Office of Foreign Assets Control restrictions that may prohibit ransom payments to sanctioned entities or jurisdictions |
| **Dwell Time** | Days attacker was present before deploying ransomware; critical for determining which backups are clean |
| **Ransomware-as-a-Service (RaaS)** | Criminal business model where ransomware developers lease their malware to affiliates who conduct attacks |
| **Rclone** | Legitimate cloud sync tool commonly abused by ransomware operators for data exfiltration before encryption |
| **3-2-1-1-0 Backup Rule** | Backup strategy requiring 3 copies, 2 media types, 1 offsite, 1 immutable/air-gapped, and 0 errors in recovery testing |

## Tools & Systems

- **ID Ransomware**: Online service to identify ransomware variant from ransom note or encrypted file sample
- **NoMoreRansom.org**: Europol-backed project providing free decryption tools for certain ransomware families
- **Veeam / Commvault**: Enterprise backup platforms with immutable repository and instant VM recovery capabilities
- **KAPE**: Rapid forensic triage collection from encrypted systems to determine initial access and dwell time
- **Cado Response**: Cloud-native forensics platform for investigating ransomware that affects cloud infrastructure

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-ransomware-response
