---
name: deploying-active-directory-honeytokens
description: Deploys deception-based honeytokens in Active Directory including fake privileged accounts with AdminCount=1, fake SPNs for Kerberoasting detection (honeyroasting), decoy GPOs with cpassword traps, and fake BloodHound paths.
subdomain: deception-technology
facing: defense
mitre_attack:
- T1558.003
- T1558.004
- T1110.003
- T1003.006
- T1552.006
nist_csf:
- DE.CM-01
- DE.AE-06
- PR.IR-01
upstream: deploying-active-directory-honeytokens@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Domain Admin or delegated AD administration privileges
- Active Directory domain (Windows Server 2016+ recommended)
- Windows Event Log forwarding to SIEM (Splunk, Sentinel, Elastic)
- PowerShell 5.1+ with ActiveDirectory module
- Group Policy Management Console (GPMC)
- Understanding of AD security, Kerberos, and BloodHound attack paths

## Instructions

### Step 1: Deploy Fake Privileged Admin Account

Create honeytoken account that mimics legacy privileged service account.

```powershell
# Import the deployment module
Import-Module .\scripts\Deploy-ADHoneytokens.ps1
# Create a honeytoken admin account
$honeyAdmin = New-HoneytokenAdmin `
    -SamAccountName "svc_sqlbackup_legacy" `
    -DisplayName "SQL Backup Service (Legacy)" `
    -Description "Legacy SQL Server backup service account - DO NOT DELETE" `
    -OU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -PasswordLength 128 `
    -SetAdminCount $true
Write-Host "Honeytoken admin created: $($honeyAdmin.DistinguishedName)"
```

### Step 2: Deploy Fake SPN for Kerberoasting Detection

Assign realistic but fake SPN to honeytoken account. Any TGS request
for this SPN is definitively malicious (honeyroasting).

```powershell
# Add fake SPN to honeytoken account
$honeySPN = Add-HoneytokenSPN `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ServiceClass "MSSQLSvc" `
    -Hostname "sql-legacy-bak01.corp.example.com" `
    -Port 1433
Write-Host "Honey SPN registered: $($honeySPN.SPN)"
Write-Host "Monitor Event ID 4769 for TGS requests targeting this SPN"
```

### Step 3: Deploy Decoy GPO with Credential Trap

Create fake GPO in SYSVOL with embedded cpassword (Group Policy Preference
password). Attackers using tools like Get-GPPPassword or gpp-decrypt will find
and attempt to use these credentials, triggering detection.

```powershell
# Create decoy GPO with cpassword trap
$decoyGPO = New-DecoyGPO `
    -GPOName "Server Maintenance Policy (Legacy)" `
    -DecoyUsername "admin_maintenance" `
    -DecoyDomain "CORP" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -EnableAuditSACL $true
Write-Host "Decoy GPO created: $($decoyGPO.GPOGuid)"
Write-Host "SACL audit enabled - any read attempt will generate Event ID 4663"
```

### Step 4: Create Deceptive BloodHound Paths

Set ACL permissions that create fake attack paths visible to BloodHound/SharpHound
reconnaissance, leading attackers toward monitored honeytokens.

```powershell
# Create fake BloodHound attack path
$deceptivePath = New-DeceptiveBloodHoundPath `
    -HoneytokenSamAccount "svc_sqlbackup_legacy" `
    -TargetHighValueGroup "Domain Admins" `
    -IntermediateOU "OU=Service Accounts,DC=corp,DC=example,DC=com"
Write-Host "Deceptive path created: $($deceptivePath.PathDescription)"
```

### Step 5: Configure Detection Rules

Set up SIEM detection rules to alert on any honeytoken interaction.

```python
# Using the Python detection agent
from agent import ADHoneytokenMonitor
monitor = ADHoneytokenMonitor(config_path="honeytoken_config.json")
# Register all honeytokens for monitoring
monitor.register_honeytoken("svc_sqlbackup_legacy", token_type="admin_account")
monitor.register_honeytoken("MSSQLSvc/sql-legacy-bak01.corp.example.com:1433", token_type="spn")
monitor.register_honeytoken("admin_maintenance", token_type="gpo_credential")
# Generate SIEM detection rules
splunk_rules = monitor.generate_detection_rules(siem="splunk")
sentinel_rules = monitor.generate_detection_rules(siem="sentinel")
sigma_rules = monitor.generate_detection_rules(siem="sigma")
for rule in sigma_rules:
    print(f"Rule: {rule['title']}")
    print(f"  Detection: {rule['detection_logic']}")
```

### Step 6: Validate Deployment

Test honeytokens to ensure detection fires correctly.

```powershell
# Validate honeytoken deployment
$validation = Test-HoneytokenDeployment `
    -SamAccountName "svc_sqlbackup_legacy" `
    -ValidateAdminCount `
    -ValidateSPN `
    -ValidateGPODecoy `
    -ValidateAuditPolicy
$validation | Format-Table Check, Status, Details -AutoSize
```

## Examples

### Full Deployment Pipeline

```powershell
Import-Module .\scripts\Deploy-ADHoneytokens.ps1
# Deploy complete honeytoken suite
$deployment = Deploy-FullHoneytokenSuite `
    -Environment "Production" `
    -ServiceAccountOU "OU=Service Accounts,DC=corp,DC=example,DC=com" `
    -SYSVOLPath "\\corp.example.com\SYSVOL\corp.example.com\Policies" `
    -TokenCount 3 `
    -IncludeSPN $true `
    -IncludeGPODecoy $true `
    -IncludeBloodHoundPath $true `
    -SIEMType "Splunk"
# Output deployment report
$deployment.Tokens | Format-Table Name, Type, SPN, DetectionRule -AutoSize
$deployment | Export-Csv "honeytoken_deployment_report.csv" -NoTypeInformation
```

### Kerberoasting Detection Query (Splunk)

```spl
index=wineventlog EventCode=4769 ServiceName="svc_sqlbackup_legacy"
| eval alert_severity="critical"
| eval alert_type="honeytoken_kerberoast"
| table _time, src_ip, Account_Name, ServiceName, Ticket_Encryption_Type
| sort - _time
```

### Microsoft Sentinel KQL Detection

```kql
SecurityEvent
| where EventID == 4769
| where ServiceName in ("svc_sqlbackup_legacy", "svc_exchange_legacy")
| extend AlertType = "Honeytoken Kerberoast Detected"
| project TimeGenerated, Computer, Account, ServiceName, IpAddress, TicketEncryptionType
```

## References

- Trimarc Security - Art of Honeypot Account: https://www.hub.trimarcsecurity.com/post/the-art-of-the-honeypot-account-making-the-unusual-look-normal
- ADSecurity.org - Detecting Kerberoasting Activity Part 2 (Honeypot): https://adsecurity.org/?p=3513
- Microsoft Defender for Identity Honeytokens: https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/deceptive-defense-best-practices-for-identity-based-honeytokens-in-microsoft-def/3851641
- SpecterOps - Kerberoasting and AES-256: https://specterops.io/blog/2025/10/21/is-kerberoasting-still-a-risk-when-aes-256-kerberos-encryption-is-enabled/
- APT29a Blog - Deploying Honeytokens in AD: https://apt29a.blogspot.com/2019/11/deploying-honeytokens-in-active.html
- ADSecurity.org - Detecting Kerberoasting Activity: https://adsecurity.org/?p=3458

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-active-directory-honeytokens
