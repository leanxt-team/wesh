---
name: detecting-ntlm-relay-with-event-correlation
description: Detect NTLM relay attacks (T1557.001) by correlating Windows Event 4624 LogonType 3 for IP-to-hostname mismatches, identifying Responder/LLMNR poisoning artifacts, auditing SMB/LDAP signing, and flagging NTLMv2-to-NTLMv1 downgrades.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1069
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: detecting-ntlm-relay-with-event-correlation@54a7988 Apache-2.0, modified by wesh
---
Not for: without centralized Windows Security Event Log collection, as a substitute for enforcing SMB signing and Extended Protection for Authentication (EPA) which prevent relay attacks at the protocol level, or without an IP-to-hostname inventory for correlation.

> **Authorized Testing Disclaimer**: offensive techniques and attack simulations described in this skill are intended exclusively for authorized penetration testing, red team engagements, purple team exercises, and security research conducted with explicit written permission from system owner. Unauthorized use of these techniques against systems you do not own or have permission to test is illegal and unethical. Always operate within scope of your engagement and comply with applicable laws and regulations.

## Prerequisites

- Windows Advanced Audit Policy configured to capture Event IDs 4624, 4625, 4648, 4776, and 8004
- Centralized log collection via Windows Event Forwarding (WEF) or agent-based shipping to SIEM
- SIEM platform (Splunk, Elastic, Microsoft Sentinel) with correlation and alerting capability
- IP address to hostname mapping inventory (DHCP logs, DNS records, or CMDB)
- Network monitoring for LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) traffic
- Understanding of MITRE ATT&CK T1557.001 and T1187 (Forced Authentication)

## Workflow

### Step 1: Understand NTLM Relay Attack Flow

NTLM relay attack follows three-phase pattern: coercion/poisoning, interception, and relay.

**Phase 1 -- Coercion or Poisoning**: attacker forces or tricks victim into initiating NTLM authentication. Methods include LLMNR/NBT-NS poisoning (Responder), PetitPotam (MS-EFSRPC abuse), PrinterBug (SpoolService), and DFSCoerce.

**Phase 2 -- Interception**: attacker captures NTLM Type 1 (Negotiate) and Type 3 (Authenticate) messages from victim.

**Phase 3 -- Relay**: attacker forwards captured NTLM messages to target service (SMB, LDAP, HTTP, MSSQL) to authenticate as victim. This succeeds only when message signing is not enforced.

```
Victim ──NTLM Negotiate──> Attacker ──NTLM Negotiate──> Target
Victim <──NTLM Challenge── Attacker <──NTLM Challenge── Target
Victim ──NTLM Authenticate──> Attacker ──NTLM Authenticate──> Target
                                                         ↓
                                              Attacker authenticated
                                              as Victim on Target
```

**Key Detection Insight**: In relay attack, Event 4624 on target will show victim's username but attacker's IP address. WorkstationName field may still reflect victim's machine. This IP-to-hostname mismatch is primary detection signal.

### Step 2: Event 4624 LogonType 3 Analysis for Relay Detection

```spl
# Splunk: Detect IP-to-Hostname Mismatches in Network Logons
# Core NTLM relay detection -- correlates WorkstationName with IpAddress
index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM" LmPackageName="NTLM V2"
| where TargetUserName != "ANONYMOUS LOGON"
    AND TargetUserName != "-"
    AND NOT match(TargetUserName, ".*\\$$")
| eval workstation_lower=lower(WorkstationName)
| lookup dns_inventory.csv hostname AS workstation_lower OUTPUT expected_ip
| where isnotnull(expected_ip) AND IpAddress != expected_ip
| table _time ComputerName TargetUserName WorkstationName IpAddress expected_ip
    LogonProcessName AuthenticationPackageName
| sort -_time
| rename ComputerName as TargetHost, IpAddress as ActualSourceIP,
    expected_ip as ExpectedSourceIP
```

```spl
# Splunk: Detect Rapid Multi-Host Authentication (Relay Spraying)
# Attackers relay captured credentials to multiple targets quickly
index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| bin _time span=2m
| stats dc(ComputerName) as target_count values(ComputerName) as targets
    values(IpAddress) as source_ips by _time TargetUserName
| where target_count > 3
| table _time TargetUserName source_ips target_count targets
| sort -target_count
```

```spl
# Splunk: Detect NTLM Authentication from Non-Workstation IPs
# Relay tools often run from Linux attack boxes not in DNS/DHCP inventory
index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| lookup dhcp_leases.csv ip AS IpAddress OUTPUT mac_address hostname
| where isnull(hostname)
| stats count dc(ComputerName) as targets_hit values(ComputerName) as target_hosts
    by IpAddress TargetUserName WorkstationName
| where count > 1
| table IpAddress TargetUserName WorkstationName targets_hit target_hosts count
| sort -targets_hit
```

```kql
-- Microsoft Sentinel KQL: NTLM Relay Detection via IP-Hostname Mismatch
let known_hosts = datatable(WorkstationName:string, ExpectedIP:string)
[
    // Populate from CMDB or use DeviceNetworkInfo table
];
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| where IpAddress != "-" and IpAddress != "::1" and IpAddress != "127.0.0.1"
| extend WorkstationClean = toupper(trim_end(@"\s+", WorkstationName))
| join kind=inner (known_hosts) on WorkstationName
| where IpAddress != ExpectedIP
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, ExpectedIP, LogonProcessName, AuthenticationPackageName,
    LmPackageName
| sort by TimeGenerated desc
```

```kql
-- Microsoft Sentinel KQL: Rapid NTLM Authentication to Multiple Targets
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| summarize TargetCount=dcount(Computer),
    Targets=make_set(Computer),
    SourceIPs=make_set(IpAddress),
    AuthCount=count()
    by TargetUserName, bin(TimeGenerated, 2m)
| where TargetCount > 3
| project TimeGenerated, TargetUserName, SourceIPs, TargetCount, Targets, AuthCount
| sort by TargetCount desc
```

### Step 3: Responder Detection via Network and Event Analysis

```spl
# Splunk: Detect Responder LLMNR/NBT-NS Poisoning via Network Logs
# Responder answers LLMNR (UDP 5355) and NBT-NS (UDP 137) queries
index=network sourcetype=zeek_dns
| where query_type IN ("LLMNR", "NBNS")
    OR id.resp_p IN (5355, 137)
| stats dc(id.orig_h) as victims count by id.resp_h answers
| where count > 10
| rename id.resp_h as responder_ip
| table responder_ip victims answers count
| sort -count
```

```spl
# Splunk: Detect LLMNR/NBT-NS Response from Non-DNS Servers
# Legitimate DNS servers respond to these; Responder impersonates them
index=network sourcetype="bro:dns:json" OR sourcetype="zeek:conn:json"
| where id_resp_p=5355 OR id_resp_p=137
| where NOT cidrmatch("10.10.0.0/24", id_resp_h)
| stats count dc(id_orig_h) as unique_victims by id_resp_h
| where unique_victims > 3
| table id_resp_h unique_victims count
| rename id_resp_h as suspicious_responder
```

```powershell
# PowerShell: Detect LLMNR and NBT-NS activity on local network
# Run on a monitoring host to identify Responder-like behavior
# Check if LLMNR is disabled (should be disabled to prevent poisoning)
$llmnr = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -ErrorAction SilentlyContinue
Write-Host "[*] LLMNR Status: $(if ($llmnr.EnableMulticast -eq 0) { 'DISABLED (Good)' } else { 'ENABLED (Vulnerable to Responder)' })"
# Check if NBT-NS is disabled
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    $nbtns = $adapter.TcpipNetbios
    $status = switch ($nbtns) {
        0 { "Default (Enabled)" }
        1 { "Enabled" }
        2 { "Disabled (Good)" }
    }
    Write-Host "[*] Adapter '$($adapter.Description)' NBT-NS: $status"
}
# Query Windows Firewall logs for LLMNR/NBT-NS traffic
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" `
    -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Message -match "5355|137" -and $_.Message -match "UDP"
    } |
    Select-Object TimeCreated, @{N='Detail';E={$_.Message.Substring(0,200)}} |
    Format-Table -AutoSize
```

```yaml
# Sigma Rule: Responder LLMNR/NBT-NS Poisoning Detection
title: Potential Responder LLMNR/NBT-NS Poisoning Activity
id: 7a8b9c0d-e1f2-3a4b-5c6d-7e8f9a0b1c2d
status: stable
description: >
  Detects a single host responding to LLMNR (UDP 5355) or NBT-NS (UDP 137)
  queries from multiple unique sources, indicating possible Responder poisoning.
references:
    - https://www.hackthebox.com/blog/ntlm-relay-attack-detection
    - https://blog.fox-it.com/2017/05/09/relaying-credentials-everywhere-with-ntlmrelayx/
logsource:
    category: firewall
detection:
    selection:
        dst_port:
            - 5355
            - 137
        action: allow
    condition: selection | count(src_ip) by dst_ip > 5
    timeframe: 5m
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
falsepositives:
    - Legitimate WINS servers or DNS servers responding to broadcast queries
    - Network discovery tools performing name resolution
```

### Step 4: SMB Signing Enforcement Audit

```powershell
# PowerShell: Audit SMB Signing Status Across Domain
# SMB signing prevents NTLM relay to SMB services
# Check local SMB signing configuration
Write-Host "=== LOCAL SMB SIGNING STATUS ==="
$smbServer = Get-SmbServerConfiguration
Write-Host "[*] SMB Server RequireSecuritySignature: $($smbServer.RequireSecuritySignature)"
Write-Host "[*] SMB Server EnableSecuritySignature: $($smbServer.EnableSecuritySignature)"
$smbClient = Get-SmbClientConfiguration
Write-Host "[*] SMB Client RequireSecuritySignature: $($smbClient.RequireSecuritySignature)"
Write-Host "[*] SMB Client EnableSecuritySignature: $($smbClient.EnableSecuritySignature)"
# Check via registry (works on older systems)
$serverSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
$clientSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" `
    -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
Write-Host "`n=== REGISTRY VALUES ==="
Write-Host "[*] Server RequireSecuritySignature: $($serverSigning.RequireSecuritySignature) (1=Required, 0=Not Required)"
Write-Host "[*] Client RequireSecuritySignature: $($clientSigning.RequireSecuritySignature) (1=Required, 0=Not Required)"
```

```powershell
# PowerShell: Domain-Wide SMB Signing Audit
# Scan all domain computers for SMB signing enforcement
$domainComputers = Get-ADComputer -Filter * -Properties OperatingSystem |
    Where-Object { $_.OperatingSystem -like "*Windows*" -and $_.Enabled -eq $true } |
    Select-Object -ExpandProperty DNSHostName
$results = @()
foreach ($computer in $domainComputers) {
    try {
        $session = New-CimSession -ComputerName $computer -ErrorAction Stop
        $smbConfig = Get-SmbServerConfiguration -CimSession $session -ErrorAction Stop
        $results += [PSCustomObject]@{
            Computer = $computer
            RequireSigning = $smbConfig.RequireSecuritySignature
            EnableSigning = $smbConfig.EnableSecuritySignature
            Status = if ($smbConfig.RequireSecuritySignature) { "ENFORCED" } else { "VULNERABLE" }
        }
        Remove-CimSession $session
    } catch {
        $results += [PSCustomObject]@{
            Computer = $computer
            RequireSigning = "ERROR"
            EnableSigning = "ERROR"
            Status = "UNREACHABLE"
        }
    }
}
# Display results sorted by vulnerability
$results | Sort-Object Status | Format-Table -AutoSize
# Export vulnerable hosts
$vulnerable = $results | Where-Object { $_.Status -eq "VULNERABLE" }
Write-Host "`n[!] VULNERABLE HOSTS (SMB Signing Not Required): $($vulnerable.Count)"
$vulnerable | Export-Csv -Path "smb_signing_audit.csv" -NoTypeInformation
```

```powershell
# PowerShell: Audit LDAP Signing Status on Domain Controllers
# LDAP signing prevents NTLM relay to LDAP/LDAPS services
# Check LDAP signing requirement on domain controllers
$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
foreach ($dc in $dcs) {
    # Check LDAP server signing requirement
    $ldapSigning = Invoke-Command -ComputerName $dc -ScriptBlock {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $value = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
        return $value.LDAPServerIntegrity
    } -ErrorAction SilentlyContinue
    $status = switch ($ldapSigning) {
        0 { "NONE (Vulnerable)" }
        1 { "Negotiate Signing (Default - Vulnerable to relay)" }
        2 { "Require Signing (Secure)" }
        default { "Unknown/Error" }
    }
    Write-Host "[*] $dc LDAP Signing: $status"
    # Check LDAP channel binding
    $channelBinding = Invoke-Command -ComputerName $dc -ScriptBlock {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
        $value = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
        return $value.LdapEnforceChannelBinding
    } -ErrorAction SilentlyContinue
    $cbStatus = switch ($channelBinding) {
        0 { "Disabled (Vulnerable)" }
        1 { "When Supported" }
        2 { "Always Required (Secure)" }
        default { "Not Configured (Vulnerable)" }
    }
    Write-Host "[*] $dc LDAP Channel Binding: $cbStatus"
}
```

```spl
# Splunk: Monitor for SMB sessions without signing
# Requires Zeek SMB logging or packet capture analysis
index=network sourcetype="zeek:smb_mapping:json" OR sourcetype="bro:smb_mapping:json"
| where NOT security_mode="signing_required"
| stats count dc(id_orig_h) as unique_clients by id_resp_h security_mode
| sort -unique_clients
| rename id_resp_h as smb_server
| table smb_server security_mode unique_clients count
```

### Step 5: NTLM Downgrade Detection

```spl
# Splunk: Detect NTLMv1 Authentication (Downgrade from NTLMv2)
# NTLMv1 is weaker and easier to relay/crack -- should not be in use
index=wineventlog EventCode=4624 LogonType=3
    LmPackageName="NTLM V1"
| where TargetUserName != "ANONYMOUS LOGON"
    AND NOT match(TargetUserName, ".*\\$$")
| stats count values(ComputerName) as targets
    values(IpAddress) as source_ips
    by TargetUserName LmPackageName
| table TargetUserName LmPackageName source_ips targets count
| sort -count
```

```spl
# Splunk: Detect NTLM Downgrade Attack Pattern
# NTLMv1 appearing after a period of only NTLMv2 suggests active downgrade
index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON"
| bin _time span=1h
| stats count(eval(LmPackageName="NTLM V1")) as ntlmv1_count
    count(eval(LmPackageName="NTLM V2")) as ntlmv2_count
    by _time
| where ntlmv1_count > 0
| eval ntlmv1_ratio = round(ntlmv1_count / (ntlmv1_count + ntlmv2_count) * 100, 2)
| table _time ntlmv1_count ntlmv2_count ntlmv1_ratio
| sort -_time
```

```kql
-- Microsoft Sentinel KQL: NTLMv1 Downgrade Detection
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where LmPackageName == "NTLM V1"
| where TargetUserName !endswith "$"
| where TargetUserName != "ANONYMOUS LOGON"
| project TimeGenerated, Computer, TargetUserName, WorkstationName,
    IpAddress, LmPackageName, LogonProcessName
| sort by TimeGenerated desc
```

```powershell
# PowerShell: Detect NTLMv1 Authentication Events on Local System
$ntlmv1Events = Get-WinEvent -LogName Security -FilterXPath @"
*[System[(EventID=4624)]]
 and
*[EventData[Data[@Name='LmPackageName']='NTLM V1']]
"@ -MaxEvents 500 -ErrorAction SilentlyContinue
if ($ntlmv1Events.Count -gt 0) {
    Write-Host "[!] WARNING: $($ntlmv1Events.Count) NTLMv1 authentication events detected!" -ForegroundColor Red
    $ntlmv1Events | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        [PSCustomObject]@{
            Time         = $_.TimeCreated
            TargetUser   = ($eventData | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            Workstation  = ($eventData | Where-Object { $_.Name -eq "WorkstationName" }).'#text'
            SourceIP     = ($eventData | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            LmPackage    = ($eventData | Where-Object { $_.Name -eq "LmPackageName" }).'#text'
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "[+] No NTLMv1 authentication events found (Good)" -ForegroundColor Green
}
# Audit GPO settings for NTLM restriction
Write-Host "`n=== NTLM RESTRICTION POLICY ==="
$ntlmPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
$level = switch ($ntlmPolicy.LmCompatibilityLevel) {
    0 { "Send LM & NTLM responses (Most Vulnerable)" }
    1 { "Send LM & NTLM - use NTLMv2 session security if negotiated" }
    2 { "Send NTLM response only" }
    3 { "Send NTLMv2 response only (Recommended minimum)" }
    4 { "Send NTLMv2 response only, refuse LM" }
    5 { "Send NTLMv2 response only, refuse LM & NTLM (Most Secure)" }
    default { "Not configured (defaults to 3 on modern Windows)" }
}
Write-Host "[*] LmCompatibilityLevel: $($ntlmPolicy.LmCompatibilityLevel) - $level"
```

### Step 6: NTLM Audit and Restriction Policy Configuration

```powershell
# PowerShell: Enable NTLM Auditing via Group Policy Registry Settings
# Must be applied via GPO for domain-wide coverage
# Audit all NTLM authentication in this domain
# GPO: Computer Configuration > Policies > Windows Settings > Security Settings >
#      Local Policies > Security Options >
#      Network Security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
# Registry equivalent (apply via GPO preferences or startup script)
# Domain Controller setting:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
#     -Name "AuditNTLMInDomain" -Value 7 -Type DWord
# Audit incoming NTLM traffic on all servers:
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
#     -Name "AuditReceivingNTLMTraffic" -Value 2 -Type DWord
# After enabling auditing, NTLM events appear in:
# Applications and Services Logs > Microsoft > Windows > NTLM > Operational
# Query NTLM operational log for audit events
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in @(8001, 8002, 8003, 8004) } |
    Select-Object TimeCreated, Id,
        @{N='EventType'; E={
            switch ($_.Id) {
                8001 { "NTLM client blocked audit" }
                8002 { "NTLM server blocked audit" }
                8003 { "NTLM server blocked in domain" }
                8004 { "NTLM authentication to DC audit" }
            }
        }},
        @{N='Detail'; E={$_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))}} |
    Format-Table -AutoSize
```

```spl
# Splunk: Monitor NTLM Audit Events (Event ID 8004)
# Shows all NTLM authentications passing through domain controllers
index=wineventlog source="WinEventLog:Microsoft-Windows-NTLM/Operational"
    EventCode=8004
| rex field=Message "Calling client name:\s+(?<client_name>[^\r\n]+)"
| rex field=Message "Calling client IP:\s+(?<client_ip>[^\r\n]+)"
| rex field=Message "Server name:\s+(?<server_name>[^\r\n]+)"
| stats count dc(server_name) as unique_servers by client_name client_ip
| sort -count
| table client_name client_ip unique_servers count
```

### Step 7: PetitPotam and Coercion Attack Detection

```spl
# Splunk: Detect PetitPotam / EFSCoerce Attack
# Monitor for machine account NTLM authentications relayed to other services
index=wineventlog EventCode=4624 LogonType=3
    AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| where match(TargetUserName, "^[A-Z0-9\\-]+\\$$")
| eval is_dc = if(match(TargetUserName, "(DC|DCSERVER|DOMCTRL)"), "Yes", "No")
| where IpAddress != "127.0.0.1" AND IpAddress != "::1"
| stats count values(ComputerName) as target_hosts
    values(IpAddress) as source_ips by TargetUserName
| where count > 2 OR mvcount(source_ips) > 1
| table TargetUserName source_ips target_hosts count
| sort -count
```

```kql
-- Microsoft Sentinel KQL: PetitPotam / Coercion Attack Detection
-- Detects domain controller machine account authenticating from unexpected IPs
let dc_accounts = SecurityEvent
| where EventID == 4624 and LogonType == 3
| where TargetUserName endswith "$"
| where Computer startswith "DC"
| distinct TargetUserName;
SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TargetUserName in (dc_accounts)
| where IpAddress != "127.0.0.1" and IpAddress != "::1"
| extend SourceHostExpected = iff(
    Computer == replace_string(TargetUserName, "$", ""), true, false)
| where SourceHostExpected == false
| project TimeGenerated, Computer, TargetUserName, IpAddress,
    WorkstationName, LogonProcessName, AuthenticationPackageName
| sort by TimeGenerated desc
```

```yaml
# Sigma Rule: NTLM Relay - Computer Account Authentication from Unexpected Source
title: Potential NTLM Relay of Computer Account Credentials
id: 5e6f7a8b-9c0d-1e2f-3a4b-5c6d7e8f9a0b
status: stable
description: >
  Detects a computer account (ending in $) authenticating via NTLM LogonType 3
  where the source IP does not match the computer's known IP, indicating possible
  NTLM relay of coerced machine authentication (PetitPotam, DFSCoerce, PrinterBug).
references:
    - https://www.crowdstrike.com/en-us/blog/how-to-detect-domain-controller-account-relay-attacks-with-crowdstrike-identity-protection/
    - https://www.fox-it.com/nl-en/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
    - https://www.nccgroup.com/research-blog/detecting-and-hunting-for-the-petitpotam-ntlm-relay-attack/
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: NTLM
        TargetUserName|endswith: '$'
    filter_localhost:
        IpAddress:
            - '127.0.0.1'
            - '::1'
            - '-'
    condition: selection and not filter_localhost
level: high
tags:
    - attack.credential_access
    - attack.t1557.001
    - attack.t1187
falsepositives:
    - Legitimate NTLM authentication from machine accounts during failover
    - Cluster service machine account authentication
```

### Step 8: Build Comprehensive Correlation Dashboard

```spl
# Splunk: NTLM Relay Detection Dashboard -- Combined Correlation Query
# Panel 1: IP-Hostname Mismatches (Core Relay Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| where TargetUserName != "ANONYMOUS LOGON" AND NOT match(TargetUserName, ".*\\$$")
| eval mismatch=if(lower(WorkstationName) != lower(mvindex(split(IpAddress, "."), 0)),
    "POSSIBLE_MISMATCH", "OK")
| where mismatch="POSSIBLE_MISMATCH"
| stats count by TargetUserName WorkstationName IpAddress ComputerName
# Panel 2: NTLMv1 Downgrade Events
index=wineventlog EventCode=4624 LmPackageName="NTLM V1"
| timechart span=1h count by ComputerName
# Panel 3: Machine Account Relay (PetitPotam Indicator)
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
    TargetUserName="*$"
| stats count values(IpAddress) as relay_sources by TargetUserName ComputerName
# Panel 4: NTLM Authentication Volume Anomaly
index=wineventlog EventCode=4624 LogonType=3 AuthenticationPackageName="NTLM"
| timechart span=15m count
| streamstats window=20 avg(count) as avg_count stdev(count) as stdev_count
| eval upper_bound=avg_count + (3 * stdev_count)
| where count > upper_bound
# Panel 5: SMB Signing Status (from audit results)
| inputlookup smb_signing_audit.csv
| stats count by Status
| table Status count
```

## Key Concepts

| Term | Definition |
|------|------------|
| **NTLM Relay (T1557.001)** | Attack that intercepts NTLM authentication messages and forwards them to target service, authenticating as victim without knowing their password |
| **Event 4624 LogonType 3** | Windows Security Event for successful network logon -- primary event generated on relay targets; source IP field reveals relay attacker's address |
| **IP-Hostname Mismatch** | When Event 4624 WorkstationName field does not correspond to IpAddress field, indicating authentication was relayed through third party |
| **Responder** | Attack tool that poisons LLMNR (UDP 5355), NBT-NS (UDP 137), and mDNS (UDP 5353) responses to capture NTLM authentication from victims on local network |
| **ntlmrelayx** | Fox-IT/Impacket tool that relays captured NTLM authentication to SMB, LDAP, HTTP, MSSQL, and other protocols to gain unauthorized access |
| **SMB Signing** | Cryptographic signing of SMB packets that prevents relay attacks against SMB services; must be set to "Required" (not "Enabled") for protection |
| **LDAP Signing** | Cryptographic signing of LDAP operations that prevents relay attacks against LDAP services on domain controllers; controlled by LDAPServerIntegrity registry value |
| **LDAP Channel Binding** | Extended Protection for Authentication (EPA) that binds NTLM authentication to TLS channel, preventing relay to LDAPS |
| **NTLMv1 Downgrade** | Attack forcing authentication from NTLMv2 to weaker NTLMv1 protocol, easier to crack offline and has weaker relay protections |
| **PetitPotam** | Coercion technique abusing MS-EFSRPC to force domain controller to authenticate to attacker-controlled host, enabling relay to AD CS or LDAP |
| **LmCompatibilityLevel** | Registry setting controlling which NTLM version is used; value of 5 (Send NTLMv2 only, refuse LM and NTLM) provides strongest protection |
| **Event 8004** | NTLM operational log event on domain controllers showing all NTLM authentication pass-through, critical for auditing NTLM usage before restriction |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Splunk / Elastic SIEM** | Log aggregation and correlation for Event 4624 analysis, IP-hostname mismatch detection, and NTLM downgrade monitoring |
| **Microsoft Sentinel** | Cloud SIEM with KQL queries for NTLM relay detection and built-in analytics rules for PetitPotam |
| **CrowdStrike Falcon Identity Protection** | Detects NTLM relay attacks against domain controller accounts regardless of coercion method used |
| **Responder** | LLMNR/NBT-NS/mDNS poisoning tool used by attackers -- understanding its behavior is essential for detection |
| **ntlmrelayx (Impacket)** | Multi-protocol NTLM relay tool developed by Fox-IT -- used in testing and by adversaries |
| **PingCastle** | Active Directory security assessment tool that audits SMB signing, LDAP signing, and NTLM configuration |
| **Zeek** | Network security monitor for capturing SMB signing negotiation, LLMNR traffic, and DCE-RPC activity |
| **Sigma** | Vendor-agnostic detection rule format for portable NTLM relay detection rules |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-ntlm-relay-with-event-correlation
