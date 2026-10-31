---
name: hunting-saas-sso-token-abuse
description: Hunts for stolen-session and OAuth/PRT token replay (T1550.001) by correlating Microsoft Entra ID SigninLogs SessionId/UniqueTokenIdentifier fields and Okta System Log sso/session events to spot impossible travel, refresh-token reuse, and token use from anomalous ASNs.
subdomain: soc-operations
facing: defense
mitre_attack:
- T1550.001
nist_csf:
- DE.CM-01
upstream: hunting-saas-sso-token-abuse@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Entra ID sign-in logs flowing to queryable store (Microsoft Sentinel / Log Analytics):
  ```bash
  # Confirm the diagnostic settings export SigninLogs + non-interactive logs to a workspace
  az monitor diagnostic-settings list --resource \
    /providers/Microsoft.aadiam/diagnosticSettings -o table
  ```
- Okta System Log access via API or SIEM ingestion:
  ```bash
  curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
    "https://<org>.okta.com/api/v1/logs?filter=eventType eq \"user.session.start\"&since=2026-06-01T00:00:00Z"
  ```
- IP enrichment source (GeoIP + ASN/hosting-provider classification)
- Read access to SIEM (KQL for Sentinel, SPL for Splunk)
- Python 3.9+ for helper script (`requests` for Okta API)

## MITRE ATT&CK Mapping

| ID | Name | Use in this skill |
|----|------|-------------------|
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Core technique — replaying stolen OAuth tokens/cookies |
| T1539 | Steal Web Session Cookie | cookie theft that precedes pass-the-cookie replay |
| T1528 | Steal Application Access Token | Acquisition of OAuth tokens via phishing/illicit consent |
| T1078.004 | Valid Accounts: Cloud Accounts | Replayed tokens grant valid-account access to SaaS |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | Follow-on persistence after token abuse |

## Workflow

### 1. Correlate Entra sign-in artifacts by session
Stitch interactive, non-interactive, and SP sign-ins for one session to see full chain.
```kusto
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| where isnotempty(SessionId)
| summarize IPs=make_set(IPAddress), Apps=make_set(AppDisplayName),
            Locations=make_set(tostring(LocationDetails.countryOrRegion)),
            Count=count() by SessionId, UserPrincipalName
| where array_length(IPs) > 1
```

### 2. Detect single session used from multiple ASNs (token replay)
```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| extend ASN = tostring(parse_json(tostring(NetworkLocationDetails))[0].networkType)
| summarize distinctIPs = dcount(IPAddress),
            ipset = make_set(IPAddress) by SessionId, UserPrincipalName
| where distinctIPs >= 2
```

### 3. Detect impossible travel within one authenticated session
```kusto
SigninLogs
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, IPAddress,
          City=tostring(LocationDetails.city),
          Country=tostring(LocationDetails.countryOrRegion), SessionId
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend prevCountry = prev(Country), prevTime = prev(TimeGenerated),
         prevUser = prev(UserPrincipalName)
| where UserPrincipalName == prevUser and Country != prevCountry
        and datetime_diff('minute', TimeGenerated, prevTime) < 60
```

### 4. Detect token use from hosting/VPS infrastructure
Replayed tokens are frequently used from datacenter ASNs, unlike user's residential/corporate ranges.
```kusto
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0
| extend asnOrg = tostring(parse_json(tostring(AutonomousSystemNumber)))
| where IPAddress in (toscalar(externaldata(ip:string)["<hosting-asn-iplist>"]))
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress
```

### 5. Hunt anomalous OAuth grants / illicit consent (token theft precursor)
```kusto
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add OAuth2PermissionGrant",
                          "Add delegated permission grant")
| extend app = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, app, Result
```

### 6. Hunt Okta System Log for reused session tokens
Single Okta session (`deviceToken`) used from divergent IPs/clients indicates hijack.
```bash
curl -s -H "Authorization: SSWS $OKTA_API_TOKEN" \
  "https://<org>.okta.com/api/v1/logs?filter=eventType eq \"policy.evaluate_sign_on\"&since=2026-06-15T00:00:00Z" \
  | jq -r '.[] | [.authenticationContext.externalSessionId, .client.ipAddress, .client.userAgent.rawUserAgent] | @tsv' \
  | sort | uniq -c | sort -rn
```

### 7. Splunk equivalent for Okta session reuse
```spl
index=okta eventType="policy.evaluate_sign_on"
| stats dc(client.ipAddress) as ip_count
        values(client.ipAddress) as ips
        values(client.userAgent.rawUserAgent) as agents
        by authenticationContext.externalSessionId actor.alternateId
| where ip_count > 1
```

### 8. Triage and respond
For confirmed token abuse, revoke sessions and rotate, then promote hunt to rule.
```bash
# Revoke all refresh tokens / sessions for the user in Entra
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/users/<userId>/revokeSignInSessions"
```
See `scripts/agent.py` to pull Okta logs and flag reused session tokens automatically.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| MITRE ATT&CK T1550.001 | Technique reference | https://attack.mitre.org/techniques/T1550/001/ |
| Entra sign-in logs schema | KQL hunting field reference | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-azure-monitor-sign-ins-log-schema |
| Azure-Sentinel hunting repo | Community KQL detections | https://github.com/Azure/Azure-Sentinel |
| Okta System Log API | Event hunting source | https://developer.okta.com/docs/reference/api/system-log/ |
| Mandiant M-Trends | Token-theft threat landscape | https://www.mandiant.com/m-trends |
| AzureAD-Attack-Defense | PRT/token replay detection guidance | https://github.com/Cloud-Architekt/AzureAD-Attack-Defense |

## Preventive Controls to Recommend

Detection should pair with controls that make stolen tokens far less useful:

- **Entra Conditional Access "token protection"** binds sign-in session to the
  device, so exfiltrated cookie/PRT cannot be replayed off-device.
- **Continuous Access Evaluation (CAE)** revokes access in near-real-time on risk
  events instead of waiting for token expiry.
- **Phishing-resistant MFA (FIDO2/passkeys)** blocks AiTM proxy phishing that
  harvests tokens in first place.
- **Short token lifetimes + refresh-token rotation** shrink replay window and turn
  refresh-token reuse into unambiguous compromise signal.
- **Okta Identity Threat Protection (ITP)** flags suspected session hijacking natively.

## False-Positive Tuning

| Benign cause | Tuning |
|--------------|--------|
| Corporate VPN/proxy egress (many users, few IPs) | Allowlist known egress IPs/ASNs |
| Mobile carrier IP rotation | Widen impossible-travel time/distance thresholds |
| Legitimate multi-device users | Correlate device IDs, not IPs |
| Backend/API calls within one session | Exclude expected service principals |

## Key Indicators

| Indicator | Signal |
|-----------|--------|
| One `SessionId` across multiple IPs/ASNs | Token/cookie replay |
| Non-interactive sign-in from new datacenter IP | Replayed refresh token |
| Impossible travel within < 1h | Concurrent session use |
| Refresh-token reuse after rotation | Strong compromise signal |
| New OAuth consent to unfamiliar app | Illicit-consent token theft |
| Okta session token from divergent user-agents | Session hijack |

## Validation Criteria

- [ ] Entra `SigninLogs` and `AADNonInteractiveUserSignInLogs` queryable
- [ ] Okta System Log accessible via API or SIEM
- [ ] Per-session correlation by `SessionId` produces results
- [ ] Multi-IP / multi-ASN single-session query implemented
- [ ] Impossible-travel-within-session query implemented
- [ ] Anomalous OAuth consent hunt implemented
- [ ] Okta reused-session-token hunt implemented
- [ ] Confirmed findings triaged and sessions revoked
- [ ] Effective queries promoted to standing detection rules
- [ ] False-positive baseline (VPN/proxy egress) documented

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-saas-sso-token-abuse
