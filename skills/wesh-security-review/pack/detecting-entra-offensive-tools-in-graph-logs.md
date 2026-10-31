---
name: detecting-entra-offensive-tools-in-graph-logs
description: Hunt AADGraphActivityLogs and MicrosoftGraphActivityLogs in Microsoft Sentinel/Log Analytics using KQL to fingerprint offensive Entra ID enumeration tools such as ROADtools, AADInternals, and AzureHound, including User-Agent signatures, roadrecon endpoint sweeps, and sign-in correlation.
subdomain: soc-operations
facing: defense
mitre_attack:
- T1078.004
nist_csf:
- DE.CM-09
upstream: detecting-entra-offensive-tools-in-graph-logs@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- A Microsoft Sentinel workspace (or Log Analytics) ingesting:
  - **MicrosoftGraphActivityLogs** (diagnostic setting on Microsoft Entra ID -> graph.microsoft.com)
  - **AADGraphActivityLogs** (diagnostic setting on Microsoft Entra ID -> legacy Azure AD Graph)
- `SigninLogs` and `AADNonInteractiveUserSignInLogs` for correlation
- Microsoft Sentinel Reader/Responder (or Log Analytics Reader) RBAC to run KQL
- Familiarity with Kusto Query Language (KQL)
- Enable diagnostic settings (Azure Portal -> Microsoft Entra ID -> Diagnostic settings -> send `MicrosoftGraphActivityLogs` and `AADGraphActivityLogs` to your workspace), or via CLI:
  ```bash
  az monitor diagnostic-settings create \
    --name "entra-graph-logs" \
    --resource "/providers/microsoft.aadiam/diagnosticSettings" \
    --logs '[{"category":"MicrosoftGraphActivityLogs","enabled":true},{"category":"AADGraphActivityLogs","enabled":true}]' \
    --workspace "<log-analytics-workspace-id>"
  ```

## MITRE ATT&CK Mapping

| ID | Technique | Application in this skill |
|----|-----------|---------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | Detecting adversaries using valid cloud credentials/tokens to enumerate tenant via Microsoft Graph and legacy Azure AD Graph APIs |

Related techniques surfaced by these hunts: **T1087.004** Account Discovery: Cloud Account, **T1069.003** Permission Groups Discovery: Cloud Groups, **T1526** Cloud Service Discovery.

## Workflow

### Step 1: Confirm both tables are ingesting
Before hunting, verify data exists and inspect schema fields you will pivot on.

```kusto
union withsource=Tbl MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| summarize Records=count(), LastSeen=max(TimeGenerated) by Tbl
```

### Step 2: Hunt User-Agent fingerprints (ROADtools / aiohttp)
ROADtools uses `aiohttp`; un-spoofed run shows `python` + `aiohttp` in User-Agent.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where RequestMethod == "GET"
| where UserAgent contains "python" and UserAgent contains "aiohttp"
| summarize RequestCount = count() by CallerIpAddress, AppId, UserAgent, UserId
| sort by RequestCount desc
```

### Step 3: Hunt AADInternals and AzureHound agents
AADInternals leaves toolkit/library strings; AzureHound's Go HTTP client and BloodHound tooling have distinctive agents.

```kusto
union MicrosoftGraphActivityLogs, AADGraphActivityLogs
| where TimeGenerated > ago(7d)
| where UserAgent has_any ("AADInternals", "aad-internals", "azurehound",
                           "BloodHound", "python-requests", "Go-http-client")
| project TimeGenerated, UserAgent, CallerIpAddress, AppId, UserId, RequestUri
| sort by TimeGenerated desc
```

### Step 4: Behavioral hunt — roadrecon endpoint sweep (spoof-resistant)
Even with spoofed agent, `roadrecon gather` touches recognizable set of directory resources in short window. Bucket by user and 5 minutes; alert when one identity hits full sweep.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| extend TopLevelResource = tolower(tostring(split(split(RequestUri, "?")[0], "/")[3]))
| summarize
    TopLevelResources = make_set(TopLevelResource),
    AppIds = make_set(AppId),
    CallerIPs = make_set(CallerIpAddress),
    UserAgents = make_set(UserAgent),
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated)
    by UserId, bin(TimeGenerated, 5m)
| where TopLevelResources has_all ("users", "tenantdetails", "groups", "applications",
    "serviceprincipals", "devices", "directoryroles", "roledefinitions", "contacts",
    "oauth2permissiongrants", "authorizationpolicy")
| project StartTime, EndTime, UserId, AppIds, CallerIPs, UserAgents
```

### Step 5: High-volume enumeration outliers
Catch tooling that makes far more directory reads than human in short window.

```kusto
MicrosoftGraphActivityLogs
| where TimeGenerated > ago(1d)
| where RequestMethod == "GET"
| where RequestUri has_any ("/users", "/groups", "/servicePrincipals", "/applications",
                            "/directoryRoles", "/roleManagement")
| summarize Reads=count(), Resources=dcount(RequestUri) by UserId, AppId, CallerIpAddress, bin(TimeGenerated, 10m)
| where Reads > 200
| sort by Reads desc
```

### Step 6: Correlate Graph activity to originating sign-in
Pivot suspicious Graph caller back to sign-in to recover device, location, MFA, and conditional-access result. Note the `SignInActivityId` in AADGraphActivityLogs may carry `==` padding versus `SigninLogs.UniqueTokenIdentifier`.

```kusto
AADGraphActivityLogs
| where TimeGenerated > ago(1d)
| where UserAgent contains "aiohttp"
| extend TokenId = trim_end("=", tostring(SignInActivityId))
| join kind=leftouter (
    SigninLogs
    | extend TokenId = tostring(UniqueTokenIdentifier)
    | project TokenId, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus, DeviceDetail
) on TokenId
| project TimeGenerated, UserId, UserPrincipalName, CallerIpAddress, IPAddress,
          AppDisplayName, ConditionalAccessStatus, UserAgent
```

### Step 7: Operationalize as analytics rules
Promote highest-fidelity queries (Steps 2-4) to scheduled analytics rules. Set query period/frequency (e.g., run every 1h over 1d), map rule to T1078.004, and configure entity mappings (Account = UserId, IP = CallerIpAddress, Host/App = AppId) so incidents enrich automatically. Tune out known automation/service-principal App IDs and approved scanner IPs via watchlist before enabling.

## Tools and Resources

| Resource | Purpose | Source |
|----------|---------|--------|
| AADGraphActivityLogs reference | Schema and field meaning | https://learn.microsoft.com/entra/identity/monitoring-health/concept-aad-graph-activity-logs |
| MicrosoftGraphActivityLogs | Graph API activity schema | https://learn.microsoft.com/graph/microsoft-graph-activity-logs-overview |
| Invictus-IR writeup | AADGraphActivityLogs hunting queries | https://www.invictus-ir.com/news/the-missing-link-aadgraphactivitylogs-finally-arrives |
| Cloudbrothers analysis | Behavioral fingerprinting of ROADtools | https://cloudbrothers.info/en/aadgraphactivitylogs/ |
| ROADtools | offensive tool being detected | https://github.com/dirkjanm/ROADtools |
| MITRE T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

## Detection Fingerprint Reference

| Tool | Primary fingerprint | Table |
|------|---------------------|-------|
| ROADtools (roadrecon) | `python` + `aiohttp` UA; full directory endpoint sweep in 5 min | AADGraphActivityLogs |
| AADInternals | `AADInternals` / toolkit strings in UA; AAD Graph reads | AADGraphActivityLogs |
| AzureHound | Go HTTP client UA; broad MS Graph enumeration | MicrosoftGraphActivityLogs |
| Generic recon | High GET volume across users/groups/apps/SPs in short window | both |

## Validation Criteria

- [ ] Both MicrosoftGraphActivityLogs and AADGraphActivityLogs confirmed ingesting
- [ ] User-Agent fingerprint hunt for ROADtools/aiohttp executed
- [ ] AADInternals/AzureHound agent hunt executed
- [ ] Behavioral endpoint-sweep hunt executed and tuned for false positives
- [ ] High-volume enumeration outlier query executed
- [ ] At least one finding correlated back to sign-in/session and source identity
- [ ] Best queries promoted to scheduled analytics rules with T1078.004 mapping and entity mappings
- [ ] Known-good service principals/IPs excluded via watchlist to control false positives

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-entra-offensive-tools-in-graph-logs
