---
name: implementing-zero-trust-for-saas-applications
description: Secures SaaS apps (Microsoft 365, Google Workspace, Salesforce, Slack) via CASB/SSPM deployment, conditional access policies, OAuth app governance, and session-level DLP controls enforcing identity verification and device compliance.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1078.004
- T1530
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: implementing-zero-trust-for-saas-applications@54a7988 Apache-2.0, modified by wesh
---
Not for: as a replacement for SaaS-native security controls (configure those first), for applications with no SAML/OIDC support, or when SaaS vendor does not support API integration for CASB/SSPM.

## Prerequisites

- Identity provider with conditional access: Microsoft Entra ID P1/P2, Okta
- CASB solution: Microsoft Defender for Cloud Apps, Netskope, or Zscaler CASB
- SaaS applications configured with SSO via SAML 2.0 or OIDC
- MDM enrollment for device compliance signals (Intune, Jamf)
- DLP policies defined for sensitive data categories

## Workflow

### Step 1: Federate SaaS Authentication Through Identity Provider

Centralize authentication for all SaaS applications through single IdP.

```powershell
# Configure SAML SSO for Salesforce via Entra ID
Connect-MgGraph -Scopes "Application.ReadWrite.All"
# Create enterprise application for Salesforce
$app = New-MgServicePrincipal -AppId "SALESFORCE_APP_ID" -DisplayName "Salesforce"
# Configure SAML SSO settings
$samlSettings = @{
    preferredSingleSignOnMode = "saml"
    samlSingleSignOnSettings = @{
        relayState = ""
    }
}
Update-MgServicePrincipal -ServicePrincipalId $app.Id -BodyParameter $samlSettings
# Assign user groups to the application
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $app.Id -BodyParameter @{
    principalId = "SALES_GROUP_ID"
    resourceId = $app.Id
    appRoleId = "DEFAULT_ROLE_ID"
}
```

### Step 2: Create Conditional Access Policies for SaaS Applications

Enforce identity and device requirements before granting SaaS access.

```powershell
# Block access from non-compliant devices to sensitive SaaS apps
$policy = @{
    displayName = "ZT - Require Compliant Device for SaaS"
    state = "enabled"
    conditions = @{
        applications = @{
            includeApplications = @("SALESFORCE_APP_ID", "M365_APP_ID", "SLACK_APP_ID")
        }
        users = @{
            includeUsers = @("All")
            excludeGroups = @("BREAK_GLASS_GROUP")
        }
        clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
    }
    grantControls = @{
        operator = "AND"
        builtInControls = @("mfa", "compliantDevice")
    }
    sessionControls = @{
        cloudAppSecurity = @{
            isEnabled = $true
            cloudAppSecurityType = "mcasConfigured"
        }
        signInFrequency = @{
            value = 8
            type = "hours"
            isEnabled = $true
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $policy
# Block downloads on unmanaged devices
$downloadPolicy = @{
    displayName = "ZT - Block Downloads on Unmanaged Devices"
    state = "enabled"
    conditions = @{
        applications = @{ includeApplications = @("SHAREPOINT_APP_ID") }
        users = @{ includeUsers = @("All") }
        devices = @{
            deviceFilter = @{
                mode = "include"
                rule = "device.isCompliant -ne True -or device.trustType -ne 'ServerAD'"
            }
        }
    }
    sessionControls = @{
        cloudAppSecurity = @{
            isEnabled = $true
            cloudAppSecurityType = "mcasConfigured"
        }
    }
}
New-MgIdentityConditionalAccessPolicy -BodyParameter $downloadPolicy
```

### Step 3: Deploy CASB for Shadow IT Discovery and App Governance

Configure Microsoft Defender for Cloud Apps to discover and control SaaS usage.

```bash
# Query discovered cloud apps via Defender for Cloud Apps API
curl -X GET "https://api.cloudappsecurity.com/api/v1/discovery/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -H "Content-Type: application/json"
# Get list of unsanctioned apps
curl -X GET "https://api.cloudappsecurity.com/api/v1/discovery/discovered_apps/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{
    "filters": {
      "appTag": {"eq": "unsanctioned"},
      "traffic": {"gte": 1000}
    },
    "sortField": "traffic",
    "sortDirection": "desc"
  }'
# Create session policy for DLP enforcement
curl -X POST "https://api.cloudappsecurity.com/api/v1/policies/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{
    "name": "Block PII Upload to SaaS",
    "policyType": "SESSION",
    "severity": "HIGH",
    "enabled": true,
    "sessionPolicyType": "CONTROL_UPLOAD",
    "filters": {
      "fileType": {"eq": ["DOCUMENT", "SPREADSHEET"]},
      "contentInspection": {
        "dataType": ["CREDIT_CARD", "SSN", "PASSPORT"]
      }
    },
    "actions": {
      "block": true,
      "notify": {
        "emailRecipients": ["security-team@company.com"]
      }
    }
  }'
```

### Step 4: Configure OAuth App Governance

Review and restrict OAuth application permissions to prevent excessive consent.

```powershell
# Query OAuth apps with high-privilege permissions
$oauthApps = Invoke-MgGraphRequest -Method GET `
  "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=tags/any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&\$select=displayName,appId,oauth2PermissionScopes"
# Review consent grants
$grants = Get-MgOauth2PermissionGrant -All
$highRisk = $grants | Where-Object {
    $_.Scope -match "Mail.ReadWrite|Files.ReadWrite.All|Directory.ReadWrite.All"
}
Write-Host "High-risk OAuth grants: $($highRisk.Count)"
$highRisk | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
    Write-Host "  App: $($sp.DisplayName) | Scope: $($_.Scope) | Type: $($_.ConsentType)"
}
# Configure app consent policy to require admin approval
$consentPolicy = @{
    displayName = "Require Admin Approval for High-Risk Permissions"
    conditions = @{
        clientApplications = @{ includeAllClientApplications = $true }
        permissions = @{
            permissionClassification = "high"
            permissions = @(
                @{ permissionValue = "Mail.ReadWrite"; permissionType = "delegated" }
                @{ permissionValue = "Files.ReadWrite.All"; permissionType = "delegated" }
            )
        }
    }
}
```

### Step 5: Implement SaaS Security Posture Management (SSPM)

Audit and remediate SaaS security configuration drift.

```bash
# Query SaaS security posture via CASB API
curl -X GET "https://api.cloudappsecurity.com/api/v1/security_config/" \
  -H "Authorization: Token ${MDCA_API_TOKEN}" \
  -d '{"app": "Microsoft 365"}'
# Common SSPM checks:
# - MFA enforcement for all admin accounts
# - External sharing restrictions in SharePoint/OneDrive
# - Email forwarding rules to external domains blocked
# - Idle session timeout configured (< 8 hours)
# - Legacy authentication protocols disabled
# - Admin consent workflow enabled
# - Conditional access policies active
# - Audit logging enabled for all services
```

## Key Concepts

| Term | Definition |
|------|------------|
| CASB | Cloud Access Security Broker - intermediary enforcing security policies between users and SaaS applications |
| SSPM | SaaS Security Posture Management - continuous monitoring of SaaS application security configurations |
| OAuth Governance | Review and control of third-party application permissions granted through OAuth consent flows |
| Session Controls | Real-time access restrictions (block downloads, DLP inspection, watermarking) applied during active SaaS sessions |
| Shadow IT | Unauthorized SaaS applications used by employees without IT approval or security review |
| Conditional Access | Policy engine evaluating identity, device, location, and risk signals before granting SaaS access |

## Tools & Systems

- **Microsoft Defender for Cloud Apps**: CASB providing shadow IT discovery, session controls, DLP, and SSPM
- **Microsoft Entra ID Conditional Access**: Policy engine for identity-based access control to SaaS applications
- **Netskope CASB**: Cloud-native CASB with inline and API-based SaaS security controls
- **Okta Identity Governance**: OAuth app governance and access certification for SaaS applications
- **SSPM Tools**: AppOmni, Adaptive Shield, Valence Security for SaaS configuration monitoring

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-zero-trust-for-saas-applications
