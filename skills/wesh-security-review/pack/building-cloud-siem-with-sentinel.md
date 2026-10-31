---
name: building-cloud-siem-with-sentinel
description: Deploy Microsoft Sentinel as a cloud-native SIEM/SOAR by configuring multi-cloud data connectors (AWS, Azure, GCP), writing KQL detection and hunting queries, and building automated Logic Apps response playbooks.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1548.005
- T1485
- T1530
- T1021.007
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: building-cloud-siem-with-sentinel@54a7988 Apache-2.0, modified by wesh
---
Not for: AWS-only environments where Security Hub and GuardDuty suffice, for endpoint detection requiring EDR capabilities (use Defender for Endpoint), or for compliance posture monitoring (see building-cloud-security-posture-management).

## Prerequisites

- Azure subscription with Microsoft Sentinel enabled on Log Analytics workspace
- Data connector permissions for target log sources (AWS CloudTrail, Azure Activity, GCP)
- Logic Apps or Azure Functions for automated response playbooks
- KQL (Kusto Query Language) proficiency for writing detection rules and hunting queries

## Workflow

### Step 1: Provision Sentinel Workspace and Data Connectors

Create Log Analytics workspace optimized for security data and enable data connectors for multi-cloud ingestion.

```powershell
# Create Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --location eastus \
  --retention-time 365 \
  --sku PerGB2018
# Enable Microsoft Sentinel on the workspace
az sentinel onboarding-state create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace
# Enable AWS CloudTrail connector
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id aws-cloudtrail \
  --kind AmazonWebServicesCloudTrail \
  --aws-cloud-trail-data-connector '{
    "awsRoleArn": "arn:aws:iam::123456789012:role/SentinelCloudTrailRole",
    "dataTypes": {"logs": {"state": "Enabled"}}
  }'
# Enable Azure AD sign-in and audit logs
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id azure-ad \
  --kind AzureActiveDirectory \
  --azure-active-directory '{
    "dataTypes": {
      "alerts": {"state": "Enabled"},
      "signinLogs": {"state": "Enabled"},
      "auditLogs": {"state": "Enabled"}
    }
  }'
```

### Step 2: Write KQL Detection Rules

Create analytics rules using Kusto Query Language to detect cloud-specific threats. Map each rule to MITRE ATT&CK techniques.

```kql
// Detect impossible travel - sign-ins from geographically distant locations
let timeframe = 1h;
let distance_threshold = 500; // km
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0 // Successful sign-ins only
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          Latitude = toreal(LocationDetails.geoCoordinates.latitude),
          Longitude = toreal(LocationDetails.geoCoordinates.longitude)
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevLatitude = prev(Latitude, 1), PrevLongitude = prev(Longitude, 1),
         PrevTime = prev(TimeGenerated, 1), PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where TimeDiff < 60
| extend Distance = geo_distance_2points(Longitude, Latitude, PrevLongitude, PrevLatitude) / 1000
| where Distance > distance_threshold
| project TimeGenerated, UserPrincipalName, IPAddress, Location, Distance, TimeDiff
```

```kql
// Detect AWS IAM credential abuse from CloudTrail
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventName in ("ConsoleLogin", "AssumeRole", "GetSessionToken")
| where ErrorCode == ""
| summarize LoginCount = count(), DistinctIPs = dcount(SourceIpAddress),
            IPList = make_set(SourceIpAddress, 10)
            by UserIdentityArn, bin(TimeGenerated, 1h)
| where DistinctIPs > 3
| project TimeGenerated, UserIdentityArn, LoginCount, DistinctIPs, IPList
```

```kql
// Detect mass S3 object deletion (potential ransomware)
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where EventName == "DeleteObject" or EventName == "DeleteObjects"
| summarize DeleteCount = count(), BucketsAffected = dcount(RequestParameters_bucketName)
            by UserIdentityArn, bin(TimeGenerated, 10m)
| where DeleteCount > 100
| project TimeGenerated, UserIdentityArn, DeleteCount, BucketsAffected
```

### Step 3: Build SOAR Playbooks with Logic Apps

Create automated response playbooks that execute when analytics rules trigger incidents. Common actions include blocking users, isolating resources, and enriching alerts with threat intelligence.

```json
{
  "definition": {
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "body": {"incidentArmId": "subscriptions/@{triggerBody()?['workspaceInfo']?['SubscriptionId']}/resourceGroups/@{triggerBody()?['workspaceInfo']?['ResourceGroupName']}/providers/Microsoft.OperationalInsights/workspaces/@{triggerBody()?['workspaceInfo']?['WorkspaceName']}/providers/Microsoft.SecurityInsights/Incidents/@{triggerBody()?['object']?['properties']?['incidentNumber']}"},
          "host": {"connection": {"name": "@parameters('$connections')['microsoftsentinel']['connectionId']"}}
        }
      }
    },
    "actions": {
      "Get_incident_entities": {
        "type": "ApiConnection",
        "inputs": {"method": "post", "path": "/Incidents/entities"}
      },
      "For_each_account_entity": {
        "type": "Foreach",
        "foreach": "@body('Get_incident_entities')?['Accounts']",
        "actions": {
          "Disable_Azure_AD_user": {
            "type": "ApiConnection",
            "inputs": {
              "method": "PATCH",
              "path": "/v1.0/users/@{items('For_each_account_entity')?['AadUserId']}",
              "body": {"accountEnabled": false}
            }
          },
          "Add_comment_to_incident": {
            "type": "ApiConnection",
            "inputs": {
              "body": {"message": "User @{items('For_each_account_entity')?['Name']} disabled by automated playbook"}
            }
          }
        }
      }
    }
  }
}
```

### Step 4: Configure Sentinel Data Lake for Long-Term Hunting

Enable Sentinel data lake for petabyte-scale log retention and advanced threat hunting using both KQL and SQL endpoints.

```kql
// Threat hunting query: detect lateral movement across AWS accounts
let suspicious_roles = AWSCloudTrail
| where TimeGenerated > ago(7d)
| where EventName == "AssumeRole"
| extend AssumedRoleArn = tostring(parse_json(RequestParameters).roleArn)
| where AssumedRoleArn contains "cross-account" or AssumedRoleArn contains "admin"
| summarize AssumeCount = count(), UniqueSourceAccounts = dcount(RecipientAccountId)
            by UserIdentityArn, AssumedRoleArn
| where AssumeCount > 10 and UniqueSourceAccounts > 2;
suspicious_roles
| join kind=inner (
    AWSCloudTrail
    | where TimeGenerated > ago(7d)
    | where EventName in ("RunInstances", "CreateFunction", "PutBucketPolicy")
) on UserIdentityArn
| project TimeGenerated, UserIdentityArn, AssumedRoleArn, EventName, SourceIpAddress
```

### Step 5: Integrate Threat Intelligence

Connect threat intelligence providers and create indicator-based matching rules to detect communication with known malicious infrastructure.

```powershell
# Enable Microsoft Threat Intelligence connector
az sentinel data-connector create \
  --resource-group security-rg \
  --workspace-name sentinel-workspace \
  --data-connector-id microsoft-ti \
  --kind MicrosoftThreatIntelligence \
  --microsoft-threat-intelligence '{
    "dataTypes": {"microsoftEmergingThreatFeed": {"lookbackPeriod": "2025-01-01T00:00:00Z", "state": "Enabled"}}
  }'
```

```kql
// Match network indicators against cloud flow logs
let TI_IPs = ThreatIntelligenceIndicator
| where TimeGenerated > ago(30d)
| where isnotempty(NetworkIP)
| distinct NetworkIP;
AzureNetworkAnalytics_CL
| where TimeGenerated > ago(24h)
| where DestIP_s in (TI_IPs)
| project TimeGenerated, SrcIP_s, DestIP_s, DestPort_d, FlowType_s
```

## Key Concepts

| Term | Definition |
|------|------------|
| KQL | Kusto Query Language, primary query language for Microsoft Sentinel used to search, analyze, and visualize security data |
| Analytics Rule | Detection logic in Sentinel that evaluates log data on schedule and creates incidents when conditions match |
| SOAR Playbook | Automated workflow triggered by incidents that performs response actions e.g. blocking accounts, enriching alerts, or notifying teams |
| Data Connector | Integration module that ingests security logs from cloud services, identity providers, and third-party tools into Sentinel |
| Sentinel Data Lake | Petabyte-scale storage layer providing long-term log retention with KQL and SQL query interfaces for advanced hunting |
| Workbook | Interactive dashboard in Sentinel displaying visualizations of security data, trends, and operational metrics |
| Watchlist | Reference data tables in Sentinel used to enrich alerts with context e.g. VIP user lists or approved IP ranges |
| Fusion Detection | Machine learning-powered correlation engine that automatically detects multi-stage attacks across data sources |

## Tools & Systems

- **Microsoft Sentinel**: Cloud-native SIEM/SOAR platform built on Azure Log Analytics with AI-powered threat detection
- **Azure Logic Apps**: Low-code automation platform for building SOAR playbooks triggered by Sentinel incidents
- **Microsoft Threat Intelligence**: Integrated threat feeds providing IP, domain, and URL indicators for matching against security logs
- **Azure Data Explorer**: High-performance analytics engine underlying Sentinel KQL queries for large-scale data exploration
- **MITRE ATT&CK Navigator**: Framework for mapping Sentinel detection rules to adversary tactics and techniques

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/building-cloud-siem-with-sentinel
