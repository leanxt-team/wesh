---
name: securing-azure-with-microsoft-defender
description: 'Deploys and configures Microsoft Defender for Cloud as a CNAPP for Azure, multi-cloud, and hybrid environments: enabling Defender plans for servers, containers, storage, and databases, configuring recommendations, and managing Secure Score via the unified Defender portal.'
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1610
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: securing-azure-with-microsoft-defender@54a7988 Apache-2.0, modified by wesh
---
Not for: AWS-only environments (see implementing-aws-security-hub), for identity provider configuration (see managing-cloud-identity-with-okta), or for network-level firewall rule management (see implementing-cloud-waf-rules).

## Prerequisites

- Azure subscription with Security Admin or Contributor role
- Azure Policy initiative for Defender for Cloud enabled at management group level
- Log Analytics workspace provisioned for security data collection
- Microsoft Defender for Cloud plans licensed (P1 or P2 for server protection)

## Workflow

### Step 1: Enable Defender for Cloud Plans

Activate Defender plans for each workload type: Servers, Containers, App Service, Storage, Databases, Key Vault, Resource Manager, and DNS. Each plan provides specialized threat detection and vulnerability assessment.

```powershell
# Enable Defender for Servers Plan 2
az security pricing create --name VirtualMachines --tier Standard --subplan P2
# Enable Defender for Containers
az security pricing create --name Containers --tier Standard
# Enable Defender for Storage with malware scanning
az security pricing create --name StorageAccounts --tier Standard \
  --extensions '[{"name":"OnUploadMalwareScanning","isEnabled":"True",
  "additionalExtensionProperties":{"CapGBPerMonthPerStorageAccount":"5000"}}]'
# Enable Defender for Databases
az security pricing create --name SqlServers --tier Standard
az security pricing create --name CosmosDbs --tier Standard
# Enable Defender for Key Vault
az security pricing create --name KeyVaults --tier Standard
# Verify all enabled plans
az security pricing list --query "[?pricingTier=='Standard'].{Plan:name, Tier:pricingTier, SubPlan:subPlan}" -o table
```

### Step 2: Configure Environment Connectors for Multi-Cloud

Connect AWS accounts and GCP projects to Defender for Cloud for unified security posture management across cloud providers.

```powershell
# Create AWS connector for CSPM
az security security-connector create \
  --name aws-production-connector \
  --resource-group security-rg \
  --environment-name AWS \
  --hierarchy-identifier "123456789012" \
  --offerings '[{
    "offeringType": "CspmMonitorAws",
    "nativeCloudConnection": {"cloudRoleArn": "arn:aws:iam::123456789012:role/DefenderForCloudRole"}
  }]'
# Create GCP connector
az security security-connector create \
  --name gcp-production-connector \
  --resource-group security-rg \
  --environment-name GCP \
  --hierarchy-identifier "my-gcp-project-id" \
  --offerings '[{"offeringType": "CspmMonitorGcp"}]'
```

### Step 3: Review and Prioritize Secure Score Recommendations

Analyze Secure Score across all subscriptions. Each recommendation includes risk priority based on asset exposure, internet exposure, and threat intelligence context.

```powershell
# Get current Secure Score
az security secure-score list \
  --query "[].{Name:displayName, Score:current, Max:max, Percentage:percentage}" -o table
# List unhealthy recommendations sorted by severity
az security assessment list \
  --query "[?properties.status.code=='Unhealthy'].{Name:properties.displayName, Severity:properties.metadata.severity, Resources:properties.resourceDetails.id}" \
  --output table
# Get specific recommendation details
az security assessment show \
  --assessment-name "4fb67663-9ab9-475d-b026-8c544cced439" \
  --query "{Name:properties.displayName, Description:properties.metadata.description, Remediation:properties.metadata.remediationDescription}"
```

### Step 4: Configure Adaptive Application Controls and JIT Access

Enable Just-In-Time VM access to reduce attack surface by opening management ports only when needed, and deploy adaptive application controls to whitelist approved executables.

```powershell
# Enable JIT VM access policy
az security jit-policy create \
  --resource-group production-rg \
  --location eastus \
  --name default \
  --virtual-machines '[{
    "id": "/subscriptions/sub-id/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-01",
    "ports": [
      {"number": 22, "protocol": "TCP", "allowedSourceAddressPrefix": "10.0.0.0/8", "maxRequestAccessDuration": "PT3H"},
      {"number": 3389, "protocol": "TCP", "allowedSourceAddressPrefix": "10.0.0.0/8", "maxRequestAccessDuration": "PT1H"}
    ]
  }]'
# Request JIT access
az security jit-policy initiate \
  --resource-group production-rg \
  --location eastus \
  --name default \
  --virtual-machines '[{
    "id": "/subscriptions/sub-id/resourceGroups/production-rg/providers/Microsoft.Compute/virtualMachines/web-server-01",
    "ports": [{"number": 22, "duration": "PT1H", "allowedSourceAddressPrefix": "203.0.113.10"}]
  }]'
```

### Step 5: Set Up Security Alerts and Workflow Automation

Configure workflow automation to trigger Logic Apps or Azure Functions when security alerts are generated. Set up email notifications for Critical and High severity alerts.

```powershell
# Create workflow automation for high severity alerts
az security automation create \
  --name high-severity-alert-automation \
  --resource-group security-rg \
  --scopes '[{"description": "Production subscription", "scopePath": "/subscriptions/<sub-id>"}]' \
  --sources '[{
    "eventSource": "Alerts",
    "ruleSets": [{"rules": [{"propertyJPath": "Severity", "propertyType": "String", "expectedValue": "High", "operator": "Equals"}]}]
  }]' \
  --actions '[{
    "logicAppResourceId": "/subscriptions/<sub-id>/resourceGroups/security-rg/providers/Microsoft.Logic/workflows/alert-handler",
    "actionType": "LogicApp"
  }]'
# Configure email notifications
az security contact create \
  --name default \
  --email "soc-team@company.com" \
  --alert-notifications "on" \
  --alerts-to-admins "on"
```

### Step 6: Enable Cloud Security Graph and Attack Path Analysis

Use cloud security graph to visualize attack paths that adversaries could exploit to reach critical assets. Prioritize remediation based on actual exploitability rather than individual finding severity.

```
# Query attack paths via Resource Graph
az graph query -q "
  securityresources
  | where type == 'microsoft.security/attackpaths'
  | extend riskLevel = properties.riskLevel
  | extend entryPoint = properties.attackPathDisplayName
  | where riskLevel == 'Critical'
  | project entryPoint, riskLevel, properties.description
  | limit 20
"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Secure Score | numerical measure of organization's security posture based on percentage of implemented security recommendations, scored per subscription and aggregated at management group level |
| Cloud Security Graph | graph database mapping relationships between cloud resources, identities, network exposure, and vulnerabilities to identify exploitable attack paths |
| Attack Path Analysis | Visualization of multi-step attack chains adversary could follow from entry point to high-value target, prioritized by real-world exploitability |
| Just-In-Time Access | Security control that blocks management ports by default and opens them temporarily upon approved request, reducing VM attack surface |
| Adaptive Application Controls | Machine-learning-based allowlisting that recommends which applications should run on VMs and alerts on deviations |
| Defender CSPM | Enhanced cloud security posture management plan providing agentless scanning, attack path analysis, and cloud security graph capabilities |
| Security Connector | Integration point connecting AWS or GCP environments to Defender for Cloud for multi-cloud posture management |

## Tools & Systems

- **Microsoft Defender for Cloud**: Core CNAPP platform providing CSPM, CWP, and threat protection across Azure, AWS, and GCP
- **Azure Resource Graph**: Query engine for exploring cloud security graph data and attack paths at scale
- **Azure Logic Apps**: Workflow automation platform for building remediation playbooks triggered by Defender alerts
- **Microsoft Defender Portal**: Unified security operations console integrating Defender for Cloud with XDR, Sentinel, and threat intelligence
- **Azure Policy**: Governance engine for enforcing Defender for Cloud recommendations as compliance requirements

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/securing-azure-with-microsoft-defender
