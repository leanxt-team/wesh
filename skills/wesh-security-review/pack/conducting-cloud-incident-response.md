---
name: conducting-cloud-incident-response
description: Respond to security incidents in AWS, Azure, and GCP via identity-based containment, cloud-native log analysis (CloudTrail, Azure Activity Logs, GCP Audit Logs), resource isolation, and forensic evidence acquisition adapted for ephemeral cloud infrastructure.
subdomain: incident-response
facing: defense
mitre_attack:
- T1078
- T1537
- T1580
- T1525
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: conducting-cloud-incident-response@54a7988 Apache-2.0, modified by wesh
---
Not for: on-premises-only incidents with no cloud component; use standard enterprise IR procedures.

## Prerequisites

- Cloud-native logging enabled and centralized: AWS CloudTrail (all regions), Azure Activity/Sign-in Logs, GCP Cloud Audit Logs
- IR-specific cloud IAM roles pre-provisioned with read-only forensic access
- Isolated forensic account/subscription/project for evidence preservation
- Cloud incident response runbooks specific to each cloud provider
- Cloud-native security tools: AWS GuardDuty, Azure Defender for Cloud, GCP Security Command Center
- Network traffic logging: VPC Flow Logs (AWS/GCP), NSG Flow Logs (Azure)

## Workflow

### Step 1: Detect and Confirm Cloud Incident

Identify scope and nature of compromise:

**AWS Indicators:**
```
CloudTrail suspicious events to investigate:
- ConsoleLogin from unexpected geolocation or IP
- CreateAccessKey for existing IAM user (persistence)
- RunInstances for crypto-mining (large instance types)
- PutBucketPolicy making S3 bucket public
- AssumeRole to cross-account roles
- DeleteTrail or StopLogging (defense evasion)
- CreateUser or AttachUserPolicy (privilege escalation)
```

**Azure Indicators:**
```
Azure Activity Log events to investigate:
- Sign-in from anonymous IP or TOR exit node
- Service principal credential added
- Role assignment changes (Owner, Contributor added)
- VM created in unusual region
- Storage account access key regenerated
- Conditional Access policy modified or deleted
- MFA disabled for user account
```

**GCP Indicators:**
```
GCP Audit Log events to investigate:
- SetIamPolicy changes granting broad access
- CreateServiceAccountKey for existing SA
- InsertInstance in unexpected zone
- SetBucketIamPolicy with allUsers
- DeleteLog or UpdateSink (log tampering)
```

### Step 2: Contain Cloud Identity Compromise

Cloud containment is primarily identity operation:

**AWS Containment:**
```bash
# Disable compromised IAM access keys
aws iam update-access-key --user-name compromised-user \
  --access-key-id AKIA... --status Inactive
# Attach deny-all policy to compromised user
aws iam attach-user-policy --user-name compromised-user \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
# Revoke all active sessions for compromised IAM role
aws iam put-role-policy --role-name compromised-role \
  --policy-name RevokeOlderSessions --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*",
      "Condition":{"DateLessThan":
        {"aws:TokenIssueTime":"2025-11-15T15:00:00Z"}}
    }]
  }'
# Isolate compromised EC2 instance
aws ec2 modify-instance-attribute --instance-id i-0abc123 \
  --groups sg-isolate-forensic
```

**Azure Containment:**
```powershell
# Disable compromised user
Set-AzureADUser -ObjectId "user@tenant.onmicrosoft.com" -AccountEnabled $false
# Revoke all sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"
# Remove role assignments
Remove-AzRoleAssignment -ObjectId "sp-object-id" -RoleDefinitionName "Contributor"
# Isolate VM with NSG deny-all rule
$nsg = New-AzNetworkSecurityGroup -Name "isolate-nsg" -ResourceGroupName "rg" -Location "eastus"
$nsg | Add-AzNetworkSecurityRuleConfig -Name "DenyAll" -Priority 100 -Direction Inbound `
  -Access Deny -Protocol * -SourceAddressPrefix * -SourcePortRange * `
  -DestinationAddressPrefix * -DestinationPortRange *
```

### Step 3: Preserve Cloud Evidence

Collect evidence before ephemeral resources are terminated or logs rotate:

**AWS Evidence Collection:**
- Export CloudTrail events to S3 in forensic account
- Snapshot EBS volumes of compromised EC2 instances
- Copy S3 access logs and object versions
- Export VPC Flow Logs for affected VPC
- Capture IAM credential reports and access advisor data

**Azure Evidence Collection:**
- Export Azure Activity Logs and Sign-in Logs (90-day retention by default)
- Snapshot managed disks of compromised VMs
- Export Azure AD audit logs
- Capture NSG flow logs
- Export Conditional Access sign-in details

**GCP Evidence Collection:**
- Export Cloud Audit Logs to forensic storage bucket
- Snapshot persistent disks of compromised VMs
- Export VPC Flow Logs
- Capture IAM policy snapshots

### Step 4: Investigate Cloud-Specific Attack Patterns

Analyze logs for common cloud attack techniques:

```
Common Cloud Attack Patterns:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Credential Compromise → IAM Privilege Escalation → Resource Abuse
2. Public S3/Blob → Data Exfiltration
3. SSRF from Web App → IMDS Token Theft → Lateral Movement
4. Compromised CI/CD Pipeline → Malicious Deployment
5. Cross-Account Role Abuse → Multi-Account Pivot
6. Lambda/Function Abuse → Crypto-mining or Data Processing
```

**IMDS Token Theft Investigation (AWS):**
```bash
# Search CloudTrail for API calls using instance role credentials from external IP
aws cloudtrail lookup-events --lookup-attributes \
  AttributeKey=EventSource,AttributeValue=ec2.amazonaws.com \
  --start-time 2025-11-14 --end-time 2025-11-16 \
  | jq '.Events[] | select(.CloudTrailEvent | fromjson | .sourceIPAddress != "internal")'
```

### Step 5: Eradicate and Recover

Remove adversary access and restore secure state:

- Rotate all compromised credentials (access keys, passwords, service principal secrets)
- Remove unauthorized IAM users, roles, policies, and access keys created by attacker
- Terminate unauthorized compute instances (crypto-miners, C2 servers)
- Restore modified S3 bucket policies and storage access policies to pre-incident state
- Re-enable security controls that were disabled (CloudTrail, GuardDuty, Defender for Cloud)
- Review and restore Conditional Access policies and MFA configurations

### Step 6: Post-Incident Cloud Hardening

Implement controls to prevent recurrence:

- Enable MFA for all IAM users and require MFA for sensitive API calls
- Implement SCPs (AWS) or Azure Policy to prevent logging disablement
- Enable GuardDuty / Defender for Cloud / Security Command Center with auto-remediation
- Implement least-privilege IAM policies using access analyzer data
- Enable IMDS v2 (token-required) on all EC2 instances to prevent SSRF-based token theft
- Configure budget alerts to detect crypto-mining cost spikes

## Key Concepts

| Term | Definition |
|------|------------|
| **IMDS (Instance Metadata Service)** | Cloud service providing instance credentials accessible from within VM; SSRF attacks target IMDS to steal tokens |
| **CloudTrail** | AWS service logging all API calls across AWS account; primary evidence source for AWS incident response |
| **Service Principal** | Non-human identity in Azure AD used by applications and services; compromise enables persistent API access |
| **SCP (Service Control Policy)** | AWS Organizations policy that limits maximum permissions available to accounts; useful for guardrails |
| **Ephemeral Infrastructure** | Cloud resources (containers, functions, auto-scaled instances) that may be terminated before evidence can be collected |
| **Cross-Account Role Assumption** | AWS mechanism allowing one account to temporarily access resources in another; attackers pivot through assumed roles |

## Tools & Systems

- **AWS CloudTrail / Azure Activity Logs / GCP Audit Logs**: Cloud-native API logging services providing primary audit trail
- **Cado Response**: Cloud-native forensics platform for automated evidence capture from AWS, Azure, and GCP
- **Prowler (AWS) / ScoutSuite (multi-cloud)**: Open-source cloud security assessment tools for post-incident posture review
- **Steampipe**: Open-source SQL-based tool for querying cloud APIs to investigate IAM configurations and resource states
- **Cartography (Lyft)**: Open-source tool for mapping cloud infrastructure relationships and identifying attack paths

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-cloud-incident-response
