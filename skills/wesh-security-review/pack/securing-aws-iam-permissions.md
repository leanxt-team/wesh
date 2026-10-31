---
name: securing-aws-iam-permissions
description: Hardens AWS IAM configurations to enforce least-privilege access, covering IAM policy scoping, permission boundaries, IAM Access Analyzer integration, and credential rotation strategies.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1003
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: securing-aws-iam-permissions@54a7988 Apache-2.0, modified by wesh
---
Not for: Azure AD or Google Cloud IAM configurations, application-level authorization logic, or federated identity provider setup (see managing-cloud-identity-with-okta).

## Prerequisites

- AWS account with administrative access or IAM:FullAccess permissions
- AWS CLI v2 installed and configured with named profiles
- AWS CloudTrail enabled for at least 90 days of API activity history
- Familiarity with JSON-based IAM policy syntax and ARN resource notation

## Workflow

### Step 1: Inventory Existing IAM Entities and Policies

Generate comprehensive inventory of all IAM users, roles, groups, and attached policies using AWS CLI and IAM credential reports. Identify accounts with console access, programmatic access keys, and their last-used timestamps.

```bash
# Generate IAM credential report
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | base64 -d > iam-report.csv
# List all IAM roles and their attached policies
aws iam list-roles --query 'Roles[*].[RoleName,Arn,CreateDate]' --output table
# Find users with access keys older than 90 days
aws iam list-users --query 'Users[*].UserName' --output text | while read user; do
  aws iam list-access-keys --user-name "$user" \
    --query "AccessKeyMetadata[?CreateDate<='$(date -d '-90 days' +%Y-%m-%d)'].[UserName,AccessKeyId,Status,CreateDate]" \
    --output table
done
```

### Step 2: Enable and Analyze IAM Access Analyzer Findings

Activate IAM Access Analyzer at organization or account level to identify resources shared externally and generate least-privilege policy recommendations based on CloudTrail activity.

```bash
# Create an Access Analyzer for the account
aws accessanalyzer create-analyzer \
  --analyzer-name account-analyzer \
  --type ACCOUNT
# List active findings for external access
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/account-analyzer \
  --filter '{"status": {"eq": ["ACTIVE"]}}'
# Generate a policy based on CloudTrail activity for a specific role
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{
    "principalArn": "arn:aws:iam::123456789012:role/AppRole",
    "cloudTrailDetails": {
      "trailArn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
      "startTime": "2025-01-01T00:00:00Z",
      "endTime": "2025-03-01T00:00:00Z"
    }
  }'
```

### Step 3: Scope Policies to Specific Resources and Conditions

Replace wildcard resource ARNs with specific resource identifiers. Add IAM policy conditions for MFA enforcement, source IP restrictions, and time-based access windows.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::production-data-bucket",
        "arn:aws:s3:::production-data-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:MultiFactorAuthPresent": "true"},
        "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
        "DateGreaterThan": {"aws:CurrentTime": "2025-01-01T00:00:00Z"}
      }
    }
  ]
}
```

### Step 4: Implement Permission Boundaries

Attach permission boundaries to IAM roles and users to define maximum scope of permissions entity can receive, preventing privilege escalation even if administrator attaches overly permissive policy.

```bash
# Create a permission boundary policy
aws iam create-policy \
  --policy-name DeveloperPermissionBoundary \
  --policy-document file://developer-boundary.json
# Attach the boundary to an IAM role
aws iam put-role-permissions-boundary \
  --role-name DeveloperRole \
  --permissions-boundary "arn:aws:iam::123456789012:policy/DeveloperPermissionBoundary"
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCommonServices",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:*",
        "lambda:*",
        "logs:*",
        "cloudwatch:*"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyIAMChanges",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:DeleteUser",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePermissionsBoundary"
      ],
      "Resource": "*"
    }
  ]
}
```

### Step 5: Enforce MFA and Eliminate Long-Lived Credentials

Require MFA for all human users accessing AWS console and CLI. Migrate workloads from IAM user access keys to IAM roles with temporary credentials via STS AssumeRole.

```bash
# Enforce MFA via SCP at the organization level
aws organizations create-policy \
  --name RequireMFA \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyAllExceptMFA",
        "Effect": "Deny",
        "NotAction": [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ],
        "Resource": "*",
        "Condition": {
          "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
        }
      }
    ]
  }'
# Deactivate unused access keys
aws iam update-access-key --user-name old-user --access-key-id AKIAEXAMPLE --status Inactive
```

### Step 6: Automate Continuous IAM Monitoring

Deploy AWS Config rules and Security Hub controls to continuously evaluate IAM posture. Set up EventBridge rules to alert on high-risk IAM changes e.g. new root access key creation or policy modifications.

```bash
# Enable AWS Config rule for IAM password policy
aws configservice put-config-rule \
  --config-rule '{
    "ConfigRuleName": "iam-password-policy",
    "Source": {
      "Owner": "AWS",
      "SourceIdentifier": "IAM_PASSWORD_POLICY"
    },
    "InputParameters": "{\"RequireUppercaseCharacters\":\"true\",\"RequireLowercaseCharacters\":\"true\",\"RequireSymbols\":\"true\",\"RequireNumbers\":\"true\",\"MinimumPasswordLength\":\"14\",\"MaxPasswordAge\":\"90\"}"
  }'
# EventBridge rule to detect root account usage
aws events put-rule \
  --name DetectRootUsage \
  --event-pattern '{
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "userIdentity": {"type": ["Root"]}
    }
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Least Privilege | Granting only minimum permissions required for identity to perform its function |
| Permission Boundary | advanced IAM feature that sets maximum permissions entity can have, regardless of attached policies |
| IAM Access Analyzer | AWS service that uses automated reasoning to identify resources shared externally and generate least-privilege policies from CloudTrail activity |
| Service Control Policy (SCP) | Organization-level policy that sets permission guardrails across all accounts in AWS Organization |
| Assume Role | STS operation that returns temporary security credentials for cross-account or service-to-service access |
| Credential Report | AWS-generated CSV listing all IAM users, their access keys, MFA status, and last activity timestamps |
| Policy Condition | Constraints in IAM policies that restrict when and how permissions apply, e.g. MFA requirements or IP ranges |
| Identity Federation | Allowing external identity providers to grant temporary AWS access without creating IAM users |

## Tools & Systems

- **AWS IAM Access Analyzer**: Generates least-privilege policies from CloudTrail activity and identifies resources shared with external entities
- **AWS Config**: Continuously evaluates IAM configuration compliance against managed and custom rules
- **AWS Security Hub**: Aggregates IAM security findings from Access Analyzer, Config, and third-party tools into unified dashboard
- **IAM Policy Simulator**: Tests effects of IAM policies before deployment by simulating API calls against policy evaluation logic
- **Prowler**: Open-source AWS security assessment tool that runs over 300 checks including IAM best practices and CIS benchmark controls

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/securing-aws-iam-permissions
