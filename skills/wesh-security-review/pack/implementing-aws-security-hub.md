---
name: implementing-aws-security-hub
description: Deploy AWS Security Hub as a centralized CSPM platform, backed by AWS Config, aggregating findings from GuardDuty, Inspector, Macie, and third-party tools; enable CIS Foundations, PCI-DSS, and NIST standards; automate remediation via EventBridge/Systems Manager; and produce Audit Manager evidence.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: implementing-aws-security-hub@54a7988 Apache-2.0, modified by wesh
---
Not for: real-time threat detection (see detecting-cloud-threats-with-guardduty), for Azure compliance monitoring (see securing-azure-with-microsoft-defender), or for deep vulnerability scanning of container images (see securing-container-registry).

## Prerequisites

- AWS Organization with designated security administrator account
- AWS Config enabled in all target accounts and regions
- GuardDuty, Inspector, and Macie activated for finding integration
- IAM permissions for securityhub:* and config:* in administrator account

## Workflow

### Step 1: Enable Security Hub with Standards

Activate Security Hub in delegated administrator account and enable security standards. AWS Security Hub CSPM supports CIS AWS Foundations Benchmark v5.0, AWS Foundational Security Best Practices, PCI DSS v3.2.1, and NIST SP 800-53.

```bash
# Enable Security Hub with standards
aws securityhub enable-security-hub \
  --enable-default-standards \
  --tags '{"Environment":"production","ManagedBy":"security-team"}'
# Enable CIS AWS Foundations Benchmark v5.0
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
    {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/pci-dss/v/3.2.1"}
  ]'
# Verify enabled standards
aws securityhub get-enabled-standards \
  --query 'StandardsSubscriptions[*].[StandardsArn,StandardsStatus]' --output table
```

### Step 2: Configure Multi-Account Aggregation

Designate Security Hub administrator and automatically enroll all organization member accounts. Configure cross-region aggregation to consolidate findings into single region.

```bash
# Designate delegated admin
aws securityhub enable-organization-admin-account \
  --admin-account-id 111122223333
# Auto-enable for all org members
aws securityhub update-organization-configuration \
  --auto-enable \
  --organization-configuration '{"ConfigurationType": "CENTRAL"}'
# Enable cross-region aggregation
aws securityhub create-finding-aggregator \
  --region-linking-mode ALL_REGIONS
```

### Step 3: Integrate Security Services and Third-Party Tools

Configure product integrations to receive findings from AWS services and partner security tools. Map third-party findings to AWS Security Finding Format (ASFF).

```bash
# List available product integrations
aws securityhub describe-products \
  --query 'Products[*].[ProductName,CompanyName,ProductSubscriptionResourcePolicy]' --output table
# Enable specific integrations
aws securityhub enable-import-findings-for-product \
  --product-arn "arn:aws:securityhub:us-east-1::product/aws/guardduty"
aws securityhub enable-import-findings-for-product \
  --product-arn "arn:aws:securityhub:us-east-1::product/aws/inspector"
# Import custom findings using ASFF format
aws securityhub batch-import-findings --findings '[{
  "SchemaVersion": "2018-10-08",
  "Id": "custom-finding-001",
  "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default",
  "GeneratorId": "custom-scanner",
  "AwsAccountId": "123456789012",
  "Types": ["Software and Configuration Checks/Vulnerabilities/CVE"],
  "Title": "Unpatched OpenSSL in production ALB backend",
  "Description": "CVE-2024-12345 detected on backend instances",
  "Severity": {"Label": "HIGH"},
  "Resources": [{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123"}]
}]'
```

### Step 4: Build Automated Remediation

Create Security Hub custom actions linked to EventBridge rules and Lambda functions for one-click or fully automated remediation of common findings.

```bash
# Create a custom action for remediation
aws securityhub create-action-target \
  --name "IsolateInstance" \
  --description "Isolate EC2 instance by replacing security groups" \
  --id "IsolateInstance"
# EventBridge rule for automated remediation of specific controls
aws events put-rule \
  --name SecurityHubAutoRemediate \
  --event-pattern '{
    "source": ["aws.securityhub"],
    "detail-type": ["Security Hub Findings - Imported"],
    "detail": {
      "findings": {
        "Compliance": {"Status": ["FAILED"]},
        "Severity": {"Label": ["CRITICAL", "HIGH"]},
        "GeneratorId": ["aws-foundational-security-best-practices/v/1.0.0/S3.1"]
      }
    }
  }'
```

### Step 5: Monitor Compliance Scores and Generate Reports

Track security scores across standards, monitor compliance drift over time, and generate reports for audit evidence.

```bash
# Get security score for a standard
aws securityhub get-security-control-definition \
  --security-control-id "S3.1"
# List all failed controls with counts
aws securityhub get-findings \
  --filters '{
    "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
  }' \
  --sort-criteria '{"Field": "SeverityLabel", "SortOrder": "desc"}' \
  --max-items 50
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Standard | Pre-packaged set of controls mapped to compliance frameworks e.g. CIS, PCI-DSS, NIST 800-53, and AWS best practices |
| Security Control | Individual automated check that evaluates specific AWS resource configuration against security requirement |
| ASFF | AWS Security Finding Format, standardized JSON schema for normalizing findings from all integrated security products |
| Compliance Score | Percentage of controls in passing state within given security standard, calculated per account and aggregated at organization level |
| Finding Aggregator | Cross-region mechanism that consolidates findings from all enabled regions into single administrator region |
| Custom Action | User-defined action that can be triggered from Security Hub console to invoke EventBridge rules for manual or automated response |

## Tools & Systems

- **AWS Security Hub CSPM**: Core platform for automated security posture checks and finding aggregation
- **AWS Config**: Underlying configuration recorder that Security Hub relies on for resource evaluation
- **Amazon EventBridge**: Event routing service for connecting Security Hub findings to automated remediation workflows
- **AWS Systems Manager**: Automation documents that Security Hub can invoke for remediation of common misconfigurations
- **AWS Audit Manager**: Generates audit-ready reports using Security Hub findings as evidence

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-aws-security-hub
