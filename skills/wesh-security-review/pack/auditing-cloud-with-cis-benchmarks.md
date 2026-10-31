---
name: auditing-cloud-with-cis-benchmarks
description: Audit AWS, Azure, and GCP environments against the CIS Foundations Benchmarks by running automated scans with tools like Prowler and ScoutSuite, interpreting failed controls, and tracking remediation for continuous compliance.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1098.003
- T1685.002
- T1580
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: auditing-cloud-with-cis-benchmarks@54a7988 Apache-2.0, modified by wesh
---
Not for: runtime threat detection (see detecting-cloud-threats-with-guardduty), for application-level security testing (see conducting-cloud-penetration-testing), or for compliance frameworks not based on CIS (refer to specific regulatory skill files).

## Prerequisites

- Read-only access to target cloud accounts (AWS SecurityAudit policy, Azure Reader role, GCP Viewer role)
- Prowler, ScoutSuite, or cloud-native CSPM tools installed and configured
- Understanding of CIS benchmark structure: sections, controls, profiles (Level 1 and Level 2)
- Remediation access for implementing fixes (separate from audit credentials)

## Workflow

### Step 1: Select Appropriate CIS Benchmark Version

Choose correct benchmark version for each cloud provider. Current versions as of 2025 include CIS AWS Foundations Benchmark v5.0, CIS Azure Foundations Benchmark v4.0, and CIS GCP Foundations Benchmark v4.0.

```
CIS Benchmark Coverage Areas:
+-------------------+-------------------------+------------------------+
| Section           | AWS v5.0                | Azure v4.0             |
+-------------------+-------------------------+------------------------+
| Identity & Access | IAM policies, MFA, root | Azure AD, RBAC, PIM    |
| Logging           | CloudTrail, Config      | Activity Log, Diag     |
| Monitoring        | CloudWatch alarms       | Defender, Sentinel     |
| Networking        | VPC, SG, NACLs         | NSG, ASG, Firewall     |
| Storage           | S3 encryption, access   | Storage encryption     |
| Database          | RDS encryption          | SQL TDE, auditing      |
+-------------------+-------------------------+------------------------+
CIS Profile Levels:
  Level 1: Practical security settings that can be implemented without significant
           performance impact or reduced functionality
  Level 2: Defense-in-depth settings that may reduce functionality or require
           additional planning for implementation
```

### Step 2: Run Automated Assessment with Prowler

Execute comprehensive CIS benchmark scans using Prowler for automated control evaluation across AWS, Azure, and GCP.

```bash
# AWS CIS v5.0 assessment
prowler aws \
  --compliance cis_5.0_aws \
  --profile audit-account \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-$(date +%Y%m%d)
# Azure CIS v4.0 assessment
prowler azure \
  --compliance cis_4.0_azure \
  --subscription-ids "sub-id-1,sub-id-2" \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-azure-$(date +%Y%m%d)
# GCP CIS v4.0 assessment
prowler gcp \
  --compliance cis_4.0_gcp \
  --project-ids "project-1,project-2" \
  --output-formats json-ocsf,html,csv \
  --output-directory ./cis-audit-gcp-$(date +%Y%m%d)
# Multi-account AWS scan using ScoutSuite
scout suite aws \
  --profile audit-account \
  --report-dir ./scout-report \
  --ruleset cis-5.0 \
  --force
```

### Step 3: Interpret Results and Prioritize Remediation

Analyze audit results by section and severity. Prioritize Level 1 controls first as they represent fundamental security hygiene, then address Level 2 controls for defense in depth.

```bash
# Parse Prowler results for failed controls
cat ./cis-audit-*/prowler-output-*.json | \
  jq '[.[] | select(.StatusExtended == "FAIL")] | group_by(.CheckID) |
  map({control: .[0].CheckID, description: .[0].CheckTitle,
  failed_resources: length, severity: .[0].Severity}) |
  sort_by(-.failed_resources)'
# Generate compliance score by section
cat ./cis-audit-*/prowler-output-*.json | \
  jq 'group_by(.Section) | map({
    section: .[0].Section,
    total: length,
    passed: [.[] | select(.StatusExtended == "PASS")] | length,
    failed: [.[] | select(.StatusExtended == "FAIL")] | length,
    score: (([.[] | select(.StatusExtended == "PASS")] | length) / length * 100 | round)
  })'
```

### Step 4: Remediate Critical and High Controls

Address failed controls starting with highest impact items. Use AWS Config remediation, Azure Policy, or Terraform to apply fixes systematically.

```bash
# CIS 1.4: Ensure no root account access key exists
aws iam list-access-keys --user-name root
# If keys exist, delete them
aws iam delete-access-key --user-name root --access-key-id AKIAEXAMPLE
# CIS 2.1.1: Ensure S3 bucket default encryption is enabled
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  aws s3api put-bucket-encryption --bucket "$bucket" \
    --server-side-encryption-configuration '{
      "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }' 2>/dev/null && echo "Encrypted: $bucket" || echo "FAILED: $bucket"
done
# CIS 3.1: Ensure CloudTrail is enabled in all regions
aws cloudtrail create-trail \
  --name organization-trail \
  --s3-bucket-name cloudtrail-logs-bucket \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/key-id
aws cloudtrail start-logging --name organization-trail
# CIS 4.x: Configure CloudWatch metric filters and alarms
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name UnauthorizedAPICalls \
  --filter-pattern '{ ($.errorCode = "*UnauthorizedAccess*") || ($.errorCode = "AccessDenied*") }' \
  --metric-transformations metricName=UnauthorizedAPICalls,metricNamespace=CISBenchmark,metricValue=1
```

### Step 5: Establish Continuous Compliance Monitoring

Deploy automated compliance monitoring to detect configuration drift between periodic audits. Use AWS Security Hub, Azure Policy, or GCP Security Command Center.

```bash
# AWS: Enable CIS v5.0 in Security Hub
aws securityhub batch-enable-standards \
  --standards-subscription-requests '[
    {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/5.0.0"}
  ]'
# Azure: Assign CIS benchmark policy initiative
az policy assignment create \
  --name cis-azure-benchmark \
  --scope "/subscriptions/<sub-id>" \
  --policy-set-definition "1a5bb27d-173f-493e-9568-eb56638dbd0e" \
  --params '{"effect": {"value": "AuditIfNotExists"}}'
# Schedule periodic Prowler assessments
# Run weekly via cron or CI/CD pipeline
0 2 * * 1 prowler aws --compliance cis_5.0_aws --output-formats csv --output-directory /opt/audits/weekly-$(date +\%Y\%m\%d)
```

## Key Concepts

| Term | Definition |
|------|------------|
| CIS Benchmark | Prescriptive security configuration guidelines developed by Center for Internet Security through community consensus |
| Level 1 Profile | Practical security controls implementable without significant performance or functionality impact, representing security hygiene |
| Level 2 Profile | Defense-in-depth controls that may restrict functionality and require careful planning before implementation |
| Foundations Benchmark | CIS benchmark specifically for cloud providers covering IAM, logging, monitoring, networking, and storage security |
| Control ID | Unique numerical identifier for each CIS recommendation (e.g., 1.4 for root access key checks, 2.1.1 for S3 encryption) |
| Compliance Score | Percentage of CIS controls in passing state, tracked over time to measure security posture improvement |
| Automated Assessment | Tool-driven evaluation of CIS controls using cloud provider APIs to check resource configurations against benchmark requirements |
| Remediation Runbook | Documented step-by-step procedure for fixing specific failed CIS control, including pre-checks and validation |

## Tools & Systems

- **Prowler**: Open-source cloud security tool performing 300+ checks including CIS benchmark assessments for AWS, Azure, and GCP
- **ScoutSuite**: Multi-cloud security auditing tool with CIS benchmark rule sets generating HTML reports
- **AWS Security Hub**: Native AWS service supporting CIS AWS Foundations Benchmark as security standard
- **Azure Policy**: Governance service with built-in CIS benchmark policy initiatives for automated compliance monitoring
- **GCP Security Command Center**: Native GCP service evaluating configurations against CIS GCP Foundations Benchmark

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-cloud-with-cis-benchmarks
