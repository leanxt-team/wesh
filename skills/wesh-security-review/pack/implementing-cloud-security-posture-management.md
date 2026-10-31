---
name: implementing-cloud-security-posture-management
description: Continuously monitor multi-cloud environments (AWS, Azure, GCP) for misconfigurations, compliance violations, and security risks using Prowler, ScoutSuite, AWS Security Hub, Microsoft Defender for Cloud, and GCP Security Command Center.
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
upstream: implementing-cloud-security-posture-management@54a7988 Apache-2.0, modified by wesh
---
Not for: runtime workload protection (use CWPP tools like Falco or Aqua), for application security testing (use DAST/SAST tools), or for network intrusion detection (use cloud-native IDS like GuardDuty or Network Watcher).

## Prerequisites

- Multi-cloud credentials with read-only security audit permissions across all target environments
- Prowler v3+ installed (`pip install prowler`)
- ScoutSuite installed (`pip install scoutsuite`)
- AWS Config, Azure Policy, and GCP Organization Policy enabled in respective environments
- Central logging destination (S3 bucket, Log Analytics Workspace, or Cloud Storage) for findings aggregation
- Notification channels configured (Slack, PagerDuty, email) for critical finding alerts

## Workflow

### Step 1: Deploy Cloud-Native CSPM Services

Enable built-in CSPM capabilities in each cloud provider for baseline posture assessment.

```bash
# AWS: Enable Security Hub with FSBP and CIS standards
aws securityhub enable-security-hub --enable-default-standards
aws securityhub batch-enable-standards --standards-subscription-requests \
  '[{"StandardsArn":"arn:aws:securityhub:::standards/cis-aws-foundations-benchmark/v/1.4.0"}]'
# Azure: Enable Microsoft Defender for Cloud (CSPM tier)
az security pricing create --name CloudPosture --tier standard
az security auto-provisioning-setting update --name default --auto-provision on
# GCP: Enable Security Command Center Premium
gcloud services enable securitycenter.googleapis.com
gcloud scc settings update --organization=ORG_ID \
  --enable-asset-discovery
```

### Step 2: Run Prowler for Multi-Cloud Assessment

Execute Prowler to perform comprehensive security checks across all three cloud providers.

```bash
# AWS assessment with all CIS checks
prowler aws \
  --profile production \
  -M json-ocsf csv html \
  -o ./prowler-results/aws/ \
  --compliance cis_1.4_aws cis_1.5_aws
# Azure assessment
prowler azure \
  --subscription-ids SUB_ID_1 SUB_ID_2 \
  -M json-ocsf csv html \
  -o ./prowler-results/azure/ \
  --compliance cis_2.0_azure
# GCP assessment
prowler gcp \
  --project-ids project-1 project-2 \
  -M json-ocsf csv html \
  -o ./prowler-results/gcp/ \
  --compliance cis_2.0_gcp
# View summary across all providers
prowler aws --list-compliance
```

### Step 3: Run ScoutSuite for Cross-Cloud Comparison

Use ScoutSuite for unified multi-cloud security assessment with visual reporting.

```bash
# Scan AWS
python3 -m ScoutSuite aws --profile production \
  --report-dir ./scoutsuite/aws/
# Scan Azure
python3 -m ScoutSuite azure --cli \
  --all-subscriptions \
  --report-dir ./scoutsuite/azure/
# Scan GCP
python3 -m ScoutSuite gcp --user-account \
  --all-projects \
  --report-dir ./scoutsuite/gcp/
# Each produces an HTML report with risk-scored findings
```

### Step 4: Build Automated Compliance Monitoring Pipeline

Create scheduled pipeline that runs CSPM checks daily and routes findings to appropriate channels.

```bash
# Create a daily Prowler scan with EventBridge + CodeBuild (AWS)
cat > buildspec.yml << 'EOF'
version: 0.2
phases:
  install:
    commands:
      - pip install prowler
  build:
    commands:
      - prowler aws -M json-ocsf -o s3://security-findings-bucket/prowler/$(date +%Y%m%d)/
      - prowler aws --compliance cis_1.5_aws -M csv -o s3://security-findings-bucket/prowler/compliance/
  post_build:
    commands:
      - |
        CRITICAL=$(cat output/*.json | grep -c '"CRITICAL"')
        if [ "$CRITICAL" -gt 0 ]; then
          aws sns publish --topic-arn arn:aws:sns:us-east-1:ACCOUNT:security-alerts \
            --subject "Prowler: $CRITICAL critical findings" \
            --message "Review at s3://security-findings-bucket/prowler/$(date +%Y%m%d)/"
        fi
EOF
# Schedule with EventBridge
aws events put-rule \
  --name daily-prowler-scan \
  --schedule-expression "cron(0 6 * * ? *)" \
  --state ENABLED
```

### Step 5: Configure Finding Aggregation and Deduplication

Aggregate findings from multiple CSPM tools and cloud providers into unified view.

```python
# findings_aggregator.py - Normalize and deduplicate CSPM findings
import json
import hashlib
from datetime import datetime
def normalize_finding(finding, source):
    """Normalize findings from different CSPM tools to a common format."""
    normalized = {
        'id': hashlib.sha256(f"{finding.get('ResourceId','')}{finding.get('CheckId','')}".encode()).hexdigest()[:16],
        'source': source,
        'cloud': finding.get('Provider', 'unknown'),
        'account': finding.get('AccountId', finding.get('SubscriptionId', '')),
        'region': finding.get('Region', ''),
        'resource_type': finding.get('ResourceType', ''),
        'resource_id': finding.get('ResourceId', ''),
        'severity': finding.get('Severity', 'INFO').upper(),
        'status': finding.get('Status', 'FAIL'),
        'title': finding.get('CheckTitle', finding.get('Title', '')),
        'description': finding.get('StatusExtended', ''),
        'compliance': finding.get('Compliance', {}),
        'remediation': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
        'timestamp': datetime.utcnow().isoformat()
    }
    return normalized
def aggregate_findings(prowler_file, scoutsuite_file):
    findings = {}
    for file_path, source in [(prowler_file, 'prowler'), (scoutsuite_file, 'scoutsuite')]:
        with open(file_path) as f:
            for line in f:
                raw = json.loads(line)
                normalized = normalize_finding(raw, source)
                if normalized['status'] == 'FAIL':
                    findings[normalized['id']] = normalized
    return sorted(findings.values(), key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}.get(x['severity'],4))
```

### Step 6: Implement Drift Detection and Auto-Remediation

Set up automated responses to configuration drift that violates security baselines.

```bash
# AWS Config auto-remediation for non-compliant S3 buckets
aws configservice put-remediation-configurations --remediation-configurations '[{
  "ConfigRuleName": "s3-bucket-public-read-prohibited",
  "TargetType": "SSM_DOCUMENT",
  "TargetId": "AWS-DisableS3BucketPublicReadWrite",
  "Parameters": {
    "S3BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}}
  },
  "Automatic": true,
  "MaximumAutomaticAttempts": 3,
  "RetryAttemptSeconds": 60
}]'
# Azure Policy for auto-remediation
az policy assignment create \
  --name "enforce-storage-encryption" \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9" \
  --scope "/subscriptions/SUB_ID" \
  --enforcement-mode Default
# GCP Organization Policy constraint
gcloud resource-manager org-policies set-policy policy.yaml --organization=ORG_ID
# policy.yaml: constraint: constraints/storage.publicAccessPrevention, enforcement: true
```

## Key Concepts

| Term | Definition |
|------|------------|
| CSPM | Cloud Security Posture Management, practice of continuously monitoring cloud infrastructure for misconfigurations and compliance violations |
| Configuration Drift | Unintended changes to cloud resource configurations that deviate from approved security baseline over time |
| Security Baseline | documented set of minimum security configuration requirements that all cloud resources must meet |
| Compliance Framework | structured set of security controls and requirements (CIS, SOC 2, PCI DSS, NIST) against which cloud configurations are evaluated |
| Finding Severity | Risk classification of misconfiguration based on exploitability and potential impact (Critical, High, Medium, Low, Informational) |
| Auto-Remediation | Automated corrective action that restores non-compliant resource to its required configuration without manual intervention |

## Tools & Systems

- **Prowler**: Open-source multi-cloud security assessment tool with 300+ checks aligned to CIS, PCI DSS, HIPAA, and NIST
- **ScoutSuite**: Multi-cloud security auditing tool producing risk-scored HTML reports from API-collected configuration data
- **AWS Security Hub**: AWS-native CSPM with aggregated findings and compliance standard evaluation
- **Microsoft Defender for Cloud**: Azure-native CSPM with secure score, regulatory compliance, and workload protection
- **GCP Security Command Center**: GCP-native security platform with asset inventory, vulnerability scanning, and compliance monitoring

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-cloud-security-posture-management
