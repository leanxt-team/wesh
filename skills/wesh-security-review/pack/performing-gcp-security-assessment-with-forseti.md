---
name: performing-gcp-security-assessment-with-forseti
description: Performing comprehensive security assessments of Google Cloud Platform environments using Forseti Security, Security Command Center, and gcloud CLI to audit IAM policies, firewall rules, storage permissions, and compliance against CIS GCP Foundations Benchmark.
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
upstream: performing-gcp-security-assessment-with-forseti@54a7988 Apache-2.0, modified by wesh
---
Not for: as a replacement for GCP Security Command Center Premium for real-time threat detection, for application-level vulnerability scanning (use Web Security Scanner), or for GKE-specific security (use GKE Security Posture).

## Prerequisites

- GCP Organization with Organization Admin or Security Admin IAM role
- gcloud CLI authenticated with sufficient permissions (`roles/securitycenter.admin`, `roles/iam.securityReviewer`)
- Security Command Center (SCC) enabled at organization level
- ScoutSuite installed for multi-cloud comparison (`pip install scoutsuite`)
- Python 3.8+ for custom audit scripts using google-cloud-asset and google-cloud-securitycenter libraries

## Workflow

### Step 1: Enable Security Command Center and Asset Inventory

Enable SCC and set up Cloud Asset Inventory for comprehensive resource visibility.

```bash
# Enable Security Command Center API
gcloud services enable securitycenter.googleapis.com \
  --project=PROJECT_ID
# Enable Cloud Asset API
gcloud services enable cloudasset.googleapis.com \
  --project=PROJECT_ID
# List all assets in the organization
gcloud asset search-all-resources \
  --scope=organizations/ORG_ID \
  --asset-types="compute.googleapis.com/Instance,storage.googleapis.com/Bucket,iam.googleapis.com/ServiceAccount" \
  --format="table(name, assetType, location, project)"
# Export asset inventory to BigQuery for analysis
gcloud asset export \
  --organization=ORG_ID \
  --output-bigquery-force \
  --output-bigquery-dataset=projects/PROJECT_ID/datasets/asset_inventory \
  --output-bigquery-table=resources \
  --content-type=resource
```

### Step 2: Audit IAM Policies and Bindings

Review IAM policies across organization for overly permissive bindings, primitive roles, and service account misuse.

```bash
# List all IAM policy bindings at org level
gcloud organizations get-iam-policy ORG_ID \
  --format=json > org-iam-policy.json
# Find all users with Owner or Editor roles across projects
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner OR policy:roles/editor" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"
# Identify service accounts with admin roles
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy.bindings.members:serviceAccount AND policy:roles/owner" \
  --format=json
# Check for allUsers or allAuthenticatedUsers bindings (public access)
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"
# List service account keys older than 90 days
gcloud iam service-accounts keys list \
  --iam-account=SA_EMAIL \
  --managed-by=user \
  --format="table(name,validAfterTime,validBeforeTime)"
```

### Step 3: Assess Firewall Rules and Network Configuration

Audit VPC firewall rules for overly permissive ingress rules, missing logging, and network exposure.

```bash
# List all firewall rules allowing ingress from 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, sourceRanges, targetTags)"
# Find firewall rules allowing all protocols/ports
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"
# Check for SSH (22) and RDP (3389) open to internet
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"
# Audit VPC flow log configuration
gcloud compute networks subnets list \
  --format="table(name, region, enableFlowLogs, logConfig.aggregationInterval)"
```

### Step 4: Audit Cloud Storage Bucket Permissions

Check for publicly accessible storage buckets and missing encryption configurations.

```bash
# List all buckets in a project
gsutil ls -p PROJECT_ID
# Check bucket IAM for public access
for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil iam get "$bucket" | grep -E "allUsers|allAuthenticatedUsers" && \
    echo "  WARNING: PUBLIC ACCESS DETECTED" || \
    echo "  OK: No public access"
done
# Check bucket encryption configuration
for bucket in $(gsutil ls -p PROJECT_ID); do
  echo "=== $bucket ==="
  gsutil kms encryption "$bucket" 2>/dev/null || echo "  Using Google-managed encryption"
done
# Check uniform bucket-level access enforcement
for bucket in $(gsutil ls -p PROJECT_ID); do
  gsutil uniformbucketlevelaccess get "$bucket"
done
```

### Step 5: Run ScoutSuite for Comprehensive Assessment

Execute ScoutSuite for automated multi-check security assessment of GCP environment.

```bash
# Run ScoutSuite against GCP
python3 -m ScoutSuite gcp \
  --user-account \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report
# Run with service account credentials
python3 -m ScoutSuite gcp \
  --service-account /path/to/service-account-key.json \
  --all-projects \
  --report-dir ./scoutsuite-gcp-report
# Open the HTML report
open ./scoutsuite-gcp-report/gcp-report.html
```

### Step 6: Query Security Command Center Findings

Retrieve and analyze SCC findings for vulnerabilities, misconfigurations, and threats.

```bash
# List active SCC findings
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND severity=\"CRITICAL\"" \
  --format="table(finding.category, finding.severity, finding.resourceName, finding.eventTime)"
# List findings by category
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND category=\"PUBLIC_BUCKET_ACL\"" \
  --format=json
# Get finding statistics grouped by category
gcloud scc findings group ORG_ID \
  --group-by="category" \
  --filter="state=\"ACTIVE\""
# List compliance violations from SCC
gcloud scc findings list ORG_ID \
  --filter="state=\"ACTIVE\" AND sourceProperties.compliance_standard=\"CIS\"" \
  --format="table(finding.category, finding.severity, finding.resourceName)"
```

## Key Concepts

| Term | Definition |
|------|------------|
| Security Command Center | GCP-native security and risk management platform that provides asset inventory, vulnerability detection, and threat monitoring |
| Forseti Security | Open-source GCP security toolkit (now deprecated in favor of SCC) that provided inventory, scanning, enforcement, and notification capabilities |
| Cloud Asset Inventory | GCP service that provides complete inventory of cloud resources with metadata, IAM policies, and org policy configurations |
| CIS GCP Foundations Benchmark | Security best practice guidelines from Center for Internet Security specific to Google Cloud Platform configuration |
| Uniform Bucket-Level Access | GCP storage setting that disables legacy ACLs and enforces access exclusively through IAM policies for consistent access control |
| Organization Policy | GCP constraint-based governance mechanism that restricts resource configurations across organization hierarchy |

## Tools & Systems

- **Security Command Center**: GCP-native CSPM providing asset inventory, vulnerability findings, and compliance scoring
- **ScoutSuite**: Multi-cloud security auditing tool with comprehensive GCP checks for IAM, compute, storage, and networking
- **gcloud CLI**: Primary command-line interface for querying GCP resource configurations and security settings
- **Cloud Asset Inventory**: API for searching and exporting resource metadata and IAM policies across GCP projects
- **Forseti Security**: Legacy open-source GCP security toolkit, superseded by SCC but still referenced in compliance frameworks

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-gcp-security-assessment-with-forseti
