---
name: deploying-cloud-deception-with-decoy-resources
description: 'Deploy cloud-native deception across AWS, Azure, and GCP using decoy (honey) resources whose only purpose is to generate a high-fidelity alert the instant an attacker touches them: canary IAM access keys, permission-less decoy users/roles/service principals, honey object-storage buckets, and decoy secrets in Secrets Manager / Key Vault / Secret Manager.'
subdomain: deception-technology
facing: defense
mitre_attack:
- T1078
- T1552
- T1580
- T1530
- T1619
nist_csf:
- DE.CM-01
- DE.CM-06
- DE.AE-02
- ID.RA-01
- RS.MA-01
upstream: deploying-cloud-deception-with-decoy-resources@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Cloud admin/IAM permissions to create decoy principals, storage, secrets, and detection wiring, ideally in dedicated deployment role with least privilege.
- Cloud audit logging already enabled: **AWS CloudTrail** (multi-region, with management and relevant data events), **Azure Activity log + Microsoft Entra audit/sign-in logs**, **GCP Cloud Audit Logs (Admin Activity always on; Data Access enabled where needed)**.
- A SIEM/alert sink: SNS topic, Microsoft Sentinel workspace, or GCP Pub/Sub + Monitoring, with routing to SOC.
- Naming and tagging convention i.e. plausible to attacker but unambiguous to defenders internally (e.g., realistic names, plus internal `deception=true` tag/label kept out of attacker-visible metadata).
- **Decoy principals must be permission-less (explicit deny-all).** value is alert, never access. decoy that grants real privilege is liability, not control.

## Workflow

### 1. Decide what to mimic
Pick decoys that match how *your* attackers operate: leaked AWS keys (credential theft), "admin" S3 bucket (data discovery), a `prod-db-password` secret (secrets harvesting), privileged-looking service account (cloud lateral movement). Place credential decoys where harvesting tools look: env files, CI variables, code comments, internal wiki.

### 2A. AWS — canary access keys on permission-less user
Create decoy IAM user with explicit deny-all policy, then issue access key to plant:
```bash
aws iam create-user --user-name svc-backup-prod --tags Key=deception,Value=true
aws iam put-user-policy --user-name svc-backup-prod \
  --policy-name deny-all \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
aws iam create-access-key --user-name svc-backup-prod   # plant the returned AccessKeyId/Secret
```
Any use of this key appears in CloudTrail (even denied calls, which still log `AccessDenied`). Wire EventBridge rule on CloudTrail to alert:
```bash
aws events put-rule --name decoy-key-used \
  --event-pattern '{"detail":{"userIdentity":{"userName":["svc-backup-prod"]}}}'
aws events put-targets --rule decoy-key-used \
  --targets "Id"="1","Arn"="arn:aws:sns:us-east-1:111111111111:soc-deception-alerts"
```

### 2B. AWS — honey S3 bucket
Create believable bucket, enable object-level data events, and alert on any read/list:
```bash
aws s3api create-bucket --bucket acme-prod-db-backups-2026 --region us-east-1
aws s3api put-bucket-tagging --bucket acme-prod-db-backups-2026 \
  --tagging 'TagSet=[{Key=deception,Value=true}]'
# Ensure CloudTrail captures S3 data events for this bucket, then alert on GetObject/ListBucket
aws events put-rule --name decoy-bucket-access \
  --event-pattern '{"detail":{"eventSource":["s3.amazonaws.com"],"requestParameters":{"bucketName":["acme-prod-db-backups-2026"]}}}'
```

### 2C. AWS — decoy secret
```bash
aws secretsmanager create-secret --name prod/db/master-password \
  --secret-string '{"username":"dbadmin","password":"DECOY-DO-NOT-USE"}' \
  --tags Key=deception,Value=true
# Alert on GetSecretValue for this secret via EventBridge -> SNS
```

### 3A. Azure — honeytoken watchlist + decoy service principal
Microsoft Sentinel natively supports honeytokens via **Watchlist** of the `HoneyTokens` template; tagged decoy accounts/secrets raise analytics alerts on use. Create permission-less decoy app registration / service principal, then add its identifiers to HoneyTokens watchlist and enable related analytics rules. Microsoft Defender for Cloud and Entra ID Protection surface anomalous sign-ins to decoy identity.

### 3B. Azure — honey storage + Key Vault decoy secret
Create decoy Storage account and Key Vault, enable diagnostic logging to Sentinel workspace, store decoy secret, and write analytics rule that fires on any data-plane read of decoy resources.

### 4A. GCP — decoy service account + honey GCS bucket
Create service account with no role bindings (permission-less), generate key to plant, and alert on its use via Cloud Audit Logs:
```bash
gcloud iam service-accounts create svc-billing-export \
  --display-name="billing-export"
gcloud iam service-accounts keys create decoy-key.json \
  --iam-account=svc-billing-export@PROJECT.iam.gserviceaccount.com   # plant this key
gsutil mb -b on gs://acme-finance-exports-2026
```
Create log-based metric + alerting policy in Cloud Monitoring that triggers on any audit-log entry where principal is decoy service account or resource is honey bucket.

### 5. Centralize and de-duplicate
Route all clouds' decoy alerts to one SOC pipeline. Tag each alert as DECEPTION/high-fidelity so it bypasses normal noise filtering and triggers IR playbook rather than triage queue.

### 6. Validate (red-team decoys)
Have authorized tester use each decoy (read bucket, call with key, fetch secret) and confirm alert lands end-to-end within target latency. decoy you have not tested is assumed broken.

### 7. Maintain realism and rotate
Refresh decoy names, secrets, and pocket-litter periodically so they age with real environment. Track every decoy in inventory so they are never mistaken for real assets during audits or cleanups.

## Key Concepts

| Concept | Definition |
|---|---|
| Decoy / honey resource | cloud object created solely to be touched by attacker; no legitimate user has any reason to use it. |
| Canary access key | planted credential whose use generates audit-log event; carries deny-all permissions. |
| High-fidelity alert | near-zero-false-positive signal because legitimate workflows never reference decoy. |
| Permission-less principal | decoy IAM user/role/service principal/service account with explicit deny-all or no role bindings. |
| Data event | Cloud audit logging of object/data-plane access (e.g., S3 GetObject), required to detect storage decoys. |
| Pocket litter | Plausible supporting artifacts (fake configs, env files, wiki entries) that make decoy credible. |
| Decoy inventory | authoritative internal record distinguishing decoys from real assets. |

## Tools & Systems

- **AWS** — IAM (decoy users/roles), S3 (honey buckets, data events), Secrets Manager / SSM Parameter Store (decoy secrets), CloudTrail, EventBridge, SNS/Lambda, GuardDuty (correlate anomalous use).
- **Azure** — Microsoft Entra ID (decoy app registrations / service principals), Storage / Key Vault decoys, **Microsoft Sentinel HoneyTokens watchlist** and analytics rules, Microsoft Defender for Cloud, Entra ID Protection.
- **GCP** — IAM service accounts (decoys), Cloud Storage (honey buckets), Secret Manager (decoy secrets), Cloud Audit Logs, log-based metrics + Cloud Monitoring alerting, Pub/Sub.
- **Open-source / managed honeytoken systems** — Canarytokens (https://canarytokens.org offers AWS API key tokens), Thinkst Canary, SpaceSiren / SpaceCrab (self-hosted AWS honey-token frameworks).
- **SIEM/SOAR** — to centralize alerts across clouds and drive IR playbook on any decoy hit.

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-cloud-deception-with-decoy-resources
