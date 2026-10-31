---
name: remediating-s3-bucket-misconfiguration
description: 'Provides step-by-step procedures for remediating Amazon S3 bucket misconfigurations that expose sensitive data: enabling S3 Block Public Access, auditing bucket policies and ACLs, enforcing encryption, configuring access logging, and deploying automated remediation with AWS Config and Lambda.'
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1573
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: remediating-s3-bucket-misconfiguration@54a7988 Apache-2.0, modified by wesh
---
Not for: Azure Blob Storage or GCP Cloud Storage misconfigurations, for S3 data classification (see implementing-cloud-dlp-policy), or for S3 access pattern analysis unrelated to security.

## Prerequisites

- AWS account with S3 administrative permissions (s3:*, s3-outposts:*)
- AWS Config enabled to evaluate S3 resource compliance
- AWS CloudTrail logging S3 data events for access auditing
- Macie enabled for sensitive data discovery in S3 buckets

## Workflow

### Step 1: Identify All Public and Misconfigured Buckets

Use multiple detection methods to identify S3 buckets with public access. Rely on AWS Config rules, S3 Access Analyzer, and Macie rather than manual inspection.

```bash
# Enable S3 Access Analyzer for external access detection
aws accessanalyzer create-analyzer \
  --analyzer-name s3-analyzer \
  --type ACCOUNT
# List all S3 buckets with public access indicators
aws s3api list-buckets --query 'Buckets[*].Name' --output text | while read bucket; do
  public_status=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
  if [ $? -ne 0 ]; then
    echo "NO PUBLIC ACCESS BLOCK: $bucket"
  fi
done
# Check bucket policies for public access grants
aws s3api list-buckets --query 'Buckets[*].Name' --output text | while read bucket; do
  policy=$(aws s3api get-bucket-policy --bucket "$bucket" 2>/dev/null)
  if echo "$policy" | grep -q '"Principal":"*"' 2>/dev/null; then
    echo "PUBLIC POLICY DETECTED: $bucket"
  fi
done
# Use AWS Config to find non-compliant buckets
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name s3-bucket-public-read-prohibited \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[*].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId'
```

### Step 2: Enable S3 Block Public Access at Account Level

Apply four Block Public Access settings at AWS account level as safety net. This prevents any bucket in account from being made public, regardless of individual bucket policies or ACLs.

```bash
# Enable account-level Block Public Access (all four settings)
aws s3control put-public-access-block \
  --account-id 123456789012 \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
# Verify account-level settings
aws s3control get-public-access-block --account-id 123456789012
# Enable at bucket level for defense in depth
aws s3api put-public-access-block \
  --bucket production-data-bucket \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'
```

### Step 3: Audit and Remediate Bucket Policies and ACLs

Review all bucket policies for overly permissive Principal statements and remove legacy ACLs. Enforce bucket ownership controls to disable ACLs entirely.

```bash
# Remove a public bucket policy
aws s3api delete-bucket-policy --bucket exposed-bucket
# Replace with a restrictive policy
aws s3api put-bucket-policy --bucket exposed-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnencryptedTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::exposed-bucket",
        "arn:aws:s3:::exposed-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    },
    {
      "Sid": "AllowOnlyVPCEndpoint",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::exposed-bucket",
        "arn:aws:s3:::exposed-bucket/*"
      ],
      "Condition": {
        "StringNotEquals": {"aws:SourceVpce": "vpce-0abc123def456"}
      }
    }
  ]
}'
# Enforce bucket owner for all objects (disable ACLs)
aws s3api put-bucket-ownership-controls --bucket exposed-bucket \
  --ownership-controls '{"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}'
```

### Step 4: Enforce Default Encryption

Enable default server-side encryption with AWS KMS or AES-256 for all buckets. Add bucket policy denying unencrypted object uploads.

```bash
# Enable default KMS encryption
aws s3api put-bucket-encryption --bucket production-data-bucket \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-id"
      },
      "BucketKeyEnabled": true
    }]
  }'
# Deny unencrypted uploads via bucket policy
aws s3api put-bucket-policy --bucket production-data-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedUploads",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:PutObject",
    "Resource": "arn:aws:s3:::production-data-bucket/*",
    "Condition": {
      "StringNotEquals": {"s3:x-amz-server-side-encryption": ["aws:kms", "AES256"]}
    }
  }]
}'
```

### Step 5: Enable Access Logging and Monitoring

Configure S3 server access logging and CloudTrail data events to track all object-level operations. Set up EventBridge rules to alert on suspicious access patterns.

```bash
# Enable server access logging
aws s3api put-bucket-logging --bucket production-data-bucket \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "s3-access-logs-bucket",
      "TargetPrefix": "production-data-bucket/"
    }
  }'
# Enable CloudTrail S3 data events
aws cloudtrail put-event-selectors --trail-name management-trail \
  --event-selectors '[{
    "ReadWriteType": "All",
    "DataResources": [{
      "Type": "AWS::S3::Object",
      "Values": ["arn:aws:s3:::production-data-bucket/"]
    }]
  }]'
```

### Step 6: Deploy Preventive Controls with SCP and Config

Use Service Control Policies to prevent disabling Block Public Access across organization. Deploy AWS Config rules with auto-remediation.

```bash
# SCP preventing Block Public Access removal
aws organizations create-policy \
  --name PreventS3PublicAccess \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyRemovePublicAccessBlock",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:PutAccountPublicAccessBlock"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/SecurityAdmin"}
      }
    }]
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| S3 Block Public Access | Four account-level and bucket-level settings that override any policy or ACL granting public access to S3 resources |
| Bucket Policy | JSON-based resource policy attached to S3 bucket defining who can access what objects under which conditions |
| ACL (Access Control List) | Legacy S3 access mechanism that grants permissions at bucket or object level; should be disabled via BucketOwnerEnforced |
| BucketOwnerEnforced | Ownership control setting that disables all ACLs on bucket, making bucket owner sole authority for access control |
| Server-Side Encryption | Automatic encryption of objects at rest using AES-256 (SSE-S3), AWS KMS (SSE-KMS), or customer-provided keys (SSE-C) |
| VPC Endpoint | Private connection between VPC and S3 that restricts bucket access to traffic originating from within VPC |
| S3 Access Analyzer | IAM Access Analyzer capability that identifies S3 buckets shared with external entities outside account or organization |

## Tools & Systems

- **AWS Config**: Evaluates S3 bucket compliance against managed rules and triggers auto-remediation for non-compliant resources
- **Amazon Macie**: Discovers and classifies sensitive data in S3 buckets to identify which misconfigurations pose highest data exposure risk
- **IAM Access Analyzer**: Identifies S3 buckets with policies or ACLs that grant access to external principals
- **S3 Storage Lens**: Provides organization-wide visibility into S3 usage patterns, access metrics, and security anomalies
- **Prowler**: Open-source tool that checks S3 security configurations against CIS benchmarks and best practices

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/remediating-s3-bucket-misconfiguration
