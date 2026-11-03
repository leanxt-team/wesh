---
name: performing-cloud-penetration-testing-with-pacu
description: Run authorized AWS penetration tests with Pacu, the open-source AWS exploitation framework, to enumerate IAM configuration, scan for privilege escalation paths, and test data access and lateral movement using compromised credentials.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
- T1068
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: performing-cloud-penetration-testing-with-pacu@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: unauthorized testing of any AWS account, for testing AWS infrastructure itself (covered by shared responsibility), for DDoS or volumetric attacks without AWS approval, or for production account testing without explicit authorization and breakglass procedures.

## Prerequisites

- Written authorization from AWS account owner with defined scope and rules of engagement
- Pacu v1.5+ installed (`pip install pacu`)
- Test AWS credentials with limited starting permissions (simulates compromised credential scenario)
- CloudTrail logging enabled to capture all Pacu activity for post-engagement review
- GuardDuty enabled to validate detection of Pacu activities
- Emergency contact and rollback procedures documented

## Workflow

### Step 1: Initialize Pacu Session and Configure Credentials

Set up Pacu session with test credentials and define engagement scope.

```bash
# Install Pacu
pip install pacu

# Start Pacu
pacu

# Create a new session for the engagement
Pacu > set_keys --key-alias pentest-target
# Enter Access Key ID: AKIA...
# Enter Secret Access Key: ...

# Verify identity
Pacu > whoami

# Review available modules
Pacu > list
Pacu > search iam
Pacu > search ec2
Pacu > search s3
```

### Step 2: Enumerate IAM Configuration

Run IAM enumeration modules to map users, roles, policies, and group memberships.

```bash
# Comprehensive IAM enumeration
Pacu > run iam__enum_users_roles_policies_groups

# Enumerate detailed permissions for the current principal
Pacu > run iam__enum_permissions

# Enumerate account authorization details (requires iam:GetAccountAuthorizationDetails)
Pacu > run iam__get_credential_report

# Enumerate role trust policies for cross-account access
Pacu > run iam__enum_roles

# Check current session data
Pacu > data iam
```

### Step 3: Scan for Privilege Escalation Paths

Use Pacu's privilege escalation scanner to identify all exploitable escalation vectors.

```bash
# Run the privilege escalation scanner
Pacu > run iam__privesc_scan

# The scanner tests for 21+ escalation methods:
# Method 1:  iam:CreatePolicyVersion
# Method 2:  iam:SetDefaultPolicyVersion
# Method 3:  iam:PassRole + ec2:RunInstances
# Method 4:  iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# Method 5:  iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping
# Method 6:  iam:PassRole + glue:CreateDevEndpoint
# Method 7:  iam:PassRole + cloudformation:CreateStack
# Method 8:  iam:PassRole + datapipeline:CreatePipeline
# Method 9:  iam:CreateAccessKey
# Method 10: iam:CreateLoginProfile
# Method 11: iam:UpdateLoginProfile
# Method 12: iam:AttachUserPolicy
# Method 13: iam:AttachGroupPolicy
# Method 14: iam:AttachRolePolicy
# Method 15: iam:PutUserPolicy
# Method 16: iam:PutGroupPolicy
# Method 17: iam:PutRolePolicy
# Method 18: iam:AddUserToGroup
# Method 19: iam:UpdateAssumeRolePolicy
# Method 20: sts:AssumeRole
# Method 21: lambda:UpdateFunctionCode

# If escalation paths found, attempt exploitation
Pacu > run iam__privesc_scan --escalate
```

### Step 4: Enumerate and Test Data Access

Discover accessible data stores including S3, DynamoDB, RDS, and Secrets Manager.

```bash
# Enumerate S3 buckets
Pacu > run s3__bucket_finder

# Download S3 bucket data for analysis
Pacu > run s3__download_bucket --bucket target-bucket --dl-names

# Enumerate EC2 instances and extract user data
Pacu > run ec2__enum
Pacu > run ec2__download_userdata

# Enumerate Lambda functions and check for secrets in environment variables
Pacu > run lambda__enum

# Enumerate Secrets Manager
Pacu > run secretsmanager__enum

# Enumerate SSM parameters (often contain secrets)
Pacu > run ssm__download_parameters

# Check for exposed EBS snapshots
Pacu > run ebs__enum_snapshots_unauth
```

### Step 5: Test Lateral Movement and Persistence

Evaluate cross-account access, service exploitation, and persistence mechanisms.

```bash
# Test cross-account role assumption
Pacu > run sts__assume_role --role-arn arn:aws:iam::TARGET:role/CrossAccountRole

# Enumerate Lambda for code execution opportunities
Pacu > run lambda__enum
# If lambda:UpdateFunctionCode permission exists, could inject code

# Test EC2 instance connect for lateral movement
Pacu > run ec2__enum
# Check for instances with instance profiles that have broader permissions

# Check for CodeBuild projects (potential credential access)
Pacu > run codebuild__enum

# Enumerate ECS/Fargate for container-based lateral movement
Pacu > run ecs__enum

# Export all discovered data
Pacu > data all
```

### Step 6: Validate Detection and Generate Report

Review whether security controls detected testing activities and compile findings.

```bash
# Check GuardDuty findings generated during testing
aws guardduty list-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-criteria '{
    "Criterion": {
      "updatedAt": {"GreaterThanOrEqual": ENGAGEMENT_START_EPOCH}
    }
  }' --output json

# Check Security Hub findings
aws securityhub get-findings \
  --filters '{
    "CreatedAt": [{"Start": "ENGAGEMENT_START_ISO", "End": "ENGAGEMENT_END_ISO"}]
  }'

# Export Pacu session data for reporting
Pacu > export_keys --all
Pacu > data all > pacu-session-export.json

# Clean up any test artifacts created during assessment
aws iam delete-user --user-name pacu-test-user 2>/dev/null
aws iam delete-access-key --user-name pacu-test-user --access-key-id AKIA... 2>/dev/null
```

## Key Concepts

| Term | Definition |
|------|------------|
| Pacu | Open-source AWS exploitation framework maintained by Rhino Security Labs, providing modular attack capabilities for authorized penetration testing |
| Privilege Escalation Scan | Automated analysis of IAM policies to identify known methods for elevating permissions from limited access to administrative control |
| iam:PassRole | Critical IAM action allowing principal to assign roles to AWS services, enabling indirect privilege escalation through Lambda, EC2, or Glue |
| Cross-Account Role Assumption | Using sts:AssumeRole to obtain temporary credentials in another AWS account through trust policy configurations |
| Rules of Engagement | Documented agreement defining scope, methods, timing, and boundaries of penetration testing engagement |
| Post-Exploitation | Activities performed after initial access to demonstrate impact, including data access, lateral movement, and persistence establishment |

## Tools & Systems

- **Pacu**: AWS exploitation framework with 50+ modules for enumeration, escalation, persistence, and data exfiltration
- **CloudFox**: AWS enumeration tool for identifying attack paths from attacker perspective
- **Principal Mapper**: IAM privilege escalation graph analysis tool for visualizing escalation paths
- **ScoutSuite**: Multi-cloud security assessment tool for identifying misconfigurations before testing
- **AWS CloudTrail**: Audit logging for capturing all Pacu activities during engagement

### Scenario: Red Team Assessment Starting from Compromised Developer Credentials

**Context**: Red team exercise simulates scenario where attacker obtains developer's AWS access key from leaked repository. Goal is to determine maximum impact achievable from this starting point.

**Approach**:
1. Initialize Pacu with compromised credentials and run `whoami` to confirm identity
2. Run `iam__enum_permissions` to map developer's effective permissions
3. Execute `iam__privesc_scan` to identify escalation paths from developer to admin
4. Discover developer can call `iam:PassRole` + `lambda:CreateFunction`, creating Lambda with admin role
5. Exploit escalation to obtain admin-level temporary credentials
6. Enumerate S3 buckets, download sensitive data, and access Secrets Manager
7. Verify whether GuardDuty detected escalation and data access activities
8. Clean up all test artifacts and document complete attack chain

**Pitfalls**: Pacu modules can be noisy and generate many API calls in short time. GuardDuty may trigger `Recon:IAMUser/MaliciousIPCaller` findings from tester's IP. Coordinate with SOC team to whitelist testing IP or establish clear communication channel to distinguish testing from real attacks. Always clean up persistence artifacts after testing.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-cloud-penetration-testing-with-pacu
