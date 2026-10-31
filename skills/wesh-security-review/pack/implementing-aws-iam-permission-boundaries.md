---
name: implementing-aws-iam-permission-boundaries
description: Configures AWS IAM permission boundaries that cap the maximum permissions an identity-based policy can grant to a user or role, so effective permissions are the intersection of the identity policy and the boundary even if the policy grants AdministratorAccess.
subdomain: identity-access-management
facing: config
mitre_attack:
- T1078
- T1110
- T1556
- T1098
- T1078.004
nist_csf:
- PR.AA-01
- PR.AA-02
- PR.AA-05
- PR.AA-06
upstream: implementing-aws-iam-permission-boundaries@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- AWS account with IAM administrative access
- Understanding of AWS IAM policy language (JSON)
- AWS CLI v2 configured with appropriate credentials
- Terraform or CloudFormation for infrastructure-as-code deployment

## Core Concepts

### How Permission Boundaries Work

```
Identity-Based Policy          Permission Boundary
(What the role CAN do)    ∩    (What the role MAY do)
        │                              │
        └──────────┬───────────────────┘
                   │
          Effective Permissions
    (Only actions in BOTH policies)
```

### Policy Evaluation Logic

AWS evaluates permissions in this order:
1. **Explicit Deny** in any policy - always wins
2. **Organizations SCP** - sets org-wide maximum
3. **Permission Boundary** - sets entity-level maximum
4. **Identity-Based Policy** - grants actual permissions
5. **Resource-Based Policy** - cross-account access (evaluated separately)

Entity can only perform action if ALL applicable policy types allow it.

### Key Use Cases

| Use Case | Description |
|----------|-------------|
| Developer Delegation | Allow devs to create IAM roles without escalating beyond their boundary |
| Sandbox Isolation | Limit what roles can do in sandbox/dev accounts |
| Multi-Tenant Workloads | Ensure tenant-specific roles cannot access other tenants' resources |
| CI/CD Pipeline Roles | Restrict automation roles to specific services |

## Workflow

### Step 1: Define Permission Boundary Policy

Create managed policy that defines maximum allowed permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowedServices",
            "Effect": "Allow",
            "Action": [
                "s3:*",
                "dynamodb:*",
                "lambda:*",
                "logs:*",
                "cloudwatch:*",
                "sqs:*",
                "sns:*",
                "events:*",
                "states:*",
                "xray:*",
                "ec2:Describe*",
                "ec2:CreateTags",
                "sts:AssumeRole",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowIAMPassRole",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::*:role/app-*",
            "Condition": {
                "StringEquals": {
                    "iam:PassedToService": [
                        "lambda.amazonaws.com",
                        "states.amazonaws.com"
                    ]
                }
            }
        },
        {
            "Sid": "DenyBoundaryDeletion",
            "Effect": "Deny",
            "Action": [
                "iam:DeletePolicy",
                "iam:DeletePolicyVersion",
                "iam:CreatePolicyVersion"
            ],
            "Resource": "arn:aws:iam::*:policy/DeveloperBoundary"
        },
        {
            "Sid": "DenyBoundaryRemoval",
            "Effect": "Deny",
            "Action": [
                "iam:DeleteUserPermissionsBoundary",
                "iam:DeleteRolePermissionsBoundary"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 2: Create Developer Delegation Policy

Grant developers ability to create IAM roles, but only with boundary attached:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowCreateRoleWithBoundary",
            "Effect": "Allow",
            "Action": [
                "iam:CreateRole",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy"
            ],
            "Resource": "arn:aws:iam::*:role/app-*",
            "Condition": {
                "StringEquals": {
                    "iam:PermissionsBoundary": "arn:aws:iam::*:policy/DeveloperBoundary"
                }
            }
        },
        {
            "Sid": "AllowCreatePolicyScoped",
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicy",
                "iam:DeletePolicy",
                "iam:CreatePolicyVersion",
                "iam:DeletePolicyVersion"
            ],
            "Resource": "arn:aws:iam::*:policy/app-*"
        },
        {
            "Sid": "AllowViewIAM",
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 3: Attach Boundary

```bash
# Create the boundary policy
aws iam create-policy \
    --policy-name DeveloperBoundary \
    --policy-document file://developer-boundary.json
# Attach boundary to an existing role
aws iam put-role-permissions-boundary \
    --role-name developer-role \
    --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary
# Create a new role with boundary
aws iam create-role \
    --role-name app-lambda-executor \
    --assume-role-policy-document file://trust-policy.json \
    --permissions-boundary arn:aws:iam::123456789012:policy/DeveloperBoundary
```

### Step 4: Prevent Privilege Escalation

Boundary must include deny statements to prevent developers from:
- Removing boundary from their own roles
- Modifying boundary policy itself
- Creating roles without boundary attached
- Accessing IAM services to escalate privileges

### Step 5: Deploy with Terraform

```hcl
resource "aws_iam_policy" "developer_boundary" {
  name   = "DeveloperBoundary"
  path   = "/"
  policy = file("${path.module}/policies/developer-boundary.json")
}
resource "aws_iam_role" "app_role" {
  name                 = "app-lambda-executor"
  assume_role_policy   = data.aws_iam_policy_document.lambda_trust.json
  permissions_boundary = aws_iam_policy.developer_boundary.arn
}
```

## Validation Checklist

- [ ] Permission boundary policy created and reviewed by security team
- [ ] Boundary includes deny statements preventing self-modification
- [ ] Developer delegation policy requires boundary on all new roles
- [ ] Role naming convention enforced (e.g., `app-*` prefix)
- [ ] Developers tested creating roles with and without boundary (should fail without)
- [ ] Privilege escalation paths tested and blocked
- [ ] CloudTrail logging enabled for IAM API calls
- [ ] Boundary policy versioned in source control
- [ ] Automated tests validate boundary effectiveness
- [ ] Documentation provided to development teams

## References

- [AWS IAM Permission Boundaries Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [When and Where to Use Permission Boundaries - AWS Security Blog](https://aws.amazon.com/blogs/security/when-and-where-to-use-iam-permissions-boundaries/)
- [AWS Example Permission Boundary - GitHub](https://github.com/aws-samples/example-permissions-boundary)
- [AWS Prescriptive Guidance - Creating Permission Boundaries](https://docs.aws.amazon.com/prescriptive-guidance/latest/transitioning-to-multiple-aws-accounts/creating-a-permissions-boundary.html)

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-aws-iam-permission-boundaries
