---
name: securing-aws-lambda-execution-roles
description: Hardens AWS Lambda execution roles by writing least-privilege IAM policies, applying permission boundaries, restricting resource-based policies, validating permissions with IAM Access Analyzer, and enforcing role scoping through SCPs.
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
upstream: securing-aws-lambda-execution-roles@54a7988 Apache-2.0, modified by wesh
---
Not for: securing Lambda function invocation (use resource-based policies and API Gateway authorizers), for Lambda code security (use SAST tools), or for Lambda network security (use VPC configuration and security groups).

## Prerequisites

- IAM permissions for policy creation, role modification, and Access Analyzer operations
- AWS IAM Access Analyzer enabled in account
- CloudTrail data events enabled for Lambda to capture actual API usage
- Existing Lambda functions to audit and scope permissions for
- Understanding of each function's required AWS service interactions

## Workflow

### Step 1: Audit Current Lambda Execution Role Permissions

Enumerate all Lambda functions and their associated IAM roles to identify over-privileged functions.

```bash
# List all Lambda functions with their execution roles
aws lambda list-functions \
  --query 'Functions[*].[FunctionName,Role]' --output table
# For each function, analyze attached policies
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
  role_arn=$(aws lambda get-function-configuration --function-name "$func" --query 'Role' --output text)
  role_name=$(echo "$role_arn" | awk -F'/' '{print $NF}')
  echo "=== $func -> $role_name ==="
  # Check for AWS managed policies (often too broad)
  aws iam list-attached-role-policies --role-name "$role_name" \
    --query 'AttachedPolicies[*].[PolicyName,PolicyArn]' --output table
  # Check inline policies
  for policy in $(aws iam list-role-policies --role-name "$role_name" --query 'PolicyNames' --output text); do
    echo "  Inline: $policy"
    aws iam get-role-policy --role-name "$role_name" --policy-name "$policy" \
      --query 'PolicyDocument' --output json
  done
done
```

### Step 2: Analyze Actual API Usage with CloudTrail

Use CloudTrail and IAM Access Analyzer to determine which API actions function uses.

```bash
# Query CloudTrail for actual API calls made by a Lambda execution role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=LAMBDA_ROLE_NAME \
  --start-time 2026-01-23T00:00:00Z \
  --end-time 2026-02-23T00:00:00Z \
  --query 'Events[*].[EventTime,EventName,EventSource]' \
  --output table | sort -k2 | uniq -f1
# Use IAM Access Analyzer policy generation (based on CloudTrail activity)
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{
    "principalArn": "arn:aws:iam::ACCOUNT:role/lambda-execution-role",
    "cloudTrailDetails": {
      "trailArn": "arn:aws:cloudtrail:us-east-1:ACCOUNT:trail/management-trail",
      "startTime": "2026-01-23T00:00:00Z",
      "endTime": "2026-02-23T00:00:00Z"
    }
  }'
# Check the generated policy
aws accessanalyzer get-generated-policy \
  --job-id JOB_ID \
  --query 'generatedPolicyResult.generatedPolicies[*].policy'
```

### Step 3: Create Least-Privilege Execution Policies

Build scoped IAM policies that grant only specific actions and resources each function needs.

```bash
# Example: Scoped policy for a function that reads from S3 and writes to DynamoDB
cat > lambda-scoped-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadInputBucket",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::input-data-bucket",
        "arn:aws:s3:::input-data-bucket/*"
      ]
    },
    {
      "Sid": "WriteDynamoDB",
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:BatchWriteItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:ACCOUNT:table/results-table"
    },
    {
      "Sid": "CloudWatchLogs",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:ACCOUNT:log-group:/aws/lambda/my-function:*"
    }
  ]
}
EOF
# Create the policy
aws iam create-policy \
  --policy-name lambda-my-function-policy \
  --policy-document file://lambda-scoped-policy.json
# Create execution role with scoped trust policy
cat > lambda-trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "aws:SourceAccount": "ACCOUNT_ID"
      }
    }
  }]
}
EOF
aws iam create-role \
  --role-name lambda-my-function-role \
  --assume-role-policy-document file://lambda-trust-policy.json
aws iam attach-role-policy \
  --role-name lambda-my-function-role \
  --policy-arn arn:aws:iam::ACCOUNT:policy/lambda-my-function-policy
```

### Step 4: Apply Permission Boundaries

Implement permission boundaries to set maximum permissions for Lambda execution roles.

```bash
# Create a permission boundary that caps Lambda role capabilities
cat > lambda-permission-boundary.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowedServices",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject", "s3:PutObject", "s3:ListBucket",
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", "dynamodb:UpdateItem",
        "sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
        "sns:Publish",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt", "kms:GenerateDataKey",
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents",
        "xray:PutTraceSegments", "xray:PutTelemetryRecords"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPrivilegeEscalation",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser", "iam:CreateRole", "iam:CreatePolicy",
        "iam:AttachRolePolicy", "iam:AttachUserPolicy",
        "iam:PutRolePolicy", "iam:PutUserPolicy",
        "iam:CreateAccessKey", "iam:PassRole",
        "lambda:CreateFunction", "lambda:UpdateFunctionConfiguration",
        "sts:AssumeRole"
      ],
      "Resource": "*"
    }
  ]
}
EOF
# Create and apply the boundary
aws iam create-policy \
  --policy-name lambda-permission-boundary \
  --policy-document file://lambda-permission-boundary.json
aws iam put-role-permissions-boundary \
  --role-name lambda-my-function-role \
  --permissions-boundary arn:aws:iam::ACCOUNT:policy/lambda-permission-boundary
```

### Step 5: Validate Policies with IAM Access Analyzer

Use Access Analyzer to validate policies for security best practices.

```bash
# Validate the scoped policy
aws accessanalyzer validate-policy \
  --policy-document file://lambda-scoped-policy.json \
  --policy-type IDENTITY_POLICY \
  --query 'findings[*].[findingType,issueCode,learnMoreLink]' --output table
# Check for unused access
aws accessanalyzer check-no-new-access \
  --new-policy-document file://lambda-scoped-policy.json \
  --existing-policy-document file://old-broad-policy.json \
  --policy-type IDENTITY_POLICY
# Verify the permission boundary effectiveness
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::ACCOUNT:role/lambda-my-function-role \
  --action-names iam:CreateUser iam:PassRole s3:GetObject dynamodb:PutItem \
  --query 'EvaluationResults[*].[EvalActionName,EvalDecision]' --output table
```

### Step 6: Enforce Role Standards with SCPs

Apply Service Control Policies to prevent Lambda functions from using overly broad roles.

```bash
# SCP to deny Lambda functions using AdministratorAccess
cat > scp-deny-lambda-admin.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyLambdaAdminRole",
    "Effect": "Deny",
    "Action": "lambda:CreateFunction",
    "Resource": "*",
    "Condition": {
      "ForAnyValue:StringLike": {
        "lambda:FunctionArn": "*"
      },
      "ArnLike": {
        "iam:PassedToService": "lambda.amazonaws.com"
      }
    }
  },
  {
    "Sid": "RequirePermissionBoundary",
    "Effect": "Deny",
    "Action": [
      "iam:CreateRole",
      "iam:AttachRolePolicy",
      "iam:PutRolePolicy"
    ],
    "Resource": "arn:aws:iam::*:role/lambda-*",
    "Condition": {
      "StringNotEquals": {
        "iam:PermissionsBoundary": "arn:aws:iam::*:policy/lambda-permission-boundary"
      }
    }
  }]
}
EOF
aws organizations create-policy \
  --name "lambda-role-guardrails" \
  --type SERVICE_CONTROL_POLICY \
  --content file://scp-deny-lambda-admin.json
```

## Key Concepts

| Term | Definition |
|------|------------|
| Execution Role | IAM role assumed by Lambda during function execution that defines all AWS API actions function can perform |
| Least Privilege | Security principle of granting only minimum permissions required for function to perform its intended operations |
| Permission Boundary | IAM policy that sets maximum permissions execution role can have, even if identity policies grant broader access |
| IAM Access Analyzer | AWS service that generates least-privilege policies based on actual CloudTrail usage and validates policies for security issues |
| Resource-Scoped Policy | IAM policy that specifies exact resource ARNs rather than wildcards, limiting access to only specific resources needed |
| Confused Deputy Prevention | Adding `aws:SourceAccount` or `aws:SourceArn` conditions to trust policies to prevent cross-account role assumption attacks |

## Tools & Systems

- **IAM Access Analyzer**: Generates least-privilege policies from CloudTrail data and validates policy security
- **IAM Policy Simulator**: Tests effective permissions for role against specific API actions before deployment
- **CloudTrail**: Audit log of all API calls used to determine actual function permission usage
- **Prowler**: Security tool with Lambda-specific checks for role permissions and configuration
- **Checkov**: Infrastructure-as-code scanner that validates Lambda IAM policies in CloudFormation/Terraform

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/securing-aws-lambda-execution-roles
