---
name: detecting-aws-iam-privilege-escalation
description: Detect AWS IAM privilege escalation paths using boto3 and Cloudsplaining policy analysis to identify overly permissive policies, dangerous permission combinations, and least-privilege violations
subdomain: cloud-security
facing: config
mitre_attack:
- T1098.001
- T1098.003
- T1078.004
- T1548.005
- T1484
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: detecting-aws-iam-privilege-escalation@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.8+ with boto3 library
- AWS credentials with IAM read-only access (iam:GetAccountAuthorizationDetails)
- Optional: cloudsplaining Python package for HTML report generation

## Steps

1. **Download IAM Authorization Details** — Call iam:GetAccountAuthorizationDetails to retrieve all users, groups, roles, and policies
2. **Analyze Policies for Privilege Escalation** — Check each policy for known escalation permission combinations
3. **Identify Wildcard Resource Policies** — Flag policies using Resource: "*" with dangerous actions
4. **Map Principal-to-Policy Relationships** — Build graph of which principals can access which escalation paths
5. **Score and Prioritize Findings** — Rank findings by severity based on escalation vector type
6. **Generate Report** — Produce structured JSON report with remediation guidance

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-aws-iam-privilege-escalation
