---
name: performing-gcp-penetration-testing-with-gcpbucketbrute
description: Performs authorized GCP security testing using GCPBucketBrute to enumerate publicly accessible storage buckets, combined with gcloud CLI IAM enumeration to find privilege escalation paths and audit service account permissions.
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
upstream: performing-gcp-penetration-testing-with-gcpbucketbrute@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Python 3.8+ with google-cloud-storage library
- GCPBucketBrute installed from RhinoSecurityLabs GitHub
- gcloud CLI authenticated with test credentials
- Authorized penetration testing scope for target GCP project
- google-api-python-client and google-auth libraries

## Steps

1. **Enumerate Storage Buckets** — Use GCPBucketBrute with keyword permutations to discover accessible GCP storage buckets
2. **Test Bucket Permissions** — Call TestIamPermissions API on each discovered bucket to determine read/write/admin access levels
3. **Audit IAM Bindings** — Enumerate project-level IAM policies to identify overly permissive role bindings
4. **Check Service Account Keys** — Identify service accounts with user-managed keys and test for privilege escalation via impersonation
5. **Test Privilege Escalation Paths** — Check for iam.serviceAccounts.actAs, setIamPolicy, and other privilege escalation vectors
6. **Generate Findings Report** — Produce structured security assessment with risk severity ratings

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-gcp-penetration-testing-with-gcpbucketbrute
