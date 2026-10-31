---
name: auditing-gcp-iam-permissions
description: Auditing Google Cloud Platform IAM permissions to identify overly permissive bindings, primitive role usage, service account key proliferation, and cross-project access risks using gcloud CLI, Policy Analyzer, and IAM Recommender.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1098.003
- T1528
- T1548.005
- T1580
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: auditing-gcp-iam-permissions@54a7988 Apache-2.0, modified by wesh
---
Not for: VPC firewall rule auditing (use network security tools), for GKE RBAC auditing (use Kubernetes-specific RBAC tools), or for real-time threat detection on IAM actions (use SCC Event Threat Detection).

## Prerequisites

- GCP organization or project with `roles/iam.securityReviewer` and `roles/cloudAsset.viewer`
- gcloud CLI authenticated with appropriate permissions
- Cloud Asset API enabled (`gcloud services enable cloudasset.googleapis.com`)
- IAM Recommender API enabled (`gcloud services enable recommender.googleapis.com`)
- Policy Analyzer API enabled (`gcloud services enable policyanalyzer.googleapis.com`)

## Workflow

### Step 1: Enumerate IAM Bindings Across Organization

List all IAM bindings at organization, folder, and project levels to understand full access landscape.

```bash
# Organization-level IAM bindings
gcloud organizations get-iam-policy ORG_ID \
  --format=json > org-iam-policy.json
# Search all IAM policies across the organization
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --format="table(resource, policy.bindings.role, policy.bindings.members)" \
  --limit=500
# Find all users and service accounts with Owner role
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner" \
  --format="table(resource, policy.bindings.members)"
# Find all bindings using primitive roles (Owner, Editor, Viewer)
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:roles/owner OR policy:roles/editor" \
  --format=json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for result in data:
    resource = result.get('resource', '')
    for binding in result.get('policy', {}).get('bindings', []):
        role = binding.get('role', '')
        if role in ['roles/owner', 'roles/editor']:
            for member in binding.get('members', []):
                print(f'{resource} | {role} | {member}')
"
```

### Step 2: Audit Service Accounts and Their Keys

Identify service accounts with excessive permissions, user-managed keys, and unused accounts.

```bash
# List all service accounts in a project
gcloud iam service-accounts list \
  --project=PROJECT_ID \
  --format="table(email, displayName, disabled)"
# Check for user-managed keys (should be minimized)
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  keys=$(gcloud iam service-accounts keys list \
    --iam-account="$sa" \
    --managed-by=user \
    --format="table(name.basename(),validAfterTime,validBeforeTime)")
  if [ -n "$keys" ]; then
    echo "=== $sa ==="
    echo "$keys"
  fi
done
# Find service accounts with admin roles across all projects
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy.bindings.members:serviceAccount AND (policy:roles/owner OR policy:roles/editor OR policy:admin)" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"
# Check service account IAM policies (who can impersonate)
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  echo "=== $sa ==="
  gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null
done
```

### Step 3: Use IAM Recommender to Identify Excess Permissions

Leverage GCP's IAM Recommender to find roles that grant more access than used.

```bash
# List IAM role recommendations for a project
gcloud recommender recommendations list \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format="table(name, description, priority, stateInfo.state)"
# Get detailed recommendation
gcloud recommender recommendations describe RECOMMENDATION_ID \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --format=json
# List insights about IAM usage
gcloud recommender insights list \
  --project=PROJECT_ID \
  --insight-type=google.iam.policy.Insight \
  --location=global \
  --format="table(name, description, severity, category)"
# Apply a recommendation (after review)
gcloud recommender recommendations mark-claimed RECOMMENDATION_ID \
  --project=PROJECT_ID \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --etag=ETAG
```

### Step 4: Analyze Effective Permissions with Policy Analyzer

Use Policy Analyzer to determine effective access for specific principals or resources.

```bash
# Check who has access to a specific resource
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --full-resource-name="//storage.googleapis.com/projects/_/buckets/sensitive-data-bucket" \
  --format="table(identityList.identities, accessControlLists.accesses.role)"
# Check what resources a specific user can access
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --identity="user:developer@company.com" \
  --format="table(accessControlLists.resources.fullResourceName, accessControlLists.accesses.role)"
# Check who can perform a specific action
gcloud asset analyze-iam-policy \
  --organization=ORG_ID \
  --full-resource-name="//cloudresourcemanager.googleapis.com/projects/PROJECT_ID" \
  --permissions="iam.serviceAccounts.actAs,iam.serviceAccountKeys.create" \
  --format="table(identityList.identities, accessControlLists.accesses.permission)"
# Find all principals with allUsers or allAuthenticatedUsers access
gcloud asset search-all-iam-policies \
  --scope=organizations/ORG_ID \
  --query="policy:allUsers OR policy:allAuthenticatedUsers" \
  --format="table(resource, policy.bindings.role, policy.bindings.members)"
```

### Step 5: Check for Domain-Wide Delegation and Impersonation Risks

Identify service accounts with domain-wide delegation and impersonation capabilities.

```bash
# Check for service accounts with domain-wide delegation
# (Requires Admin SDK access to list delegated accounts)
gcloud iam service-accounts list --project=PROJECT_ID --format=json | python3 -c "
import json, sys
accounts = json.load(sys.stdin)
for sa in accounts:
    email = sa.get('email', '')
    # Check if the SA has domain-wide delegation enabled
    # This requires Admin SDK API access
    print(f'SA: {email} - Check admin.google.com for delegation status')
"
# Find service accounts that other identities can impersonate
for sa in $(gcloud iam service-accounts list --project=PROJECT_ID --format="value(email)"); do
  policy=$(gcloud iam service-accounts get-iam-policy "$sa" --format=json 2>/dev/null)
  if echo "$policy" | python3 -c "
import json, sys
p = json.load(sys.stdin)
for b in p.get('bindings', []):
    if b['role'] in ['roles/iam.serviceAccountTokenCreator', 'roles/iam.serviceAccountUser']:
        print(f'  {b[\"role\"]}: {b[\"members\"]}')
" 2>/dev/null; then
    echo "=== Impersonation risk: $sa ==="
  fi
done
```

### Step 6: Generate Audit Report and Apply Remediation

Compile findings and implement recommended permission reductions.

```bash
# Remove primitive role and replace with predefined role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/editor"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/compute.viewer"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:developer@company.com" \
  --role="roles/storage.objectViewer"
# Delete unused service account keys
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SA_EMAIL
# Disable unused service accounts
gcloud iam service-accounts disable SA_EMAIL --project=PROJECT_ID
```

## Key Concepts

| Term | Definition |
|------|------------|
| Primitive Role | Legacy GCP roles (Owner, Editor, Viewer) that grant broad permissions across all services, not recommended for production |
| Predefined Role | GCP-managed role scoped to specific services and actions, providing more granular access than primitive roles |
| IAM Recommender | GCP ML-based service that analyzes actual permission usage and suggests role reductions to achieve least privilege |
| Policy Analyzer | Tool for analyzing effective IAM access across organization hierarchy, answering who-can-access-what queries |
| Service Account Key | User-managed credential for service account authentication, security risk as keys can be exported and do not auto-expire |
| Domain-Wide Delegation | Grants service account ability to impersonate any user in Google Workspace domain, significant privilege escalation risk |

## Tools & Systems

- **gcloud CLI**: Primary tool for querying and managing GCP IAM policies, service accounts, and role bindings
- **IAM Recommender**: ML-based recommendation engine for reducing excessive permissions based on actual usage
- **Policy Analyzer**: Organization-wide effective access analysis tool for understanding who can access what
- **Cloud Asset Inventory**: Cross-project search for IAM policies and resource metadata
- **ScoutSuite**: Multi-cloud auditing tool with GCP IAM-specific checks for role assignments and service accounts

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-gcp-iam-permissions
