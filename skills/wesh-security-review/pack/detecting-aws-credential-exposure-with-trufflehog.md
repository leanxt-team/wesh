---
name: detecting-aws-credential-exposure-with-trufflehog
description: Scan source code repositories, CI/CD pipelines, and configuration files for exposed AWS credentials using TruffleHog, git-secrets, and AWS-native detection.
subdomain: cloud-security
facing: config
mitre_attack:
- T1552.001
- T1552
- T1078.004
- T1589.001
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: detecting-aws-credential-exposure-with-trufflehog@54a7988 Apache-2.0, modified by wesh
---
Not for: real-time credential monitoring (use AWS GuardDuty or Amazon Macie), for managing secrets (use AWS Secrets Manager or HashiCorp Vault), or for detecting non-credential sensitive data like PII (use Amazon Macie or DLP tools).

## Prerequisites

- TruffleHog v3 installed (`brew install trufflehog` or `pip install trufflehog`)
- git-secrets installed for pre-commit hook integration (`brew install git-secrets`)
- Access to source code repositories (GitHub, GitLab, Bitbucket, or local git repos)
- AWS CLI configured with permissions to check key status (`iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`)
- GitHub or GitLab API token for scanning organization-wide repositories

## Workflow

### Step 1: Install and Configure TruffleHog

Install TruffleHog v3 and verify it can detect AWS credential patterns.

```bash
# Install TruffleHog v3
pip install trufflehog
# Or install from binary release
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# Verify installation
trufflehog --version
# Test with a known test repository
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified
```

### Step 2: Scan Git Repositories for Exposed Credentials

Scan entire git history including all branches and commits for AWS access keys, secret keys, and session tokens.

```bash
# Scan a local git repository (full history)
trufflehog git file:///path/to/repo --only-verified --json > trufflehog-results.json
# Scan a GitHub organization's repositories
trufflehog github --org=your-organization --token=$GITHUB_TOKEN --only-verified
# Scan a specific GitHub repository with all branches
trufflehog git https://github.com/org/repo.git --only-verified --branch=main
# Scan a GitLab group
trufflehog gitlab --group=your-group --token=$GITLAB_TOKEN --only-verified
# Scan filesystem paths for credentials in config files
trufflehog filesystem /path/to/project --only-verified
```

### Step 3: Analyze and Validate Detected Credentials

Parse TruffleHog results to identify verified (still-active) credentials versus rotated or test keys.

```bash
# Parse TruffleHog JSON output for AWS findings
cat trufflehog-results.json | python3 -c "
import json, sys
for line in sys.stdin:
    finding = json.loads(line)
    if 'AWS' in finding.get('DetectorName', ''):
        print(f\"Detector: {finding['DetectorName']}\")
        print(f\"Verified: {finding.get('Verified', False)}\")
        print(f\"Source: {finding.get('SourceMetadata', {})}\")
        print(f\"Commit: {finding.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('commit', 'N/A')}\")
        print(f\"File: {finding.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'N/A')}\")
        print('---')
"
# Check if a detected access key is still active
aws iam get-access-key-last-used --access-key-id AKIAIOSFODNN7EXAMPLE
# List all access keys for a user to find active keys
aws iam list-access-keys --user-name target-user \
  --query 'AccessKeyMetadata[*].[AccessKeyId,Status,CreateDate]' --output table
```

### Step 4: Set Up Pre-Commit Hooks with git-secrets

Prevent credentials from being committed in first place using git-secrets as pre-commit hook.

```bash
# Install git-secrets
git secrets --install  # In each repository
# Register AWS credential patterns
git secrets --register-aws
# Add custom patterns for internal credential formats
git secrets --add 'AKIA[0-9A-Z]{16}'
git secrets --add 'aws_secret_access_key\s*=\s*.{40}'
git secrets --add 'aws_session_token\s*=\s*.+'
# Scan entire repository history
git secrets --scan-history
# Add to global git template for all new repos
git secrets --install ~/.git-templates/git-secrets
git config --global init.templateDir ~/.git-templates/git-secrets
```

### Step 5: Integrate TruffleHog into CI/CD Pipeline

Add TruffleHog scanning as CI/CD gate to block deployments containing exposed credentials.

```yaml
# GitHub Actions workflow (.github/workflows/secrets-scan.yml)
name: Secrets Scan
on: [push, pull_request]
jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified --results=verified
```

```yaml
# GitLab CI (.gitlab-ci.yml)
secrets_scan:
  stage: test
  image: trufflesecurity/trufflehog:latest
  script:
    - trufflehog git file://$CI_PROJECT_DIR --since-commit $CI_COMMIT_BEFORE_SHA --only-verified --fail
  allow_failure: false
```

### Step 6: Respond to Detected Credential Exposure

Execute incident response procedures when verified credentials are found exposed.

```bash
# IMMEDIATE: Deactivate the exposed access key
aws iam update-access-key \
  --user-name compromised-user \
  --access-key-id AKIAEXPOSEDKEY123456 \
  --status Inactive
# Generate new credentials
aws iam create-access-key --user-name compromised-user
# Review CloudTrail for unauthorized usage of the exposed key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAEXPOSEDKEY123456 \
  --start-time 2026-01-01T00:00:00Z \
  --query 'Events[*].[EventTime,EventName,EventSource,SourceIPAddress]' \
  --output table
# Delete the exposed key after rotation is confirmed
aws iam delete-access-key \
  --user-name compromised-user \
  --access-key-id AKIAEXPOSEDKEY123456
# Remove the credential from git history using BFG Repo Cleaner
java -jar bfg.jar --replace-text credentials.txt repo.git
```

## Key Concepts

| Term | Definition |
|------|------------|
| TruffleHog | Open-source secrets detection tool that scans git history, filesystems, and cloud services for exposed credentials using regex patterns and verification APIs |
| Verified Secret | credential that TruffleHog has confirmed is still active by making API call to target service (e.g., AWS STS GetCallerIdentity) |
| git-secrets | AWS Labs pre-commit hook tool that prevents committing strings matching AWS credential patterns to git repositories |
| Access Key Rotation | practice of regularly replacing AWS access key pairs to limit window of exposure if key is compromised |
| BFG Repo Cleaner | Tool for removing sensitive data from git history without rewriting entire repository, faster than git filter-branch |
| GitHub Secret Scanning | GitHub-native feature that scans public repositories for known credential patterns and notifies credential provider |

## Tools & Systems

- **TruffleHog v3**: Primary scanning engine supporting git, filesystem, S3, and CI/CD integration with verified credential detection
- **git-secrets**: AWS Labs pre-commit hook for preventing credential commits at developer workstation level
- **BFG Repo Cleaner**: Fast tool for removing credentials from git history after exposure is detected
- **AWS GuardDuty**: Threat detection service that alerts on anomalous usage of AWS credentials from unexpected locations
- **GitHub Advanced Security**: Platform-native secret scanning for GitHub repositories with push protection

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-aws-credential-exposure-with-trufflehog
