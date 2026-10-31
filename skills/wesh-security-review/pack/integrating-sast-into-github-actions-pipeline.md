---
name: integrating-sast-into-github-actions-pipeline
description: Integrates CodeQL and Semgrep SAST scanning into GitHub Actions, covering scans on pull requests/pushes, rule tuning to cut false positives, SARIF upload to GitHub Advanced Security, and merge-blocking quality gates for high-severity findings.
subdomain: devsecops
facing: config
mitre_attack:
- T1195
- T1554
- T1059.004
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
upstream: integrating-sast-into-github-actions-pipeline@54a7988 Apache-2.0, modified by wesh
---
Not for: runtime vulnerability detection (use DAST instead), for scanning third-party dependencies (use SCA tools like Snyk), or for infrastructure-as-code scanning (use Checkov or tfsec).

## Prerequisites

- GitHub repository with GitHub Actions enabled
- GitHub Advanced Security license (required for CodeQL on private repos; free for public repos)
- Semgrep account for managed rules and Semgrep App dashboard (free tier available)
- Repository code in supported language: Python, JavaScript/TypeScript, Java, C/C++, C#, Go, Ruby, Swift, Kotlin

## Workflow

### Step 1: Configure CodeQL Analysis Workflow

Create CodeQL workflow that runs on pull requests and on weekly schedule to catch vulnerabilities in existing code.

```yaml
# .github/workflows/codeql-analysis.yml
name: "CodeQL Analysis"
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '30 2 * * 1'  # Weekly Monday 2:30 AM
jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: ['javascript', 'python']
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
          queries: security-extended,security-and-quality
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
        with:
          category: "/language:${{ matrix.language }}"
```

### Step 2: Add Semgrep Scanning for Custom Rules

Semgrep complements CodeQL with faster scans and support for custom pattern-based rules. Configure it to upload SARIF results to same GitHub Security tab.

```yaml
# .github/workflows/semgrep.yml
name: "Semgrep SAST Scan"
on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]
jobs:
  semgrep:
    name: Semgrep Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    container:
      image: semgrep/semgrep:latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Run Semgrep
        run: |
          semgrep ci \
            --config auto \
            --config p/owasp-top-ten \
            --config p/cwe-top-25 \
            --sarif --output semgrep-results.sarif \
            --severity ERROR \
            --error
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep-results.sarif
          category: semgrep
```

### Step 3: Create Custom Semgrep Rules for Organization Patterns

Write organization-specific rules to catch patterns unique to your codebase, e.g. deprecated internal APIs or insecure configuration patterns.

```yaml
# .semgrep/custom-rules.yml
rules:
  - id: hardcoded-database-url
    patterns:
      - pattern: |
          $DB_URL = "...$PROTO://...:...$PASS@..."
    message: |
      Hardcoded database connection string with credentials detected.
      Use environment variables or a secrets manager instead.
    languages: [python, javascript, typescript]
    severity: ERROR
    metadata:
      cwe: "CWE-798: Use of Hard-coded Credentials"
      owasp: "A07:2021 - Identification and Authentication Failures"
  - id: unsafe-deserialization
    patterns:
      - pattern-either:
          - pattern: pickle.loads(...)
          - pattern: yaml.load(..., Loader=yaml.Loader)
          - pattern: yaml.load(..., Loader=yaml.FullLoader)
    message: |
      Unsafe deserialization detected. Use safe alternatives to prevent
      remote code execution vulnerabilities.
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-502: Deserialization of Untrusted Data"
  - id: missing-csrf-protection
    patterns:
      - pattern: |
          @app.route("...", methods=["POST"])
          def $FUNC(...):
              ...
      - pattern-not-inside: |
          @csrf.exempt
          ...
    message: "POST endpoint may lack CSRF protection."
    languages: [python]
    severity: WARNING
```

### Step 4: Establish Quality Gates with Branch Protection

Configure branch protection rules that require SAST checks to pass before merging, preventing vulnerable code from reaching production branches.

```bash
# Use GitHub CLI to set branch protection requiring SAST checks
gh api repos/{owner}/{repo}/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["Analyze (javascript)","Analyze (python)","Semgrep Scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}'
```

### Step 5: Tune and Suppress False Positives

Manage false positives through CodeQL query filters and Semgrep nosemgrep annotations to maintain developer trust in scan results.

```yaml
# codeql-config.yml - Custom CodeQL configuration
name: "Custom CodeQL Config"
queries:
  - uses: security-extended
  - uses: security-and-quality
  - excludes:
      id: js/unused-local-variable
paths-ignore:
  - '**/test/**'
  - '**/tests/**'
  - '**/vendor/**'
  - '**/node_modules/**'
  - '**/*.test.js'
  - '**/*.spec.py'
```

```python
# Example: Suppressing a known false positive in Semgrep
import subprocess
def run_safe_command(cmd_list):
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use
    result = subprocess.run(cmd_list, capture_output=True, text=True, shell=False)
    return result.stdout
```

### Step 6: Aggregate and Report Findings

Use GitHub Security Overview dashboard and configure notifications for security alerts across repositories.

```bash
# Query SARIF results via GitHub API for reporting
gh api repos/{owner}/{repo}/code-scanning/alerts \
  --jq '.[] | select(.state=="open") | {rule: .rule.id, severity: .rule.security_severity_level, file: .most_recent_instance.location.path, line: .most_recent_instance.location.start_line}'
# Count open alerts by severity
gh api repos/{owner}/{repo}/code-scanning/alerts \
  --jq '[.[] | select(.state=="open")] | group_by(.rule.security_severity_level) | map({severity: .[0].rule.security_severity_level, count: length})'
```

## Key Concepts

| Term | Definition |
|------|------------|
| SAST | Static Application Security Testing — analyzes source code without executing it to find security vulnerabilities |
| SARIF | Static Analysis Results Interchange Format — standardized JSON format for expressing results from static analysis tools |
| CodeQL | GitHub's semantic code analysis engine that treats code as data and queries it for vulnerability patterns |
| Semgrep | Lightweight static analysis tool using pattern matching to find bugs and security issues across many languages |
| Security Extended | CodeQL query suite that includes additional security queries beyond default set for deeper analysis |
| Quality Gate | Automated checkpoint that blocks code from progressing through pipeline unless security criteria are met |
| False Positive | scan finding that incorrectly identifies secure code as vulnerable, requiring suppression or tuning |

## Tools & Systems

- **CodeQL**: GitHub's semantic code analysis engine with deep dataflow and taint tracking analysis
- **Semgrep**: Fast, lightweight pattern-matching SAST tool with 3000+ community rules and custom rule support
- **GitHub Advanced Security**: Platform providing code scanning, secret scanning, and dependency review in GitHub
- **SARIF Viewer**: VS Code extension for reviewing SARIF results locally during development
- **GitHub Security Overview**: Organization-level dashboard aggregating security alerts across all repositories

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/integrating-sast-into-github-actions-pipeline
