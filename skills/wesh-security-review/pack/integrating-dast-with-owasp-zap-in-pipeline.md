---
name: integrating-dast-with-owasp-zap-in-pipeline
description: Integrates OWASP ZAP (Zed Attack Proxy) into GitHub Actions and GitLab CI pipelines, covering baseline, full, and API scan configuration against running applications, ZAP finding interpretation, scan policy tuning, and DAST quality gates.
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
upstream: integrating-dast-with-owasp-zap-in-pipeline@54a7988 Apache-2.0, modified by wesh
---
Not for: scanning source code (use SAST), for scanning dependencies (use SCA), or for infrastructure configuration scanning (use IaC scanning tools).

## Prerequisites

- OWASP ZAP Docker image or installed locally (zaproxy/zap-stable or zaproxy/action-*)
- Running target application accessible from CI/CD runner (staging URL or Docker service)
- ZAP scan rules configuration (optional, for tuning)
- OpenAPI/Swagger specification for API scanning (optional)

## Workflow

### Step 1: Configure ZAP Baseline Scan in GitHub Actions

```yaml
# .github/workflows/dast-scan.yml
name: DAST Security Scan
on:
  deployment_status:
  workflow_dispatch:
    inputs:
      target_url:
        description: 'Target URL to scan'
        required: true
jobs:
  zap-baseline:
    name: ZAP Baseline Scan
    runs-on: ubuntu-latest
    services:
      webapp:
        image: ${{ github.repository }}:${{ github.sha }}
        ports:
          - 8080:8080
        options: --health-cmd="curl -f http://localhost:8080/health" --health-interval=10s --health-timeout=5s --health-retries=5
    steps:
      - uses: actions/checkout@v4
      - name: ZAP Baseline Scan
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'http://webapp:8080'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j'
          allow_issue_writing: false
      - name: Upload ZAP Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-baseline-report
          path: report_html.html
```

### Step 2: Configure ZAP Full Scan for Comprehensive Testing

```yaml
  zap-full-scan:
    name: ZAP Full Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ZAP Full Scan
        uses: zaproxy/action-full-scan@v0.12.0
        with:
          target: ${{ github.event.inputs.target_url || 'https://staging.example.com' }}
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a -j -T 60'
      - name: Upload Reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: zap-full-report
          path: |
            report_html.html
            report_json.json
```

### Step 3: Configure API Scan with OpenAPI Specification

```yaml
  zap-api-scan:
    name: ZAP API Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ZAP API Scan
        uses: zaproxy/action-api-scan@v0.12.0
        with:
          target: 'https://staging.example.com/api/openapi.json'
          format: openapi
          rules_file_name: '.zap/api-rules.tsv'
          cmd_options: '-a -j'
```

### Step 4: Configure ZAP Scan Rules

```tsv
# .zap/rules.tsv
# Rule ID	Action (IGNORE/WARN/FAIL)	Description
10003	IGNORE	# Vulnerable JS Library (handled by SCA)
10015	WARN	# Incomplete or No Cache-control Header
10021	FAIL	# X-Content-Type-Options Missing
10035	FAIL	# Strict-Transport-Security Missing
10038	FAIL	# Content Security Policy Missing
10098	IGNORE	# Cross-Domain Misconfiguration (CDN)
40012	FAIL	# Cross Site Scripting (Reflected)
40014	FAIL	# Cross Site Scripting (Persistent)
40018	FAIL	# SQL Injection
40019	FAIL	# SQL Injection (MySQL)
40032	FAIL	# .htaccess Information Leak
90033	FAIL	# Loosely Scoped Cookie
```

### Step 5: Run ZAP with Docker Compose for Local Testing

```yaml
# docker-compose.zap.yml
version: '3.8'
services:
  webapp:
    build: .
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      retries: 5
  zap:
    image: zaproxy/zap-stable:latest
    depends_on:
      webapp:
        condition: service_healthy
    command: >
      zap-baseline.py
        -t http://webapp:8080
        -r /zap/wrk/report.html
        -J /zap/wrk/report.json
        -c /zap/wrk/rules.tsv
        -I
    volumes:
      - ./zap-reports:/zap/wrk
      - ./.zap/rules.tsv:/zap/wrk/rules.tsv
```

## Key Concepts

| Term | Definition |
|------|------------|
| DAST | Dynamic Application Security Testing — tests running applications by sending requests and analyzing responses |
| Baseline Scan | Quick passive scan that spiders application without active attacks, suitable for CI/CD |
| Full Scan | Active scan including attack payloads for XSS, SQLi, and other injection vulnerabilities |
| API Scan | Targeted scan using OpenAPI/Swagger specs to test all documented API endpoints |
| Spider | ZAP's crawler that discovers application pages and endpoints by following links |
| Active Scan | Phase where ZAP sends attack payloads to discovered endpoints to find exploitable vulnerabilities |
| Passive Scan | Analysis of HTTP responses for security headers, cookies, and information disclosure without sending attacks |
| Scan Policy | Configuration defining which attack types to enable and their intensity levels |

## Tools & Systems

- **OWASP ZAP**: Open-source web application security scanner for DAST testing
- **zaproxy/action-baseline**: GitHub Action for ZAP passive baseline scanning
- **zaproxy/action-full-scan**: GitHub Action for ZAP active full scanning
- **zaproxy/action-api-scan**: GitHub Action for API-focused scanning with OpenAPI support
- **Nuclei**: Alternative vulnerability scanner with template-based detection for CI/CD integration

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/integrating-dast-with-owasp-zap-in-pipeline
