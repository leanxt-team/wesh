---
name: performing-supply-chain-attack-simulation
description: Simulates and detects software supply chain attacks: typosquatting detection via Levenshtein distance against popular PyPI package names, dependency confusion testing against private registries, SHA-256 package hash verification, and known-CVE scanning with pip-audit.
subdomain: application-security
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1195
- T1554
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
upstream: performing-supply-chain-attack-simulation@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Prerequisites

- Python 3.9+ with `pip-audit`, `Levenshtein`, `requests`
- Access to PyPI JSON API (https://pypi.org/pypi/{package}/json)
- Network access for package metadata retrieval

## Key Detection Areas

1. **Typosquatting** — compare package names against top PyPI packages using edit distance thresholds
2. **Dependency confusion** — check if internal package names exist on public PyPI with higher version numbers
3. **Hash verification** — download packages and verify SHA-256 digests match published hashes
4. **Vulnerability scanning** — audit installed packages against OSV and PyPA advisory databases
5. **Metadata anomalies** — flag packages with suspicious author emails, missing homepages, or very recent first upload dates

## Output

JSON report with risk scores per package, detected attack vectors, hash verification results, and CVE findings.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-supply-chain-attack-simulation
