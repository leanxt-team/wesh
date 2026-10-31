---
name: detecting-malicious-npm-packages
description: Triage npm packages and lockfiles for install-script malware, credential exfiltration, and worming behavior using GuardDog, manual tarball inspection, and dynamic detonation with network/filesystem monitoring.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195.002
nist_csf:
- DE.CM-09
upstream: detecting-malicious-npm-packages@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Isolated VM or disposable container with **no production credentials** and snapshot/rollback capability.
- GuardDog:
  ```bash
  pip install guarddog
  # or run via Docker without local install:
  docker pull ghcr.io/datadog/guarddog
  alias guarddog='docker run --rm ghcr.io/datadog/guarddog'
  ```
- Node.js + npm (use `--ignore-scripts` when downloading for analysis).
- `jq`, `tar`, and optionally OSV-Scanner for known-vulnerability/known-malicious cross-checks:
  ```bash
  go install github.com/google/osv-scanner/cmd/osv-scanner@v1
  ```
- For dynamic analysis: sandbox with egress logging (e.g., `tcpdump`, DNS sink, or network namespace).

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Core technique — trojanized npm package delivered through registry. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Malicious install scripts / module code execute attacker JavaScript. |
| T1552.001 | Unsecured Credentials: Credentials In Files | Packages steal `~/.npmrc`, `.env`, SSH keys, and cloud credential files. |
| T1041 | Exfiltration Over C2 Channel | Stolen secrets posted to attacker HTTP(S) endpoints. |
| T1027 | Obfuscated Files or Information | base64/eval/hex obfuscation hides payload from review. |

## Workflow

### 1. Download package without executing it
Fetch tarball with scripts disabled so nothing runs during acquisition.
```bash
mkdir triage && cd triage
# Resolve the tarball URL and download it (no install, no scripts)
npm pack express@4.18.2            # produces express-4.18.2.tgz
# or for an arbitrary version:
npm view some-pkg@1.2.3 dist.tarball
curl -sL "$(npm view some-pkg@1.2.3 dist.tarball)" -o some-pkg.tgz
tar -xzf some-pkg.tgz              # extracts into ./package
```

### 2. Scan single package with GuardDog
GuardDog applies metadata + source heuristics and prints which rules matched.
```bash
# Scan the latest published version from the registry
guarddog npm scan express
# Scan a specific version
guarddog npm scan some-pkg --version 1.2.3
# Scan the local tarball / extracted directory you downloaded above
guarddog npm scan ./some-pkg.tgz
guarddog npm scan ./package/
```

### 3. Verify entire dependency tree
`verify` scans every dependency declared in manifest — ideal for code review.
```bash
guarddog npm verify /path/to/repo/package.json
```

### 4. Focus on highest-signal heuristics
Filter to npm rules most indicative of malware to cut noise during triage.
```bash
guarddog npm scan some-pkg \
  --rules npm-install-script \
  --rules npm-serialize-environment \
  --rules npm-exec-base64 \
  --rules npm-silent-process-execution \
  --rules npm-obfuscation \
  --rules shady-links \
  --rules typosquatting
```

### 5. Emit machine-readable output for pipelines
JSON for tooling, SARIF for GitHub code scanning.
```bash
guarddog npm scan some-pkg --output-format=json   > guarddog.json
guarddog npm verify package.json --output-format=sarif > guarddog.sarif
```

### 6. Manually inspect lifecycle scripts and source
Lifecycle scripts are first thing to read; obfuscation and outbound URLs are red flags.
```bash
# Show all lifecycle hooks
jq '.scripts' package/package.json
# Hunt for exfiltration / execution primitives in the source
grep -rEn "child_process|exec\(|spawn|eval\(|Buffer\.from\(.*base64|process\.env|https?://" package/ \
  --include='*.js' --include='*.ts' | head -50
```

### 7. Cross-check lockfiles against known-malicious versions
During active campaign, compare pinned versions to advisory's bad-version list, and run OSV.
```bash
# Extract resolved name@version pairs from a v3 lockfile
jq -r '.packages | to_entries[] | select(.key|startswith("node_modules/")) | "\(.key|ltrimstr("node_modules/"))@\(.value.version)"' package-lock.json
# OSV-Scanner flags known-vulnerable AND known-malicious (MAL-) advisories
osv-scanner --lockfile=package-lock.json
```

### 8. Detonate safely with monitoring (only if static is inconclusive)
Run install inside disposable, network-monitored sandbox.
```bash
# In a throwaway container / VM with egress capture running (tcpdump -w capture.pcap):
npm install ./some-pkg.tgz            # scripts WILL run — sandbox only
# Baseline-diff the filesystem afterwards for writes outside node_modules,
# and inspect capture.pcap for unexpected DNS / HTTP beacons.
```

### 9. Extract and operationalize IOCs
Pull URLs, IPs, and hashes for blocking and intel sharing.
```bash
grep -rhoE "https?://[a-zA-Z0-9./?=_%:-]+" package/ | sort -u > urls.txt
sha256sum some-pkg.tgz package/*.js > hashes.txt
```

### 10. Run bundled triage helper
`agent.py` orchestrates GuardDog, lifecycle-script inspection, and IOC extraction into one report.
```bash
python scripts/agent.py --package some-pkg --version 1.2.3 --output verdict.json
# or against a local tarball:
python scripts/agent.py --tarball ./some-pkg.tgz --output verdict.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| GuardDog | Heuristic npm/PyPI/Go malware scanner | https://github.com/DataDog/guarddog |
| OSV-Scanner | Known-vulnerable & known-malicious (MAL-) advisory matching | https://github.com/google/osv-scanner |
| OSV malicious DB | Open-source malicious package advisories | https://github.com/ossf/malicious-packages |
| npm lifecycle docs | preinstall/install/postinstall semantics | https://docs.npmjs.com/cli/v10/using-npm/scripts |
| Datadog Security Labs | npm campaign writeups & rules | https://securitylabs.datadoghq.com/ |
| Semgrep | Rule engine GuardDog uses for source heuristics | https://semgrep.dev/ |

## Validation Criteria

- [ ] Package acquired with scripts disabled in isolated environment.
- [ ] GuardDog `scan` run on target version with results captured.
- [ ] Full dependency tree run through GuardDog `verify` where applicable.
- [ ] Lifecycle scripts (`preinstall`/`install`/`postinstall`) read and assessed.
- [ ] Lockfile versions cross-checked against OSV / known-bad lists.
- [ ] Dynamic detonation performed in sandbox if static analysis was inconclusive.
- [ ] IOCs (URLs, IPs, hashes) extracted and recorded.
- [ ] Documented verdict (benign / suspicious / malicious) with supporting evidence.
- [ ] Malicious findings reported to registry and shared as threat intel.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-malicious-npm-packages
