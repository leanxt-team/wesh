---
name: detecting-typosquatting-packages
description: Flag misspelled, brandjacked, and typosquatted package names across npm, PyPI, and crates.io before installation, using edit-distance, keyboard-proximity, and known-target corpus matching with typomania, Microsoft OSSGadget's oss-find-squats, and pypi-scan.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195.002
nist_csf:
- ID.RA-09
upstream: detecting-typosquatting-packages@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** This skill is for defensive software-supply-chain security, package screening, and authorized research. Use corpus-matching and registry-query techniques here only against registries you are permitted to query at scale and packages you intend to evaluate for your own organization. Mass automated registry scraping may violate registry terms of service.

## Prerequisites

- Rust toolchain (`cargo`) to build/use typomania, or prebuilt OSSGadget release
- Python 3.8+ for pypi-scan and helper script in this skill
- Network access to target registry's public API (npmjs.org, pypi.org, crates.io)
- Corpus of "popular" package names for ecosystem (download counts or top-N list)

Install tooling:

```bash
# typomania (library + example harness) — Rust Foundation
git clone https://github.com/rustfoundation/typomania
cd typomania
cargo build --release
cargo run --example registry   # demonstrates the Harness against a fake registry
# OSSGadget (Microsoft) — cross-ecosystem squat finder
# Download a release binary, then:
oss-find-squats pkg:npm/requests          # purl syntax
oss-find-squats pkg:pypi/reqeusts
# pypi-scan (IQTLabs) — PyPI typosquat enumerator
git clone https://github.com/IQTLabs/pypi-scan
cd pypi-scan
pip install -r requirements.txt
# ecosyste-ms ground-truth dataset of known squats
git clone https://github.com/ecosyste-ms/typosquatting-dataset
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic |
|--------------|------|--------|
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | Initial Access |

Typosquatted dependency is delivery vehicle for T1195.002: attacker compromises victim's supply chain not by breaching real package but by getting malicious look-alike installed in its place. Related downstream behavior frequently includes T1059 (Command and Scripting Interpreter) via install hooks and T1041/T1567 (Exfiltration) of tokens and environment variables.

## Workflow

### Step 1: Build popular-name corpus
Detector needs reference set of legitimate names to compare against. Pull top packages by download count for ecosystem.

```bash
# PyPI: top packages dataset (Hugo van Kemenade's top-pypi-packages)
curl -s https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json \
  -o top-pypi-packages.json
# npm: query the registry's most-depended-upon search
curl -s 'https://registry.npmjs.org/-/v1/search?text=not:unstable&popularity=1.0&size=250' \
  -o npm-top.json
# crates.io: top crates by downloads
curl -s 'https://crates.io/api/v1/crates?sort=downloads&per_page=100' \
  -H 'User-Agent: typosquat-screen (security@example.com)' -o crates-top.json
```

### Step 2: Generate candidate squats with standard mutation primitives
typomania/typogard apply fixed set of name transformations that mirror real attacker behavior. Reproduce them to understand what screen must catch:

```text
1. Repeated characters     requests  -> reqquests
2. Omitted characters      requests  -> requsts
3. Swapped/transposed      requests  -> reqeusts
4. Swapped words           python-dateutil -> dateutil-python
5. Common typos (1-edit)   requests  -> rewuests   (keyboard adjacency)
6. Homophones / vowel swap requests  -> requeasts
7. Version / suffix tricks lodash    -> lodashs, lodash-js
8. Delimiter swaps         cross-env -> crossenv, cross_env
9. Scope confusion (npm)   @types/node -> types-node
```

Run typomania's harness, which implements these as reusable primitives behind the `Corpus` and `Harness` traits:

```bash
# In the typomania checkout: feed your popular corpus, then check a name.
# The Harness::check method (parallelized via rayon) compares the candidate
# against every corpus entry using the squatting primitives.
cargo run --example registry -- --corpus top-pypi-packages.json --name reqeusts
```

### Step 3: Screen with OSSGadget oss-find-squats
OSSGadget queries live registry, generates mutations of supplied package, and reports which mutated names exist as published packages.

```bash
# Find names that squat on a legitimate package, checking which exist in the registry
oss-find-squats pkg:npm/lodash
oss-find-squats pkg:pypi/requests
# Reverse direction: given a SUSPECT name, find the legitimate package it mimics
oss-find-squats --quiet pkg:npm/loadsh
```

### Step 4: Enumerate PyPI squats with pypi-scan
```bash
cd pypi-scan
# Find candidate typosquats of a specific package
python pypi_scan.py -p requests
# Scan the top-N most-downloaded PyPI packages for existing squats
python pypi_scan.py -n 50
```

### Step 5: Enrich suspected squats with registry metadata
Near-miss name is only suspicious if it is also young, low-download, or ships install scripts. Pull metadata to triage:

```bash
# npm package metadata: creation time, maintainers, scripts
curl -s https://registry.npmjs.org/loadsh | \
  python -c 'import sys,json;d=json.load(sys.stdin);v=d["dist-tags"]["latest"];print("created:",d["time"]["created"]);print("scripts:",d["versions"][v].get("scripts",{}))'
# npm download counts (last week)
curl -s https://api.npmjs.org/downloads/point/last-week/loadsh
# PyPI JSON API: release history and author
curl -s https://pypi.org/pypi/reqeusts/json | \
  python -c 'import sys,json;d=json.load(sys.stdin);i=d["info"];print(i["name"],i["author"],i["home_page"]);print("releases:",list(d["releases"].keys()))'
```

### Step 6: Score, triage, and confirm
Combine signals into risk score. High risk = small edit distance to popular name AND (package age < 90 days OR downloads < 1000 OR presence of `postinstall`/`preinstall`/setup-time network calls). Cross-check against ecosyste-ms known-squats dataset:

```bash
# Is this name a documented squat?
grep -i 'loadsh' typosquatting-dataset/data/*.csv
```

Confirm malicious intent by inspecting (in sandbox/VM only) install scripts and source tarball — never `npm install` or `pip install` suspect on your workstation.

### Step 7: Enforce in CI/CD
Add blocking gate that screens every new dependency name introduced by PR:

```yaml
# .github/workflows/typosquat-gate.yml
name: typosquat-gate
on: [pull_request]
jobs:
  screen:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Screen new dependencies
        run: |
          git diff origin/${{ github.base_ref }}...HEAD -- package.json requirements.txt \
            | grep '^+' | python scripts/agent.py screen --ecosystem npm --corpus top.json --stdin
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| typomania | Rust typosquat-detection library (powers crates.io) | https://github.com/rustfoundation/typomania |
| OSSGadget `oss-find-squats` | Cross-ecosystem squat finder (purl) | https://github.com/microsoft/OSSGadget |
| pypi-scan | PyPI typosquat enumerator | https://github.com/IQTLabs/pypi-scan |
| ecosyste-ms typosquatting-dataset | Curated known-squat ground truth | https://github.com/ecosyste-ms/typosquatting-dataset |
| top-pypi-packages | PyPI popular-name corpus | https://hugovk.github.io/top-pypi-packages/ |
| OWASP CI/CD Security Top 10 | Supply-chain control guidance | https://owasp.org/www-project-top-10-ci-cd-security-risks/ |

## Mutation Primitives Reference

| Primitive | Legit | Squat | Why it works |
|-----------|-------|-------|--------------|
| Transposition | requests | reqeusts | Common typing slip |
| Omission | requests | requsts | Dropped character |
| Repetition | requests | reqquests | Stuck key |
| Delimiter swap | cross-env | crossenv | Hyphen vs none ambiguity |
| Word order | python-dateutil | dateutil-python | Reordered compound name |
| Homoglyph/vowel | requests | requeasts | Visual/phonetic similarity |
| Suffix/scope | lodash | lodash-js, loadsh | Plausible "official" variant |

## Validation Criteria

- [ ] Popular-name corpus downloaded for each in-scope ecosystem
- [ ] Mutation primitives reproduced and known squat (e.g., `loadsh`) is correctly flagged
- [ ] typomania / OSSGadget / pypi-scan run against at least one real package
- [ ] Suspected squats enriched with age, download, and install-script metadata
- [ ] Findings cross-checked against ecosyste-ms known-squats dataset
- [ ] Risk scoring suppresses obvious false positives (legit scoped/forked packages)
- [ ] CI/CD gate screens new dependency names on every pull request
- [ ] No suspect package installed outside disposable sandbox

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-typosquatting-packages
