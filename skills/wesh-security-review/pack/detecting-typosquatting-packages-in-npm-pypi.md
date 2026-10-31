---
name: detecting-typosquatting-packages-in-npm-pypi
description: Detects typosquatting attacks in npm and PyPI package registries by analyzing package name similarity using Levenshtein distance and other string metrics, examining publish date heuristics to identify recently created packages mimicking established ones, and flagging download count anomalies where suspicious packages have disproportionately low usage compared to their legitimate targets.
subdomain: supply-chain-security
facing: config
mitre_attack:
- T1195.001
- T1195.002
- T1608.001
- T1554
nist_csf:
- GV.SC-01
- GV.SC-03
- GV.SC-06
- GV.SC-07
upstream: detecting-typosquatting-packages-in-npm-pypi@54a7988 Apache-2.0, modified by wesh
---
Not for: as the sole determination of malicious intent; name similarity alone does not prove a package is malicious. Do not use for bulk automated takedown requests without manual review of flagged packages. Do not use against private registries without authorization.

## Prerequisites

- Python 3.9+ with `requests` and `python-Levenshtein` (or `rapidfuzz`) packages installed
- Network access to `https://pypi.org/pypi/<package>/json` (PyPI JSON API) and `https://registry.npmjs.org/<package>` (npm registry API)
- List of popular or critical packages to monitor (e.g., top 1000 PyPI packages, organization's dependency list)
- Understanding of common typosquatting patterns: character omission, transposition, insertion, substitution, and hyphen/underscore manipulation

## Workflow

### Step 1: Build Target Package Watchlist

Establish set of legitimate packages to monitor for typosquats:

- **Extract project dependencies**: Parse `requirements.txt`, `Pipfile.lock`, `package.json`, or `package-lock.json` to extract all direct and transitive dependency names
- **Include popular packages**: Supplement with high-value targets from top 1000 PyPI downloads (available from `https://hugovk.github.io/top-pypi-packages/`) or top npm packages by download count
- **Add organization packages**: Include any packages published by your organization that attackers might target with typosquats to intercept internal installations
- **Normalize names**: PyPI treats hyphens, underscores, and periods as equivalent (PEP 503 normalization: `re.sub(r"[-_.]+", "-", name).lower()`). npm package names are case-sensitive but scoped packages use `@scope/name` format. Normalize before comparison.

### Step 2: Generate Candidate Typosquat Names

Produce potential typosquat variants for each target package:

- **Character omission**: Remove each character one at time (`requests` -> `rquests`, `requets`, `reqests`)
- **Character transposition**: Swap adjacent characters (`requests` -> `erquests`, `rqeuests`, `reques ts`)
- **Character substitution**: Replace characters with keyboard-adjacent keys using QWERTY distance map (`requests` -> `rrquests`, `requesta`)
- **Character insertion**: Insert common characters at each position (`requests` -> `rrequests`, `reqquests`)
- **Separator manipulation**: For hyphenated names, try removing, doubling, or replacing separators (`my-package` -> `mypackage`, `my--package`, `my_package`)
- **Common prefix/suffix attacks**: Prepend or append common strings (`python-requests`, `requests-python`, `requests2`, `requests-lib`)

### Step 3: Query Registry APIs for Candidate Packages

Check whether generated candidate names exist in registry:

- **PyPI JSON API**: Send `GET https://pypi.org/pypi/<candidate>/json` for each candidate. A `200` response means package exists; `404` means it does not. Extract from response: `info.name`, `info.version`, `info.author`, `info.summary`, `info.home_page`, `info.project_urls`, and `releases` (keyed by version with `upload_time_iso_8601` timestamps).
- **npm registry API**: Send `GET https://registry.npmjs.org/<candidate>` with `Accept: application/json`. Extract: `name`, `description`, `dist-tags.latest`, `time.created`, `time.modified`, `maintainers`, and `versions`.
- **Rate limiting**: PyPI has no published rate limits but respect reasonable request rates (1-2 requests/second). npm registry returns `429` when rate limited; implement exponential backoff.
- **Batch optimization**: For large candidate lists, parallelize requests with connection pooling (`requests.Session`) and limit concurrency to avoid triggering abuse protections.

### Step 4: Analyze Package Metadata for Suspicion Signals

Score each existing candidate package against multiple heuristic signals:

- **Levenshtein distance**: Calculate edit distance between candidate name and target. Packages with distance 1-2 from popular package are high-priority suspects. Historical analysis shows 18 of 40 known typosquats had Levenshtein distance of 2 or less from their targets.
- **Publish date recency**: Compare candidate's first publish date against target's. package created years after its near-namesake is more suspicious. Flag packages created within last 90 days that are similar to packages published years ago.
- **Download count disparity**: Compare weekly downloads. Legitimate similarly-named packages typically have comparable or explainable download counts. package with 50 downloads versus its near-namesake with 5 million downloads is suspicious. PyPI download stats are available via BigQuery (`pypistats.org/api/`); npm provides download counts at `https://api.npmjs.org/downloads/point/last-week/<package>`.
- **Author and maintainer analysis**: Check if candidate package author matches legitimate package author. Different authors for near-identical names increase suspicion.
- **Description similarity**: Compare package descriptions. Typosquats frequently copy or closely paraphrase target package description to appear legitimate.
- **Version count**: Legitimate packages typically have many versions over time. package with only 1-2 versions and name similar to popular package is suspicious.
- **Repository URL analysis**: Check if candidate links to same repository as target (likely legitimate fork/mirror) or has no repository URL (suspicious).

### Step 5: Score, Rank, and Report Findings

Combine signals into composite risk score and generate actionable report:

- **Weighted scoring**: Assign weights to each signal. Example: Levenshtein distance 1 = 40 points, Levenshtein distance 2 = 25 points, created < 90 days ago = 15 points, download ratio < 0.001 = 15 points, different author = 10 points, single version = 5 points. Total score out of 100.
- **Threshold classification**: Score >= 70: HIGH risk (likely typosquat), 40-69: MEDIUM risk (requires manual review), < 40: LOW risk (likely legitimate)
- **Generate report**: For each flagged package, include target it mimics, all signal values, composite score, direct links to both packages on registry, and recommendation (block, investigate, or allow)
- **Actionable output**: Produce blocklist of flagged package names that can be imported into package manager deny-lists, CI/CD policy engines, or artifact repository proxy rules

## Key Concepts

| Term | Definition |
|------|------------|
| **Typosquatting** | Registering package name that closely resembles popular package, exploiting common typos to trick developers into installing malicious code |
| **Levenshtein Distance** | minimum number of single-character edits (insertions, deletions, substitutions) required to transform one string into another; primary metric for measuring name similarity |
| **Dependency Confusion** | broader supply chain attack where attackers publish malicious packages to public registries with names matching private internal packages, exploiting package manager resolution order |
| **PEP 503 Normalization** | Python packaging specification that treats hyphens, underscores, and periods as equivalent in package names, meaning `my-package`, `my_package`, and `my.package` resolve to same package |
| **QWERTY Distance** | keyboard-layout-aware distance metric measuring how far apart two keys are on standard keyboard, used to detect substitutions from adjacent key mistyping |
| **Combosquatting** | variant of typosquatting where attackers prepend or append common words to package name (e.g., `requests-security`, `python-requests`) |
| **StarJacking** | attack where typosquat package links its repository URL to legitimate package's GitHub repository to inflate apparent credibility |

## Tools & Systems

- **PyPI JSON API**: REST API at `https://pypi.org/pypi/<package>/json` returning package metadata including name, author, versions, upload timestamps, and project URLs
- **npm Registry API**: REST API at `https://registry.npmjs.org/<package>` returning package metadata including maintainers, version history, creation timestamps, and distribution info
- **python-Levenshtein / rapidfuzz**: Python libraries for fast string distance computation, supporting Levenshtein, Damerau-Levenshtein, Jaro-Winkler, and other similarity metrics
- **pypistats.org API**: Provides download statistics for PyPI packages, enabling download count comparison between suspected typosquats and their targets
- **npm download counts API**: Endpoint at `https://api.npmjs.org/downloads/point/<period>/<package>` providing download statistics for npm packages

## Typosquatting Detection Report

**Scan Date**: 2026-03-19
**Registry**: PyPI
**Packages Monitored**: 87
**Candidates Generated**: 2,412
**Candidates Found in Registry**: 34
**Flagged as Suspicious**: 5

### HIGH Risk (Score >= 70)

| Suspect Package | Target Package | Levenshtein | Created | Downloads | Score |
|----------------|---------------|-------------|---------|-----------|-------|
| reqeusts | requests | 1 | 2026-02-28 | 43 | 92 |
| requsets | requests | 1 | 2026-03-01 | 12 | 88 |
| numpyy | numpy | 1 | 2026-01-15 | 67 | 78 |

### Recommendation
- BLOCK: reqeusts, requsets, numpyy (add to artifact proxy deny-list)
- REPORT: Submit malware reports to security@pypi.org with package names and evidence
- MONITOR: Continue weekly scans for full dependency watchlist
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-typosquatting-packages-in-npm-pypi
