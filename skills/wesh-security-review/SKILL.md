---
name: wesh-security-review
description: On-demand defensive security pack — secure code review, SAST/SCA, secrets, IaC/container/k8s hardening, crypto, API/auth, LLM guardrails, detection, forensics, IR. Use for "security review", "harden", "scan for vulns", or /wesh-security-review.
---

Defensive security library: 698 skills, loaded one at a time. You pick, read, follow. Tailored codegraph recipe on the 34 code-editing skills; the rest are grep + procedure.

> Authorized defensive / own-system work only. Needs scope or rules of engagement for any live target. Refuse out-of-scope.

## How
1. Find skill: grep `pack/INDEX.tsv` (columns: `name  facing  subdomain  description`) for the task. e.g. `grep -iE 'jwt|oauth|token' pack/INDEX.tsv`. Many hits: pick closest by description, say which.
2. Read `pack/<name>.md`. That is the procedure. Follow it, wesh rules still apply (smallest complete change, never-cut list, run covering tests once).
3. `facing: source` skills open with a class-specific `## Codegraph (do this first)` block — a tailored `codegraph_explore` query for that vuln class's sinks, then `callers`/`impact` before editing shared code, `affected` for tests, `sync` before "unused". Those skills' own "grep the codebase" steps route through codegraph; grep stays for strings, config, dynamic refs. No graph yet: grep the sinks the block names.
4. Not found: say so, grep the repo yourself, do not invent a tool or CVE.

## Scope
In: review/scan/harden/detect/implement/audit/respond — code, infra (IaC, container, k8s, cloud config), pipelines, crypto, identity, AI/LLM apps, forensics, incident response, threat hunting.
Out (not in this pack): exploitation, credential access, C2, lateral movement, pentest engagements, phishing, offensive recon. Those live upstream, not vendored here.

## Facing
- `source` (34): editing/testing vulnerable code in the repo — XSS, XXE, SQLi, CORS, access control, mass assignment, business logic, sensitive-data exposure, JWT/OAuth, crypto impl, LLM guardrails, SAST rules. Codegraph genuinely pays off; each carries a tailored codegraph recipe.
- `config` (234): running a scanner or configuring infra — SAST/SCA/secret tools (trivy, snyk, gitleaks, semgrep), IaC/container/k8s/cloud hardening, CI/CD, TLS/HSM/KMS, API gateways. Follow the procedure; codegraph only if it sends you into app code.
- `defense` (430): forensics, IR, SOC, threat hunting, detection engineering, network/endpoint/OT, vuln mgmt, compliance. Grep + the procedure; no codegraph.

Each `pack/<name>.md` keeps its MITRE/NIST ids and an `upstream:` line. Prose cavemanised; commands, configs and code kept verbatim. Full originals (scripts/, references/): the upstream link in each file.
