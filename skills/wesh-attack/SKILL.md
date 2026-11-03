---
name: wesh-attack
description: On-demand offensive security pack — exploitation, credential access, C2, lateral movement, phishing simulation, pentest and red-team engagements, 120 skills, one at a time. Use for "attack simulation", "pentest", "red team", "exploit", or /wesh-attack.
---

Offensive security library: 120 skills, loaded one at a time. You pick, read, follow. Tailored codegraph recipe on the 35 code-facing skills; the rest are grep + procedure.

> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## How
1. Find skill: grep `pack/INDEX.tsv` (columns: `name  facing  subdomain  description`) for the task. e.g. `grep -iE 'jwt|oauth|token' pack/INDEX.tsv`. Many hits: pick closest by description, say which.
2. Read `pack/<name>.md`. That is the procedure. Follow it, wesh rules still apply (smallest complete change, never-cut list, run covering tests once).
3. `facing: source` skills open with a class-specific `## Codegraph (do this first)` block — a tailored `codegraph_explore` query for that vuln class's sinks, then `callers`/`impact` before editing shared code and `affected` for tests — and their own "grep the codebase" steps route through codegraph. No graph yet: grep the sinks the block names.
4. Not found: say so, grep the repo yourself, do not invent a tool or CVE.

## Scope
In: the offensive side of authorized security work — exploit development against a target you own or are contracted to test, credential access, C2 and post-exploitation, lateral movement, phishing simulation, red-team and purple-team exercises, pentest engagements, wireless and network attacks.
Out: targets without written authorization, denial of service, mass exploitation, persistence on systems outside the engagement, and anything that reaches a third party the scope does not name.

Every `pack/<name>.md` opens with the authorization line and carries its own legal notice. Scope decides, not the tool: if the rules of engagement do not cover it, the answer is no.

## Facing
- `source` (35): the attack is written against the target's own code — SSTI, SQLi, NoSQLi, deserialization, prototype pollution, JWT confusion, SSRF, request smuggling, IDOR, mass assignment, race conditions, type juggling, cache poisoning and deception, CSP bypass, CSRF, clickjacking, GraphQL depth and introspection, parameter pollution, cert pinning, rate-limit bypass, binary exploitation. Codegraph genuinely pays off; each carries a tailored recipe.
- `config` (85): the tooling and the engagement — Metasploit, impacket, certipy, BloodHound, Sliver and Havoc C2, pacu, gcpbucketbrute, evilginx, gophish, Covenant, pyrit, Stratus Red Team, hashcat, aircrack, netexec, wmiexec, kerberoasting, DCSync, PetitPotam, OSINT, AD abuse and wireless. Follow the procedure; codegraph only if it sends you into app code.

Each `pack/<name>.md` keeps its MITRE/NIST ids and an `upstream:` line. Prose cavemanised; commands, configs and code kept verbatim. Full originals (scripts/, references/): the upstream link in each file.
