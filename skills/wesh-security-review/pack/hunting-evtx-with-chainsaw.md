---
name: hunting-evtx-with-chainsaw
description: Run Chainsaw against collected Windows EVTX files to hunt with the SigmaHQ rule corpus, built-in detection rules, and high-speed keyword/regex search, plus analyze shimcache, SRUM, and event-log gaps, outputting colorized tables, CSV, or JSON.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1059.001
nist_csf:
- DE.AE-02
upstream: hunting-evtx-with-chainsaw@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Chainsaw binary. Download release from GitHub or build from source:
  ```bash
  # Build from source (Rust toolchain required)
  git clone https://github.com/WithSecureLabs/chainsaw.git
  cd chainsaw && cargo build --release
  ./target/release/chainsaw --version
  # or: nix profile install github:WithSecureLabs/chainsaw
  ```
- Chainsaw repo ships `mappings/` (Sigma field mappings) and `rules/` (Chainsaw rules).
- Copy of SigmaHQ rules for full Sigma coverage:
  ```bash
  git clone https://github.com/SigmaHQ/sigma.git
  ```
- Collected Windows `.evtx` files (and registry hives like `SYSTEM`/`Amcache.hve` for shimcache analysis).

## MITRE ATT&CK Mapping

| Technique ID | Official Name | Why Chainsaw Detects It |
|--------------|---------------|-------------------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Sigma rules over EID 4104/4103 and search flag malicious PowerShell |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Process-creation Sigma rules surface suspicious cmd usage |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Sigma rules over registry events flag persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Rules over EID 4698/106 detect task creation |
| T1070.006 | Indicator Removal: Timestomp | `analyse gaps` and shimcache analysis reveal tampering/time gaps |
| T1204.002 | User Execution: Malicious File | Shimcache analysis shows executed binaries |

## Workflow

### 1. Hunt EVTX with Sigma rules
Run SigmaHQ corpus against collected logs using bundled mapping file. mapping translates Sigma fields to EVTX fields.
```bash
chainsaw hunt ./collected_evtx \
  -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml
```

### 2. Hunt with Chainsaw built-in rules plus Sigma
Combine Chainsaw's own rules (`-r`) with Sigma (`-s`) for broader coverage.
```bash
chainsaw hunt ./collected_evtx \
  -r ./rules \
  -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml
```

### 3. Filter to reduce noise
Limit results by Sigma rule level, status, and detection kind.
```bash
chainsaw hunt ./collected_evtx -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml \
  --level high --status stable --kind evtx
```

### 4. Output to CSV and JSON
Write structured output for reporting and pipelines.
```bash
# JSON to stdout/file
chainsaw hunt ./collected_evtx -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml --json > detections.json
# CSV into a directory (one file per detection group)
chainsaw hunt ./collected_evtx -s ./sigma/rules \
  --mapping ./mappings/sigma-event-logs-all.yml --csv --output ./csv_out
```

### 5. Targeted keyword and regex search
Confirm hypothesis by searching raw events independent of rules.
```bash
# Case-insensitive keyword search
chainsaw search "mimikatz" -i ./collected_evtx
# Regex for base64-encoded PowerShell commands, as JSON
chainsaw search -e "-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{20,}" ./collected_evtx --json
# Time-bounded search using a Tau expression
chainsaw search ./collected_evtx -t 'Event.System.EventID: =4624' \
  --from "2026-06-01T00:00:00" --to "2026-06-20T00:00:00"
```

### 6. Analyse shimcache for execution evidence
Parse AppCompatCache from SYSTEM hive, pair it with Amcache timestamps, and pattern-match suspicious entries.
```bash
chainsaw analyse shimcache ./SYSTEM \
  --regexfile ./shimcache_patterns.txt \
  --amcache ./Amcache.hve --tspair \
  --output ./shimcache_analysis.csv
```

### 7. Analyse SRUM and event-log gaps
Detect program/network usage and identify suspicious logging gaps (possible log clearing or timestomp).
```bash
# SRUM database analysis
chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat -o srum.json
# Event-log gaps that may indicate cleared/tampered logs
chainsaw analyse gaps ./collected_evtx --min-time-gap-minutes 30 --json
```

### 8. Dump and lint
Inspect raw artifact content and validate custom rules before hunt.
```bash
chainsaw dump ./SOFTWARE --json --output dump.json
chainsaw lint -r ./rules --kind sigma
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| Chainsaw | Fast EVTX/artifact hunting and search | https://github.com/WithSecureLabs/chainsaw |
| SigmaHQ rules | Community detection rules | https://github.com/SigmaHQ/sigma |
| Chainsaw mappings | Sigma-to-EVTX field mappings | https://github.com/WithSecureLabs/chainsaw/tree/master/mappings |
| Hayabusa | Alternative Sigma EVTX timeline tool | https://github.com/Yamato-Security/hayabusa |
| Timeline Explorer | Review CSV output | https://ericzimmerman.github.io/ |

## Validation Criteria

- [ ] Chainsaw binary installed and `--version` confirmed.
- [ ] SigmaHQ rules and correct mapping file available.
- [ ] Sigma hunt run against collected EVTX directory.
- [ ] Chainsaw built-in rules combined with Sigma where appropriate.
- [ ] Detections filtered by level/status/kind to reduce noise.
- [ ] CSV and/or JSON output produced for reporting.
- [ ] Targeted keyword/regex/Tau searches run to confirm findings.
- [ ] Shimcache analysed with Amcache timestamp pairing.
- [ ] SRUM and event-log-gap analysis performed where artifacts exist.
- [ ] Findings (e.g., PowerShell T1059.001) documented for hunt report.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-evtx-with-chainsaw
