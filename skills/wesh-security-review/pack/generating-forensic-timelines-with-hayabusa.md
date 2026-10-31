---
name: generating-forensic-timelines-with-hayabusa
description: Run Hayabusa against collected Windows EVTX files to apply Sigma detection rules and produce a prioritized, chronological CSV/JSON timeline with severity levels, MITRE ATT&CK mappings, and per-host/per-Event-ID metrics.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1059.001
nist_csf:
- RS.AN-03
upstream: generating-forensic-timelines-with-hayabusa@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Hayabusa binary. Download pre-compiled release (Windows/Linux/macOS) from GitHub:
  ```bash
  # Linux example
  curl -LO https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-3.0.0-lin-x64-gnu.zip
  unzip hayabusa-*.zip && cd hayabusa-*
  ./hayabusa-3.0.0-lin-x64-gnu --version
  ```
  Or build from source (rules are submodule):
  ```bash
  git clone https://github.com/Yamato-Security/hayabusa.git --recursive
  cd hayabusa && cargo build --release
  ```
- Collected Windows `.evtx` files (or run with `--live-analysis` on host, as Administrator).
- Updated detection rules:
  ```bash
  ./hayabusa update-rules
  ```
- Optional: Timeline Explorer (Windows) or Timesketch for visualizing output; `jq` for JSONL.

## MITRE ATT&CK Mapping

| Technique ID | Official Name | Why Hayabusa Detects It |
|--------------|---------------|-------------------------|
| T1059.001 | Command and Scripting Interpreter: PowerShell | Sigma rules over Event IDs 4104/4103 and Sysmon flag malicious PowerShell |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Rules over process-creation events surface suspicious cmd usage |
| T1078 | Valid Accounts | Logon events (4624/4625/4672) reveal anomalous authentication |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Rules over registry-modification events flag persistence |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Event ID 4698/106 rules surface task creation |
| T1003 | OS Credential Dumping | Rules flag LSASS access and credential-dumping patterns |

## Workflow

### 1. Update rule set
Pull latest Sigma and Hayabusa rules before every investigation.
```bash
./hayabusa update-rules
```

### 2. Build CSV timeline from collected logs
Point Hayabusa at directory of `.evtx` files and write CSV timeline. `-w` skips interactive wizard for scripted runs.
```bash
./hayabusa csv-timeline -d ./collected_evtx -o timeline.csv -w
# UTC timestamps for cross-host correlation
./hayabusa csv-timeline -d ./collected_evtx -o timeline_utc.csv -U -w
```

### 3. Choose output profile
Profiles control detail. Use `verbose` to include MITRE ATT&CK tactics, tags, and source rule/EVTX file; `all-field-info` to retain every original field.
```bash
# Verbose: adds MITRE tactics, tags, rule file, evtx file
./hayabusa csv-timeline -d ./collected_evtx -o timeline_verbose.csv -p verbose -w
# Preserve all original event fields
./hayabusa csv-timeline -d ./collected_evtx -o timeline_full.csv -p all-field-info -w
```
Available profiles: `minimal`, `standard` (default), `verbose`, `all-field-info`, `all-field-info-verbose`, `super-verbose`, `timesketch-minimal`, `timesketch-verbose`.

### 4. Filter by minimum severity
Focus triage on highest-confidence detections with `-m`/`--min-level`.
```bash
./hayabusa csv-timeline -d ./collected_evtx -o critical.csv -m high -w
```
Levels: `informational`, `low`, `medium`, `high`, `critical`.

### 5. Produce JSON/JSONL timeline for tooling
JSONL feeds cleanly into `jq` and downstream pipelines.
```bash
./hayabusa json-timeline -d ./collected_evtx -L -o timeline.jsonl -w
# Example: top rule titles
jq -r '.RuleTitle' timeline.jsonl | sort | uniq -c | sort -rn | head
```

### 6. Generate metrics and pivot keywords
Summaries reveal which hosts and Event IDs dominate, and pivot keywords give hunting leads.
```bash
./hayabusa computer-metrics -d ./collected_evtx -o computers.csv
./hayabusa eid-metrics -d ./collected_evtx -o eid.csv
./hayabusa log-metrics -d ./collected_evtx -o logs.csv
./hayabusa pivot-keywords-list -d ./collected_evtx -m medium -o pivots
```

### 7. Search logs for specific IOCs
Use the `search` command for keyword or regex hunting independent of detection rules.
```bash
# Keyword search (case-insensitive) for a suspicious binary
./hayabusa search -d ./collected_evtx -k "powershell" -i
# Regex search for base64-looking PowerShell encoded commands
./hayabusa search -d ./collected_evtx -r "-[Ee]nc(odedCommand)?\s+[A-Za-z0-9+/=]{20,}"
```

### 8. Live triage on running host
On affected machine (Administrator), analyze local logs without exporting first.
```bash
./hayabusa csv-timeline -l -o live_timeline.csv -m high -w
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| Hayabusa | Sigma-based EVTX timeline/threat hunting | https://github.com/Yamato-Security/hayabusa |
| hayabusa-rules | Sigma + Hayabusa detection rules | https://github.com/Yamato-Security/hayabusa-rules |
| Takajō | Hayabusa results analyzer | https://github.com/Yamato-Security/takajo |
| Timeline Explorer | Review CSV timelines | https://ericzimmerman.github.io/ |
| Timesketch | Collaborative timeline analysis | https://timesketch.org/ |
| Sigma | Generic detection rule format | https://github.com/SigmaHQ/sigma |

## Validation Criteria

- [ ] Hayabusa binary installed and `--version` confirmed.
- [ ] Rules updated with `update-rules` before analysis.
- [ ] CSV timeline generated from collected `.evtx` directory.
- [ ] Appropriate output profile selected for investigation goal.
- [ ] Timeline filtered by minimum severity for triage focus.
- [ ] JSON/JSONL timeline produced for downstream tooling where needed.
- [ ] Computer/EID/log metrics generated.
- [ ] Pivot keywords list produced for hunting leads.
- [ ] Targeted IOC searches run with keyword/regex.
- [ ] Findings (e.g., PowerShell T1059.001 detections) documented in incident timeline.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/generating-forensic-timelines-with-hayabusa
