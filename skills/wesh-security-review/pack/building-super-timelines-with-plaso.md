---
name: building-super-timelines-with-plaso
description: Generate forensic super-timelines with Plaso's log2timeline.py, pinfo.py, psort.py, and psteal.py CLI tools (fusing file-system MACB, registry, EVTX, browser history, prefetch, LNK, and more), then triage and filter the results in Timesketch.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1070
nist_csf:
- RS.AN-03
upstream: building-super-timelines-with-plaso@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** Build timelines only from evidence you are authorized to analyze. Work from forensic images/copies and preserve chain of custody.

## Prerequisites

- Install Plaso (Docker is supported, reproducible method):
  ```bash
  docker pull log2timeline/plaso
  # Run a tool, mounting your evidence/output directory
  docker run -v /cases:/data log2timeline/plaso log2timeline.py --version
  ```
  Alternatively on Ubuntu via GIFT PPA:
  ```bash
  sudo add-apt-repository ppa:gift/stable
  sudo apt-get update && sudo apt-get install -y plaso-tools
  ```
- A Timesketch instance (docker-compose deployment from https://github.com/google/timesketch) for triage.
- Forensic image (E01/raw) or mounted file system.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1070 | Indicator Removal | Super timelines reveal indicator-removal behavior (log clearing, file deletion, timestomping) by exposing inconsistencies between MACB timestamps, USN journal, and event logs. |

Plaso is defensive forensics engine; mapping reflects anti-forensic adversary behavior super timelines are well suited to detect.

## Workflow

### 1. Extract events into storage file
`log2timeline.py` writes a `.plaso` file from source. `--storage-file` names output; source can be an `.E01`, raw image, mount point, or directory.
```bash
log2timeline.py --storage-file timeline.plaso /cases/greendale/image.E01
```
Scope parsers for speed/relevance with `--parsers` (presets like `win7`, `webhist`, or explicit parser names):
```bash
log2timeline.py --parsers "win7,!filestat" --storage-file timeline.plaso /cases/image.E01
```

### 2. Inspect storage file
`pinfo.py` reports source, parsers used, event counts, and any warnings.
```bash
pinfo.py timeline.plaso
```

### 3. Export filtered super timeline (CSV)
`psort.py` selects output module with `-o`, writes with `-w`, normalizes timezone with `--output-time-zone`, and accepts event filter expression to scope date range.
```bash
psort.py --output-time-zone 'UTC' \
  -o l2tcsv \
  -w supertimeline.csv \
  timeline.plaso \
  "date > datetime('2026-01-01T00:00:00') AND date < datetime('2026-01-27T00:00:00')"
```
For Timesketch-friendly JSON lines, use the `json_line` output module:
```bash
psort.py --output-time-zone 'UTC' -o json_line -w supertimeline.jsonl timeline.plaso
```

### 4. One-step extraction + export with psteal
`psteal.py` runs extraction and CSV export together for quick triage.
```bash
psteal.py --source /cases/greendale/image.E01 -o l2tcsv -w supertimeline.csv
```

### 5. Import into Timesketch
Use official `timesketch_importer` CLI to upload the `.plaso` (or CSV/JSONL) into sketch. Timesketch chunks/reassembles and indexes file.
```bash
timesketch_importer \
  --host http://127.0.0.1:5000 \
  --username admin \
  --timeline_name "greendale-host01" \
  --sketch_id 1 \
  timeline.plaso
```

### 6. Triage in Timesketch
In sketch UI:
- Filter to suspicious window or `data_type` (e.g. `windows:evtx:record`, `fs:stat`).
- Star/tag events of interest and add comments for collaboration.
- Save searches and run analyzers (e.g. browser timeframe, similarity, sigma) over timeline.
- Build narrative from corroborating events across artifact sources.

### 7. Hunt for anti-forensics
Look for MACB timestamps that disagree with $UsnJrnl entries (timestomping), gaps or `EventLog cleared` (1102) records, and deleted-then-recreated files — all visible on unified timeline.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Plaso (log2timeline) | Timeline engine + tools | https://github.com/log2timeline/plaso |
| Plaso documentation | Tool usage and parsers | https://plaso.readthedocs.io/ |
| Timesketch | Timeline analysis platform | https://github.com/google/timesketch |
| Timesketch docs | Deployment, importer, analyzers | https://timesketch.org/ |
| Plaso Docker image | Reproducible runtime | https://hub.docker.com/r/log2timeline/plaso |

## Key Commands

| Command | Purpose |
|---------|---------|
| `log2timeline.py --storage-file out.plaso <source>` | Extract events |
| `log2timeline.py --parsers <preset> ...` | Scope parsers |
| `pinfo.py out.plaso` | Inspect storage file |
| `psort.py -o l2tcsv -w out.csv out.plaso "<filter>"` | Filter + export CSV |
| `psort.py -o json_line -w out.jsonl out.plaso` | Export JSONL |
| `psteal.py --source <img> -o l2tcsv -w out.csv` | Extract + export in one step |
| `timesketch_importer --host ... <file>` | Import into Timesketch |

## Validation Criteria

- [ ] `.plaso` storage file produced from source image
- [ ] pinfo confirms expected parsers ran and event counts are non-zero
- [ ] Super timeline exported with UTC normalization and scoped filter
- [ ] Timeline imported into Timesketch sketch and indexed
- [ ] Suspicious window triaged with tags/stars/saved searches
- [ ] Anti-forensic indicators (timestomping, log clearing) checked
- [ ] Findings documented with corroborating cross-source events

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/building-super-timelines-with-plaso
