---
name: deploying-ransomware-canary-files
description: Deploys and monitors ransomware canary files using Python's watchdog library, placing decoy files mimicking high-value targets (financial records, credentials, database exports) where ransomware enumerates first, and alerting via email, Slack, or syslog on any read/modify/rename/delete.
subdomain: ransomware-defense
facing: defense
mitre_attack:
- T1486
- T1083
- T1490
- T1485
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
upstream: deploying-ransomware-canary-files@54a7988 Apache-2.0, modified by wesh
---
Not for: as a replacement for endpoint protection, backup strategy, or network segmentation. Canary files are a detection layer, not a prevention mechanism.

## Prerequisites

- Python 3.8+ with pip
- watchdog library (pip install watchdog)
- Write access to directories where canary files will be placed
- SMTP server credentials or Slack webhook URL for alerting
- Administrative access for placing canaries in system directories

## Workflow

### Step 1: Generate Canary Files

Create decoy files with realistic names and content that attract ransomware scanners. Files should have names like `Passwords.xlsx`, `Financial_Report_2026.docx`, `backup_credentials.csv` and contain plausible-looking but fake data. Place them in directories ransomware typically targets first: user desktops, Documents folders, network share roots, and backup paths.

### Step 2: Deploy Filesystem Monitor

Use Python's watchdog library with custom `FileSystemEventHandler` that watches canary file paths. handler triggers on `on_modified`, `on_deleted`, `on_moved`, and `on_created` events for canary files. Any legitimate user or process should never touch these files, so any interaction is high-confidence indicator of ransomware or unauthorized access.

### Step 3: Configure Alert Pipeline

Wire filesystem monitor to multiple alert channels: email via SMTP, Slack webhook POST, syslog forwarding to SIEM, and local log file. Include triggering event type, file path, timestamp, and process information (when available) in alert payloads.

### Step 4: Validate and Test

Simulate ransomware behavior by programmatically modifying, renaming, and deleting canary files to verify detection pipeline fires correctly. Measure time-to-alert and validate alert delivery across all configured channels.

## Key Concepts

| Term | Definition |
|------|------------|
| **Canary File** | decoy file placed in monitored directory that triggers alert when accessed, modified, or deleted |
| **Watchdog** | Python library that monitors filesystem events using OS-native APIs (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows) |
| **Honey File** | Synonym for canary file; fake document designed to attract and detect malicious activity |
| **Entropy Check** | Measuring randomness in file content to detect encryption (ransomware produces high-entropy output) |

## Tools & Systems

- **watchdog**: Python filesystem monitoring library using OS-native event APIs
- **smtplib**: Python standard library for SMTP email alerting
- **requests**: HTTP library for Slack webhook integration
- **hashlib**: SHA-256 hashing for canary file integrity verification
- **psutil**: Process information gathering when canary file access is detected

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-ransomware-canary-files
