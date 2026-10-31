---
name: implementing-file-integrity-monitoring-with-aide
description: Configures AIDE (Advanced Intrusion Detection Environment) for file integrity monitoring on Linux, covering baseline database creation, scheduled integrity checks via cron, change detection, and alerting on unauthorized modifications.
subdomain: endpoint-security
facing: defense
mitre_attack:
- T1055
- T1547
- T1059
- T1036
nist_csf:
- PR.PS-01
- PR.PS-02
- DE.CM-01
- PR.IR-01
upstream: implementing-file-integrity-monitoring-with-aide@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- AIDE installed on target Linux system (apt install aide / yum install aide)
- Root or sudo access for file system scanning
- Python 3.8+ with standard library

## Steps

1. **Generate AIDE Configuration** — Create aide.conf with monitoring rules for critical directories (/etc, /bin, /sbin, /usr/bin, /boot)
2. **Initialize Baseline Database** — Run aide --init to create initial file integrity baseline
3. **Run Integrity Check** — Execute aide --check to compare current state against baseline
4. **Parse Change Report** — Extract added, removed, and changed files from AIDE output
5. **Configure Automated Monitoring** — Generate cron job for scheduled integrity checks
6. **Generate Compliance Report** — Produce structured report of all file changes with severity classification

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-file-integrity-monitoring-with-aide
