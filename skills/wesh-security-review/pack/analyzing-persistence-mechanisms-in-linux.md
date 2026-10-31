---
name: analyzing-persistence-mechanisms-in-linux
description: Scan Linux systems for persistence mechanisms including crontab/systemd entries, LD_PRELOAD injection, shell profile modifications (.bashrc, .profile), and SSH authorized_keys backdoors, then correlate findings with auditd logs into an installation timeline.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1053.003
- T1543.002
- T1574.006
- T1546.004
- T1098.004
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: analyzing-persistence-mechanisms-in-linux@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Root or sudo access on target Linux system (or forensic image)
- auditd configured with file watch rules on persistence paths
- Python 3.8+ with standard library (os, subprocess, json)
- Optional: OSSEC/Wazuh agent for file integrity monitoring alerts

## Steps

1. **Scan Crontab Entries** — Enumerate all user crontabs, /etc/cron.d/, /etc/cron.daily/, and anacron jobs for suspicious commands
2. **Audit Systemd Units** — Check /etc/systemd/system/ and ~/.config/systemd/user/ for non-package-managed service and timer units
3. **Detect LD_PRELOAD Hijacking** — Check /etc/ld.so.preload and LD_PRELOAD environment variable for injected shared libraries
4. **Inspect Shell Profiles** — Scan .bashrc, .bash_profile, .profile, /etc/profile.d/ for injected commands or reverse shells
5. **Check SSH Authorized Keys** — Audit all authorized_keys files for unauthorized public keys with command restrictions
6. **Correlate Auditd Logs** — Search auditd logs for file modification events on persistence paths to build installation timeline
7. **Generate Persistence Report** — Produce risk-scored report of all discovered persistence mechanisms

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-persistence-mechanisms-in-linux
