---
name: analyzing-windows-prefetch-with-python
description: Parse Windows Prefetch (.pf) files with the windowsprefetch Python library to reconstruct application execution history, run counts, and accessed file/volume lists.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1036.005
- T1070.004
- T1070
- T1003.001
- T1057
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: analyzing-windows-prefetch-with-python@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9+ with `windowsprefetch` library (pip install windowsprefetch)
- Windows Prefetch files from C:\Windows\Prefetch\ (versions 17-30 supported)
- Understanding of Windows Prefetch file naming conventions (EXECUTABLE-HASH.pf)

## Steps

### Step 1: Collect Prefetch Files
Gather .pf files from target system's C:\Windows\Prefetch\ directory.

### Step 2: Parse Execution History
Extract executable name, run count, last execution timestamps, and volume information.

### Step 3: Detect Suspicious Execution
Flag known attack tools (mimikatz, psexec, etc.), renamed binaries, and unusual execution patterns.

### Step 4: Build Execution Timeline
Reconstruct chronological execution timeline from all Prefetch files.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-windows-prefetch-with-python
