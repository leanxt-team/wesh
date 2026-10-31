---
name: analyzing-linux-kernel-rootkits
description: Detect kernel-level rootkits in Linux memory dumps using Volatility3 linux plugins (check_syscall, lsmod, hidden_modules), rkhunter system scanning, and /proc vs /sys discrepancy analysis to identify hooked syscalls, hidden kernel modules, and tampered system structures.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1014
- T1547.006
- T1564.001
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: analyzing-linux-kernel-rootkits@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Volatility3 installed (pip install volatility3)
- Linux memory dump (acquired via LiME, AVML, or /proc/kcore)
- Volatility3 Linux symbol table (ISF) matching target kernel version
- rkhunter and chkrootkit for live system scanning
- Reference known-good kernel image for comparison

## Steps

### Step 1: Acquire Memory Dump
Capture Linux physical memory using LiME kernel module or AVML for cloud instances.

### Step 2: Analyze with Volatility3
Run linux.check_syscall, linux.lsmod, linux.hidden_modules, and linux.check_idt plugins to detect rootkit artifacts.

### Step 3: Cross-View Analysis
Compare module lists from /proc/modules, lsmod, and /sys/module to identify modules hidden from one view but present in another.

### Step 4: Live System Scanning
Run rkhunter and chkrootkit to detect known rootkit signatures, suspicious files, and modified system binaries.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-linux-kernel-rootkits
