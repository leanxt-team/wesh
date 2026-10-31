---
name: detecting-rootkit-activity
description: Detects rootkit presence on compromised systems by identifying hidden processes, hooked system calls, modified kernel structures, and covert network connections using Volatility memory forensics, cross-view detection, and tools like GMER, rkhunter, chkrootkit, and RootkitRevealer.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1014
- T1547.006
- T1564.001
- T1574.006
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: detecting-rootkit-activity@54a7988 Apache-2.0, modified by wesh
---
Not for: as a first-line detection method; start with standard malware triage and escalate to rootkit analysis when hiding behavior is suspected.

## Prerequisites

- Volatility 3 for memory forensics and kernel structure analysis
- GMER or Rootkit Revealer (Windows) for live system scanning
- rkhunter and chkrootkit (Linux) for filesystem and process integrity checks
- Sysinternals tools (Process Explorer, Autoruns, RootkitRevealer) for Windows analysis
- Memory dump from suspected system (WinPmem, LiME)
- Clean baseline of OS for comparison (known-good kernel module hashes)

## Workflow

### Step 1: Cross-View Detection for Hidden Processes

Compare process lists from different data sources to find discrepancies:

```bash
# Volatility: Compare process enumeration methods
# pslist - walks ActiveProcessLinks (EPROCESS linked list - what rootkits manipulate)
vol3 -f memory.dmp windows.pslist > pslist_output.txt
# psscan - scans physical memory for EPROCESS pool tags (rootkit-resistant)
vol3 -f memory.dmp windows.psscan > psscan_output.txt
# Compare outputs to find hidden processes
python3 << 'PYEOF'
pslist_pids = set()
psscan_pids = set()
with open("pslist_output.txt") as f:
    for line in f:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            pslist_pids.add(int(parts[1]))
with open("psscan_output.txt") as f:
    for line in f:
        parts = line.split()
        if len(parts) > 1 and parts[1].isdigit():
            psscan_pids.add(int(parts[1]))
hidden = psscan_pids - pslist_pids
if hidden:
    print(f"[!] HIDDEN PROCESSES DETECTED (in psscan but not pslist):")
    for pid in hidden:
        print(f"    PID: {pid}")
else:
    print("[*] No hidden processes detected via cross-view analysis")
PYEOF
```

### Step 2: Detect System Call Hooking

Identify hooks in System Service Descriptor Table (SSDT) and Import Address Tables:

```bash
# Check SSDT for hooked system calls
vol3 -f memory.dmp windows.ssdt
# Identify hooks pointing outside ntoskrnl.exe or win32k.sys
vol3 -f memory.dmp windows.ssdt | grep -v "ntoskrnl\|win32k"
# Check for Inline hooks (detour patching)
vol3 -f memory.dmp windows.apihooks --pid 4  # System process
# IDT (Interrupt Descriptor Table) analysis
vol3 -f memory.dmp windows.idt
# Check for IRP (I/O Request Packet) hooking on drivers
vol3 -f memory.dmp windows.driverscan
vol3 -f memory.dmp windows.driverirp
```

```
Types of Rootkit Hooks:
━━━━━━━━━━━━━━━━━━━━━
SSDT Hook:         Modifies System Service Descriptor Table entries to redirect
                   system calls through rootkit code (filters process/file listings)
IAT Hook:          Patches Import Address Table of a process to intercept API calls
                   before they reach the kernel
Inline Hook:       Overwrites the first bytes of a function with a JMP to rootkit code
                   (detour/trampoline technique)
IRP Hook:          Intercepts I/O Request Packets to filter disk/network operations
                   at the driver level
DKOM:              Direct Kernel Object Manipulation - unlinking structures like
                   EPROCESS from the ActiveProcessLinks list without hooking
```

### Step 3: Analyze Kernel Modules and Drivers

Identify unauthorized kernel drivers that may be rootkit components:

```bash
# List all loaded kernel modules
vol3 -f memory.dmp windows.modules
# Scan for drivers in memory (including hidden/unlinked)
vol3 -f memory.dmp windows.driverscan
# Compare module lists to find hidden drivers
vol3 -f memory.dmp windows.modscan > modscan.txt
vol3 -f memory.dmp windows.modules > modules.txt
# Check driver signatures and verify against known-good baselines
vol3 -f memory.dmp windows.verinfo
# Dump suspicious driver for static analysis
vol3 -f memory.dmp windows.moddump --base 0xFFFFF80012340000 --dump
```

### Step 4: Detect File and Registry Hiding

Identify files and registry keys hidden by rootkit:

```bash
# Linux rootkit detection with rkhunter
rkhunter --check --skip-keypress --report-warnings-only
# chkrootkit scanning
chkrootkit -q
# Windows: Compare filesystem views
# Live system file listing vs Volatility filescan
vol3 -f memory.dmp windows.filescan > mem_files.txt
# Check for hidden registry keys
vol3 -f memory.dmp windows.registry.hivelist
vol3 -f memory.dmp windows.registry.printkey --key "SYSTEM\CurrentControlSet\Services"
# Look for hidden services (loaded but not in service registry)
vol3 -f memory.dmp windows.svcscan | grep -i "kernel"
```

### Step 5: Network Connection Analysis

Find hidden network connections and backdoors:

```bash
# Memory-based network connection enumeration
vol3 -f memory.dmp windows.netscan
# Compare with live netstat (if available) to find hidden connections
# Hidden connections: present in memory but not shown by netstat
# Look for raw sockets (often used by rootkits for covert communication)
vol3 -f memory.dmp windows.netscan | grep RAW
# Check for network filter drivers (NDIS hooks)
vol3 -f memory.dmp windows.driverscan | grep -i "ndis\|tcpip\|afd"
# Analyze callback routines registered by drivers
vol3 -f memory.dmp windows.callbacks
```

### Step 6: Integrity Verification

Verify system file and kernel integrity:

```bash
# Check kernel code integrity (compare in-memory kernel to on-disk copy)
vol3 -f memory.dmp windows.moddump --base 0xFFFFF80070000000 --dump
# Compare SHA-256 of dumped ntoskrnl.exe with known-good copy
# Windows: System File Checker (on live system)
sfc /scannow
# Linux: Package integrity verification
rpm -Va  # RPM-based systems
debsums -c  # Debian-based systems
# Compare critical system binaries
find /bin /sbin /usr/bin /usr/sbin -type f -exec sha256sum {} \; > current_hashes.txt
# Compare against baseline: diff baseline_hashes.txt current_hashes.txt
# YARA scan for known rootkit signatures
vol3 -f memory.dmp yarascan.YaraScan --yara-file rootkit_rules.yar
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Rootkit** | Malware designed to maintain persistent, privileged access while hiding its presence from system administrators and security tools |
| **DKOM** | Direct Kernel Object Manipulation; technique of modifying kernel data structures (e.g., unlinking EPROCESS) to hide objects without hooking |
| **SSDT Hooking** | Replacing entries in System Service Descriptor Table to intercept and filter system call results (hide processes, files, connections) |
| **Inline Hooking** | Patching first instructions of function with jump to rootkit code; rootkit can filter function output before returning |
| **Cross-View Detection** | Comparing results from multiple enumeration methods (linked list walk vs memory scan) to identify discrepancies caused by hiding |
| **Kernel Driver** | Code running in kernel mode (Ring 0) with full system access; rootkits use malicious drivers to gain kernel-level control |
| **Bootkits** | Rootkits that infect boot process (MBR, VBR, or UEFI firmware) to load before operating system and security tools |

## Tools & Systems

- **Volatility**: Memory forensics framework providing cross-view detection, SSDT analysis, and kernel structure inspection for rootkit detection
- **GMER**: Free Windows rootkit detection tool scanning for SSDT hooks, IDT hooks, IRP hooks, and hidden processes/files/registry
- **rkhunter**: Linux rootkit detection tool checking for known rootkit signatures, suspicious files, and system binary modifications
- **chkrootkit**: Linux tool for detecting rootkit presence through signature-based and anomaly-based checks
- **Sysinternals RootkitRevealer**: Microsoft tool comparing Windows API results with raw filesystem/registry scans to find discrepancies

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-rootkit-activity
