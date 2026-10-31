---
name: analyzing-memory-dumps-with-volatility
description: Analyzes RAM memory dumps from compromised systems using the Volatility framework to identify malicious processes, injected code, network connections, loaded modules, and extracted credentials.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1055
- T1003
- T1059
- T1620
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: analyzing-memory-dumps-with-volatility@54a7988 Apache-2.0, modified by wesh
---
Not for: disk image analysis; use Autopsy, FTK, or Sleuth Kit for disk forensics.

## Prerequisites

- Volatility 3 installed (`pip install volatility3`) with symbol tables for target OS
- Memory dump file acquired from target system (using WinPmem, LiME, or DumpIt)
- Knowledge of source OS version for correct profile/symbol selection
- Sufficient disk space (memory dumps can be 4-64 GB)
- YARA rules for scanning memory for known malware signatures
- Strings utility for extracting readable strings from memory regions

## Workflow

### Step 1: Identify Memory Dump Profile

Determine operating system and version from memory dump:

```bash
# Volatility 3: Automatic OS detection
vol3 -f memory.dmp windows.info
# List available plugins
vol3 -f memory.dmp --help
# If symbols are needed, download from:
# https://downloads.volatilityfoundation.org/volatility3/symbols/
# For Volatility 2 (legacy):
vol2 -f memory.dmp imageinfo
vol2 -f memory.dmp kdbgscan
```

### Step 2: Enumerate Running Processes

List all processes and identify suspicious entries:

```bash
# List all processes
vol3 -f memory.dmp windows.pslist
# Process tree (parent-child relationships)
vol3 -f memory.dmp windows.pstree
# Scan for hidden/unlinked processes (rootkit detection)
vol3 -f memory.dmp windows.psscan
# Compare pslist vs psscan to find hidden processes
# Processes in psscan but not pslist are potentially hidden by rootkits
# Check for process hollowing
vol3 -f memory.dmp windows.pslist --dump
# Then verify the dumped EXE matches the expected binary on disk
```

```
Suspicious Process Indicators:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- svchost.exe not spawned by services.exe (wrong parent)
- csrss.exe/lsass.exe with unusual parent process
- Multiple instances of lsass.exe (should be only one)
- Processes with misspelled names (scvhost.exe, lssas.exe)
- cmd.exe or powershell.exe spawned by WINWORD.EXE or browser
- Processes running from unusual paths (%TEMP%, %APPDATA%)
- Processes with no parent (orphaned - parent terminated)
```

### Step 3: Detect Malicious Code Injection

Scan for injected code and process hollowing:

```bash
# Detect injected code in processes (malfind)
vol3 -f memory.dmp windows.malfind
# Malfind looks for:
# - Memory regions with PAGE_EXECUTE_READWRITE protection
# - Memory regions containing PE headers (MZ/PE signature)
# - VAD (Virtual Address Descriptor) anomalies
# Dump injected memory regions for analysis
vol3 -f memory.dmp windows.malfind --dump --pid 2184
# List loaded DLLs per process
vol3 -f memory.dmp windows.dlllist --pid 2184
# Detect hollowed processes by comparing mapped image to disk
vol3 -f memory.dmp windows.hollowfind
# Scan for loaded drivers (potential rootkit drivers)
vol3 -f memory.dmp windows.driverscan
# List kernel modules
vol3 -f memory.dmp windows.modules
```

### Step 4: Analyze Network Connections

Extract active and closed network connections:

```bash
# List all network connections (active and listening)
vol3 -f memory.dmp windows.netscan
# Output columns: Offset, Protocol, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner
# Filter for established connections to external IPs
vol3 -f memory.dmp windows.netscan | grep ESTABLISHED
# For older Windows (XP/2003):
vol3 -f memory.dmp windows.netstat
# Cross-reference PIDs with process list
# Suspicious: svchost.exe connected to external IP on non-standard port
# Suspicious: notepad.exe or calc.exe with network connections
```

### Step 5: Extract Artifacts and Credentials

Recover sensitive data from memory:

```bash
# Dump process memory for a specific PID
vol3 -f memory.dmp windows.memmap --dump --pid 2184
# Extract command-line history
vol3 -f memory.dmp windows.cmdline
# Extract environment variables
vol3 -f memory.dmp windows.envars --pid 2184
# Registry analysis (extract Run keys for persistence)
vol3 -f memory.dmp windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"
# Extract hashed/cached credentials
vol3 -f memory.dmp windows.hashdump
vol3 -f memory.dmp windows.cachedump
vol3 -f memory.dmp windows.lsadump
# Extract clipboard contents
vol3 -f memory.dmp windows.clipboard
# File extraction from memory
vol3 -f memory.dmp windows.filescan | grep -i "payload\|malware\|suspicious"
vol3 -f memory.dmp windows.dumpfiles --virtaddr 0xFA8001234560
```

### Step 6: Scan Memory with YARA Rules

Apply YARA signatures to detect known malware in memory:

```bash
# Scan entire memory dump with YARA rules
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar
# Scan specific process memory
vol3 -f memory.dmp yarascan.YaraScan --yara-file malware_rules.yar --pid 2184
# Built-in YARA scan for common patterns
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule FindC2 { strings: \$s1 = \"gate.php\" condition: \$s1 }"
# Scan for encryption key material
vol3 -f memory.dmp yarascan.YaraScan --yara-rules "rule AES_Key { strings: \$sbox = { 63 7C 77 7B F2 6B 6F C5 } condition: \$sbox }"
```

### Step 7: Timeline and Report Generation

Create analysis timeline and compile findings:

```bash
# Generate comprehensive timeline
vol3 -f memory.dmp timeliner.Timeliner --output-file timeline.csv
# Timeline includes:
# - Process creation/exit times
# - Network connection timestamps
# - Registry modification times
# - File access times
# Export process list for reporting
vol3 -f memory.dmp windows.pslist --output csv > processes.csv
# Export network connections
vol3 -f memory.dmp windows.netscan --output csv > network.csv
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Memory Forensics** | Analysis of volatile memory (RAM) contents to identify running processes, network connections, and in-memory artifacts that may not exist on disk |
| **Process Hollowing** | Malware technique of creating legitimate process in suspended state, replacing its memory with malicious code, then resuming execution |
| **Malfind** | Volatility plugin detecting injected code by identifying memory regions with executable permissions and PE headers in non-image VADs |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure tracking memory regions allocated to process; anomalies in VADs indicate injection or hollowing |
| **EPROCESS** | Windows kernel structure representing process; rootkits unlink EPROCESS entries to hide processes from standard tools |
| **Pool Tag Scanning** | Memory forensics technique scanning for kernel object pool tags to find objects (processes, files, connections) even when unlinked |
| **Fileless Malware** | Malware that operates entirely in memory without creating files on disk; only detectable through memory forensics |

## Tools & Systems

- **Volatility 3**: Open-source memory forensics framework supporting Windows, Linux, and macOS memory analysis with plugin architecture
- **WinPmem**: Memory acquisition tool for Windows systems that creates raw memory dumps for offline analysis
- **LiME (Linux Memory Extractor)**: Loadable kernel module for capturing Linux system memory dumps
- **Rekall**: Alternative memory forensics framework with some unique analysis capabilities (discontinued but still useful)
- **MemProcFS**: Memory process file system allowing mounting memory dumps as file systems for intuitive analysis

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-memory-dumps-with-volatility
