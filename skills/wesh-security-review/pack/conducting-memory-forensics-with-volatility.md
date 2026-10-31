---
name: conducting-memory-forensics-with-volatility
description: Performs memory forensics analysis using Volatility 3 to extract evidence of malware execution, process injection, network connections, and credential theft from RAM dumps captured during incident response.
subdomain: incident-response
facing: defense
mitre_attack:
- T1055
- T1003.001
- T1014
- T1059.001
- T1620
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
upstream: conducting-memory-forensics-with-volatility@54a7988 Apache-2.0, modified by wesh
---
Not for: analyzing disk images or file system artifacts; use disk forensics tools (Autopsy, FTK) for those tasks.

## Prerequisites

- Memory acquisition tool deployed or available: WinPmem, Magnet RAM Capture, DumpIt, or AVML (Linux)
- Volatility 3 installed with Python 3.8+ and required symbol tables
- Sufficient storage for memory dumps (equal to system RAM size, typically 8-64 GB)
- YARA rules for malware detection in memory (Florian Roth's signature-base, custom rules)
- Reference baseline of normal processes and DLLs for OS version being analyzed
- Chain of custody documentation for evidence handling

## Workflow

### Step 1: Acquire Memory Image

Capture RAM from target system using forensically sound method:

**Windows (WinPmem):**
```
winpmem_mini_x64.exe output.raw
```

**Windows (Magnet RAM Capture):**
```
MagnetRAMCapture.exe
# GUI-based, select output path, generates .raw file
```

**Windows (DumpIt):**
```
DumpIt.exe
# Creates memory dump in current directory automatically
```

**Linux (AVML - Acquire Volatile Memory for Linux):**
```
./avml output.lime
```

Document acquisition metadata:
```
Acquisition Record:
━━━━━━━━━━━━━━━━━
Target Host:      WKSTN-042
RAM Size:         16 GB
Dump File:        WKSTN-042_20251115_1445.raw
Dump Size:        16,843,612,160 bytes
SHA-256:          a4b3c2d1e5f6...
Acquisition Tool: WinPmem 4.0
Acquired By:      [Analyst Name]
Timestamp:        2025-11-15T14:45:00Z
```

### Step 2: Identify Operating System and Profile

Volatility 3 automatically identifies OS, but verify:

```bash
# Get system information
vol -f WKSTN-042_20251115_1445.raw windows.info
# Output includes:
# OS: Windows 10 22H2 (Build 19045.3693)
# Kernel Base: 0xf8066c200000
# DTB: 0x1aa000
# Symbols: ntkrnlmp.pdb
```

### Step 3: Analyze Running Processes

Examine process tree for suspicious activity:

```bash
# List all running processes
vol -f memory.raw windows.pslist
# Show process tree (parent-child relationships)
vol -f memory.raw windows.pstree
# Scan for hidden/unlinked processes (rootkit detection)
vol -f memory.raw windows.psscan
# Compare pslist vs psscan to find hidden processes
# Processes in psscan but NOT in pslist may be hidden by rootkits
```

Key indicators of compromise in process analysis:
- `svchost.exe` running without `-k` parameter or with wrong parent (should be `services.exe`)
- `csrss.exe` or `lsass.exe` with abnormal parent process
- Processes with misspelled names (`scvhost.exe`, `lssas.exe`)
- Unusual processes spawned by `outlook.exe`, `winword.exe`, or `excel.exe`
- Multiple instances of processes that should be singletons (`lsass.exe`, `smss.exe`)

### Step 4: Investigate Network Connections

Extract active and recently closed network connections:

```bash
# List all network connections
vol -f memory.raw windows.netscan
# Focus output fields:
# Offset    Proto  LocalAddr     LocalPort  ForeignAddr    ForeignPort  State     PID  Owner
# 0xe10...  TCPv4  10.1.5.42     49721     185.220.101.42  443         ESTAB     3847  update.exe
```

Cross-reference suspicious connections with process tree to identify C2 communications. Look for:
- Connections to external IPs from unexpected processes
- High port numbers connecting to port 443/80 from non-browser processes
- Connections from `svchost.exe` or system processes to external IPs

### Step 5: Detect Process Injection and Malware

Use malfind to identify injected code and memory-resident malware:

```bash
# Detect injected code in processes
vol -f memory.raw windows.malfind
# Output shows:
# PID  Process       Start      End        Tag  Protection  Hexdump/Disassembly
# 3847 explorer.exe  0x2a10000  0x2a14000  VadS PAGE_EXECUTE_READWRITE
# MZ header detected - injected PE
# Dump suspicious process memory
vol -f memory.raw windows.memmap --pid 3847 --dump
# List DLLs loaded by a suspicious process
vol -f memory.raw windows.dlllist --pid 3847
# Scan memory with YARA rules
vol -f memory.raw windows.yarascan --yara-file malware_rules.yar
```

### Step 6: Extract Credentials and Artifacts

Recover sensitive data from memory:

```bash
# Dump registry hives from memory (for password hash extraction)
vol -f memory.raw windows.registry.hivelist
vol -f memory.raw windows.hashdump
# Extract command line history
vol -f memory.raw windows.cmdline
# List handles (files, registry keys, mutexes)
vol -f memory.raw windows.handles --pid 3847
# Extract clipboard contents
vol -f memory.raw windows.clipboard
# Dump cached files from memory
vol -f memory.raw windows.dumpfiles --pid 3847
```

### Step 7: Generate Forensic Report

Compile findings into structured analysis report documenting all evidence extracted from memory:

- Process anomalies with PIDs, parent processes, and timestamps
- Network connections with associated process context
- Injected code regions with memory protection flags
- Extracted IOCs (hashes, IPs, domains, mutexes, registry keys)
- YARA rule matches with rule names and match offsets
- Credential exposure (hashes found, accounts at risk)

## Key Concepts

| Term | Definition |
|------|------------|
| **Volatile Evidence** | Data that exists only in RAM and is lost when system is powered off; includes running processes, network connections, encryption keys |
| **Process Injection** | Technique where malware inserts code into legitimate process's memory space to evade detection (malfind detects this) |
| **EPROCESS** | Windows kernel data structure representing process; psscan searches for these structures even when unlinked from active process list |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure tracking memory regions allocated to process; malfind examines VADs for executable but non-file-backed regions |
| **Symbol Tables** | OS-specific data structures that Volatility 3 uses to parse memory; downloaded automatically based on detected OS version |
| **PAGE_EXECUTE_READWRITE** | Memory protection flag indicating region is readable, writable, and executable; common indicator of injected malicious code |
| **Memory-Resident Malware** | Malware that operates entirely in RAM without writing persistent files to disk, making it invisible to traditional disk-based antivirus |

## Tools & Systems

- **Volatility 3**: Primary open-source memory forensics framework; Python 3 rewrite with automatic symbol resolution
- **WinPmem / DumpIt / Magnet RAM Capture**: Memory acquisition tools for Windows systems
- **AVML (Acquire Volatile Memory for Linux)**: Microsoft's open-source Linux memory acquisition tool
- **YARA**: Pattern matching engine for scanning memory dumps against malware signatures and behavioral rules
- **MemProcFS**: Memory analysis tool that presents memory as virtual file system for intuitive browsing

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-memory-forensics-with-volatility
