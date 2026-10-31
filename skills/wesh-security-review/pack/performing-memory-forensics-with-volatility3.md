---
name: performing-memory-forensics-with-volatility3
description: Analyze volatile memory (RAM) dumps using the Volatility 3 framework to extract running processes, network connections, loaded modules, credentials, and encryption keys, and to detect process hollowing, DLL injection, or hidden processes/rootkits.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
- T1074
- T1119
- T1070
- T1059
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: performing-memory-forensics-with-volatility3@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- Python 3.7+ installed
- Volatility 3 framework installed (`pip install volatility3`)
- Memory dump in raw, ELF, or crash dump format
- Appropriate symbol tables (ISF files) for target OS version
- Sufficient disk space for analysis output (2-3x memory dump size)
- Optional: YARA rules for malware scanning in memory

## Workflow

### Step 1: Acquire Memory Dump and Install Volatility 3

```bash
# Install Volatility 3
pip install volatility3
# Or install from source for latest features
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -e .
# Download Windows symbol tables (ISF packs)
# Place in volatility3/symbols/ directory
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d /opt/volatility3/volatility3/symbols/
# Download Linux and Mac symbol packs
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
# Memory acquisition tools (for live systems):
# Windows: winpmem, DumpIt, FTK Imager
# Linux: LiME (Linux Memory Extractor)
sudo insmod lime-$(uname -r).ko "path=/cases/memory/linux_mem.lime format=lime"
# Verify the memory dump
file /cases/case-2024-001/memory/memory.raw
ls -lh /cases/case-2024-001/memory/memory.raw
```

### Step 2: Identify Operating System Profile

```bash
# Run banners plugin to identify the OS
vol -f /cases/case-2024-001/memory/memory.raw banners
# For Windows, identify the OS version
vol -f /cases/case-2024-001/memory/memory.raw windows.info
# Output example:
# Variable        Value
# Kernel Base     0xf8047e200000
# DTB             0x1ad000
# Symbols         ntkrnlmp.pdb/GUID
# Is64Bit         True
# IsPAE           False
# primary layer   Intel32e
# KdVersionBlock  0xf8047ee232c0
# Major/Minor     15.19041
# Machine Type    34404
# KeNumberProcessors 4
# SystemTime      2024-01-18 14:32:15 UTC
# NtBuildLab      19041.1.amd64fre.vb_release.191206-1406
# NtProductType   NtProductWinNt
# NtSystemRoot    C:\WINDOWS
# PE MajorOperatingSystemVersion 10
# PE MinorOperatingSystemVersion 0
# For Linux memory dumps
vol -f /cases/case-2024-001/memory/linux_mem.lime linux.info
```

### Step 3: Enumerate Processes and Detect Anomalies

```bash
# List all running processes
vol -f /cases/case-2024-001/memory/memory.raw windows.pslist | tee /cases/case-2024-001/analysis/pslist.txt
# Show process tree (parent-child relationships)
vol -f /cases/case-2024-001/memory/memory.raw windows.pstree | tee /cases/case-2024-001/analysis/pstree.txt
# Detect hidden processes using cross-view analysis
vol -f /cases/case-2024-001/memory/memory.raw windows.psscan | tee /cases/case-2024-001/analysis/psscan.txt
# Compare pslist vs psscan to find hidden processes
diff <(vol -f memory.raw windows.pslist | awk '{print $1}' | sort) \
     <(vol -f memory.raw windows.psscan | awk '{print $1}' | sort)
# List DLLs loaded by a suspicious process (PID 4532)
vol -f /cases/case-2024-001/memory/memory.raw windows.dlllist --pid 4532
# Check for process hollowing and injection
vol -f /cases/case-2024-001/memory/memory.raw windows.malfind | tee /cases/case-2024-001/analysis/malfind.txt
# Dump suspicious process memory for further analysis
vol -f /cases/case-2024-001/memory/memory.raw windows.memmap --pid 4532 --dump \
   -o /cases/case-2024-001/analysis/dumps/
```

### Step 4: Analyze Network Connections and Registry

```bash
# List active network connections
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | tee /cases/case-2024-001/analysis/netscan.txt
# Filter for established connections
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep ESTABLISHED
# Filter for listening ports
vol -f /cases/case-2024-001/memory/memory.raw windows.netscan | grep LISTENING
# Extract network connections with process mapping
vol -f /cases/case-2024-001/memory/memory.raw windows.netstat | tee /cases/case-2024-001/analysis/netstat.txt
# Dump registry hives from memory
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.hivelist
# Extract specific registry keys
vol -f /cases/case-2024-001/memory/memory.raw windows.registry.printkey \
   --key "Software\Microsoft\Windows\CurrentVersion\Run"
# Check services
vol -f /cases/case-2024-001/memory/memory.raw windows.svcscan | tee /cases/case-2024-001/analysis/services.txt
```

### Step 5: Extract Credentials and Sensitive Data

```bash
# Dump cached credentials (hashdump)
vol -f /cases/case-2024-001/memory/memory.raw windows.hashdump | tee /cases/case-2024-001/analysis/hashes.txt
# Extract LSA secrets
vol -f /cases/case-2024-001/memory/memory.raw windows.lsadump
# Dump cached domain credentials
vol -f /cases/case-2024-001/memory/memory.raw windows.cachedump
# Search for plaintext strings in process memory
vol -f /cases/case-2024-001/memory/memory.raw windows.strings --pid 4532 \
   | grep -iE '(password|credential|token|api.key)'
# Extract command history from cmd.exe/powershell
vol -f /cases/case-2024-001/memory/memory.raw windows.cmdline | tee /cases/case-2024-001/analysis/cmdline.txt
# Extract environment variables
vol -f /cases/case-2024-001/memory/memory.raw windows.envars --pid 4532
```

### Step 6: Scan for Malware with YARA Rules

```bash
# Scan memory with YARA rules
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/malware_index.yar | tee /cases/case-2024-001/analysis/yara_hits.txt
# Scan specific process memory
vol -f /cases/case-2024-001/memory/memory.raw yarascan \
   --yara-file /opt/yara-rules/apt_rules.yar --pid 4532
# Check loaded kernel modules for rootkits
vol -f /cases/case-2024-001/memory/memory.raw windows.modules | tee /cases/case-2024-001/analysis/modules.txt
# Detect unlinked/hidden modules
vol -f /cases/case-2024-001/memory/memory.raw windows.modscan | tee /cases/case-2024-001/analysis/modscan.txt
# Check for SSDT hooks (System Service Descriptor Table)
vol -f /cases/case-2024-001/memory/memory.raw windows.ssdt | grep -v "ntoskrnl\|win32k"
# Dump a suspicious executable from memory
vol -f /cases/case-2024-001/memory/memory.raw windows.dumpfiles --pid 4532 \
   -o /cases/case-2024-001/analysis/extracted/
```

### Step 7: Compile Findings into Report

```bash
# Generate comprehensive analysis summary
echo "=== MEMORY FORENSICS REPORT ===" > /cases/case-2024-001/analysis/memory_report.txt
echo "Image: memory.raw" >> /cases/case-2024-001/analysis/memory_report.txt
echo "OS: Windows 10 Build 19041" >> /cases/case-2024-001/analysis/memory_report.txt
echo "" >> /cases/case-2024-001/analysis/memory_report.txt
echo "--- Suspicious Processes ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/malfind.txt >> /cases/case-2024-001/analysis/memory_report.txt
echo "--- Network Connections ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/netscan.txt >> /cases/case-2024-001/analysis/memory_report.txt
echo "--- YARA Matches ---" >> /cases/case-2024-001/analysis/memory_report.txt
cat /cases/case-2024-001/analysis/yara_hits.txt >> /cases/case-2024-001/analysis/memory_report.txt
# Calculate hash of the memory dump for integrity
sha256sum /cases/case-2024-001/memory/memory.raw >> /cases/case-2024-001/analysis/memory_report.txt
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Volatile data | Information that exists only in RAM and is lost when power is removed |
| Process hollowing | Technique where malware replaces legitimate process memory with malicious code |
| DLL injection | Loading unauthorized DLLs into running process address space |
| EPROCESS | Windows kernel structure representing process; basis for process listing |
| Pool scanning | Searching memory for kernel object signatures to find hidden artifacts |
| VAD (Virtual Address Descriptor) | Memory management structure tracking process virtual memory regions |
| ISF (Intermediate Symbol Format) | Volatility 3 symbol table format for OS-specific structure definitions |
| Malfind | Plugin detecting injected code by examining VAD permissions and content |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Volatility 3 | Primary open-source memory forensics framework |
| LiME | Linux Memory Extractor for acquiring Linux RAM dumps |
| WinPmem | Windows physical memory acquisition driver |
| DumpIt | Comae one-click Windows memory dump utility |
| YARA | Pattern matching engine for malware signature scanning |
| Rekall | Alternative memory forensics framework (Google) |
| MemProcFS | Memory process file system for memory analysis |
| strings | Extract printable strings from binary memory dumps |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-memory-forensics-with-volatility3
