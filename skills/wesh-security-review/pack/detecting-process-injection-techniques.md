---
name: detecting-process-injection-techniques
description: Detects and analyzes process injection techniques used by malware including classic DLL injection, process hollowing, APC injection, thread hijacking, and reflective loading.
subdomain: malware-analysis
facing: defense
mitre_attack:
- T1027
- T1055
- T1140
- T1497
- T1070
nist_csf:
- DE.AE-02
- RS.AN-03
- ID.RA-01
- DE.CM-01
upstream: detecting-process-injection-techniques@54a7988 Apache-2.0, modified by wesh
---
Not for: standard DLL loading analysis; injection implies unauthorized code placement in a process without that process's cooperation.

## Prerequisites

- Volatility 3 for memory forensics analysis of injection artifacts
- Sysmon configured with Event IDs 8 (CreateRemoteThread) and 10 (ProcessAccess)
- API Monitor or x64dbg for observing injection API calls in real-time
- Process Hacker or Process Explorer for inspecting process memory regions
- Understanding of Windows memory management (VirtualAlloc, VAD, page protections)
- Isolated analysis environment for safe malware execution and monitoring

## Workflow

### Step 1: Identify Injection via Memory Forensics

Use Volatility to detect injected code in process memory:

```bash
# malfind: Primary injection detection plugin
vol3 -f memory.dmp windows.malfind
# malfind detects:
# - Memory regions with PAGE_EXECUTE_READWRITE (RWX) protection
# - PE headers (MZ signature) in non-image VAD entries
# - Executable memory not backed by a file on disk
# Filter by specific process
vol3 -f memory.dmp windows.malfind --pid 852
# Dump injected memory regions for analysis
vol3 -f memory.dmp windows.malfind --dump
# Check VAD (Virtual Address Descriptor) tree for anomalies
vol3 -f memory.dmp windows.vadinfo --pid 852
# Detect hollowed processes (mapped image doesn't match disk)
vol3 -f memory.dmp windows.hollowfind
```

### Step 2: Classify Injection Technique

Identify which injection method was used based on artifacts:

```
Process Injection Techniques and Detection Artifacts:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Classic DLL Injection
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
   Artifact: Loaded DLL in target process not present in known-good baseline
   Detection: New DLL in dlllist not matching disk hash, CreateRemoteThread event
2. Process Hollowing (RunPE)
   APIs: CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx ->
         WriteProcessMemory -> SetThreadContext -> ResumeThread
   Artifact: Process image in memory doesn't match file on disk
   Detection: hollowfind plugin, mismatched PE headers vs disk file
3. APC Injection
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> QueueUserAPC
   Artifact: Alertable thread has queued APC pointing to injected code
   Detection: Thread start addresses outside known modules
4. Thread Hijacking
   APIs: OpenProcess -> VirtualAllocEx -> WriteProcessMemory ->
         SuspendThread -> GetThreadContext -> SetThreadContext -> ResumeThread
   Artifact: Thread instruction pointer changed to injected code
   Detection: Thread context modification, EIP/RIP outside module boundaries
5. Reflective DLL Injection
   APIs: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread (to reflective loader)
   Artifact: DLL loaded in memory but NOT in loaded module list
   Detection: malfind (PE in non-image memory), module not in ldrmodules
6. Process Doppelganging
   APIs: NtCreateTransaction -> NtCreateFile(transacted) -> NtWriteFile ->
         NtCreateSection -> NtRollbackTransaction -> NtCreateProcessEx
   Artifact: Process created from transacted file that was rolled back
   Detection: Process with no corresponding file on disk
7. AtomBombing
   APIs: GlobalAddAtom -> NtQueueApcThread (with GlobalGetAtomName)
   Artifact: Code stored in global atom table, APC triggers copy to target
   Detection: Unusual atom table entries, APC injection indicators
```

### Step 3: Detect Injection via Sysmon Events

Analyze Sysmon and Windows Event Log data:

```bash
# Sysmon Event ID 8: CreateRemoteThread
# Detect when one process creates a thread in another
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=8]]" /f:text /c:20
# Sysmon Event ID 10: ProcessAccess
# Detect suspicious access rights to other processes
# DesiredAccess containing PROCESS_VM_WRITE (0x0020) + PROCESS_CREATE_THREAD (0x0002)
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=10]]" /f:text /c:20
# Sysmon Event ID 1: Process Creation
# Detect process hollowing via suspicious parent-child relationships
wevtutil qe "Microsoft-Windows-Sysmon/Operational" \
  /q:"*[System[EventID=1]]" /f:text /c:20
```

```python
# Parse Sysmon events for injection indicators
import xml.etree.ElementTree as ET
import subprocess
# Query CreateRemoteThread events
result = subprocess.run(
    ["wevtutil", "qe", "Microsoft-Windows-Sysmon/Operational",
     "/q:*[System[EventID=8]]", "/f:xml", "/c:100"],
    capture_output=True, text=True
)
suspicious_injections = []
for event_xml in result.stdout.split("</Event>"):
    if not event_xml.strip():
        continue
    try:
        root = ET.fromstring(event_xml + "</Event>")
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        data = {}
        for d in root.findall(".//e:EventData/e:Data", ns):
            data[d.get("Name")] = d.text
        source = data.get("SourceImage", "")
        target = data.get("TargetImage", "")
        # Flag injections from unusual sources into system processes
        system_procs = ["svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe"]
        if any(p in target.lower() for p in system_procs):
            if not any(p in source.lower() for p in ["csrss.exe", "services.exe", "lsass.exe"]):
                print(f"[!] Suspicious injection: {source} -> {target}")
                suspicious_injections.append(data)
    except:
        pass
```

### Step 4: Analyze Injected Code

Examine injected payload to understand its purpose:

```bash
# Dump injected code from Volatility malfind
vol3 -f memory.dmp windows.malfind --pid 852 --dump
# Analyze the dumped region
file malfind.*.dmp
# If it contains a PE (MZ header), analyze as a standalone executable
python3 << 'PYEOF'
import pefile
# Attempt to parse as PE
try:
    pe = pefile.PE("malfind.852.0x400000.dmp")
    print("Injected PE detected!")
    print(f"  Architecture: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
    print(f"  Imports:")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"    {entry.dll.decode()}: {len(entry.imports)} functions")
except:
    print("Not a valid PE - likely shellcode")
    # Analyze as shellcode
    with open("malfind.852.0x400000.dmp", "rb") as f:
        shellcode = f.read()
    print(f"  Size: {len(shellcode)} bytes")
    print(f"  First bytes: {shellcode[:32].hex()}")
PYEOF
# Disassemble shellcode
python3 -c "
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
with open('malfind.852.0x400000.dmp', 'rb') as f:
    code = f.read()[:256]
md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(code, 0x400000):
    print(f'  0x{insn.address:X}: {insn.mnemonic} {insn.op_str}')
"
# Scan with YARA for known payloads
vol3 -f memory.dmp yarascan.YaraScan --pid 852 --yara-file malware_rules.yar
```

### Step 5: Map to MITRE ATT&CK

Classify detected techniques in ATT&CK framework:

```
MITRE ATT&CK Process Injection Sub-Techniques (T1055):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
T1055.001  Dynamic-link Library Injection
T1055.002  Portable Executable Injection
T1055.003  Thread Execution Hijacking
T1055.004  Asynchronous Procedure Call (APC)
T1055.005  Thread Local Storage
T1055.008  Ptrace System Calls (Linux)
T1055.009  Proc Memory (/proc/pid/mem - Linux)
T1055.011  Extra Window Memory Injection
T1055.012  Process Hollowing
T1055.013  Process Doppelganging
T1055.014  VDSO Hijacking (Linux)
T1055.015  ListPlanting
```

### Step 6: Create Detection Signatures

Build detection rules for identified technique:

```yaml
# Sigma rule for CreateRemoteThread injection
title: Suspicious CreateRemoteThread into System Process
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetImage|endswith:
            - '\svchost.exe'
            - '\explorer.exe'
            - '\lsass.exe'
    filter:
        SourceImage|endswith:
            - '\csrss.exe'
            - '\services.exe'
            - '\svchost.exe'
    condition: selection and not filter
level: high
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Process Injection** | Technique of executing code within address space of another process, typically to evade detection and inherit target's trust level |
| **Process Hollowing** | Creating legitimate process in suspended state, unmapping its memory, writing malicious code, and resuming execution to masquerade as legitimate process |
| **Reflective DLL Injection** | Loading DLL into process's memory without using Windows loader, so DLL does not appear in loaded module list |
| **APC Injection** | Queuing Asynchronous Procedure Call to thread in target process, causing it to execute injected code when thread enters alertable state |
| **VAD (Virtual Address Descriptor)** | Windows kernel structure describing memory regions in process; anomalous VAD entries (RWX permissions, non-image PE) indicate injection |
| **CreateRemoteThread** | Windows API creating thread in another process; primary mechanism for classic DLL injection and many other injection techniques |
| **PAGE_EXECUTE_READWRITE** | Memory protection allowing read, write, and execute; rarely used by legitimate applications, common indicator of injected code |

## Tools & Systems

- **Volatility (malfind)**: Memory forensics plugin detecting injected code through VAD analysis and PE header scanning in non-image memory regions
- **Sysmon**: System Monitor providing detailed Windows event logging including CreateRemoteThread (EID 8) and ProcessAccess (EID 10)
- **Process Hacker**: Advanced process management tool showing detailed memory regions, thread stacks, and injected modules
- **API Monitor**: Windows tool for monitoring and logging API calls made by processes, useful for observing injection sequences in real-time
- **pe-sieve**: Tool scanning running processes for signs of code injection, hooking, and hollowing

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-process-injection-techniques
