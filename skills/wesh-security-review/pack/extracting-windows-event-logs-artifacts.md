---
name: extracting-windows-event-logs-artifacts
description: Extract, parse, and analyze Windows Event Logs (EVTX) using Chainsaw, Hayabusa, and EvtxECmd to detect lateral movement, persistence, and privilege escalation.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
- T1074
- T1119
- T1070
- T1021
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: extracting-windows-event-logs-artifacts@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- Windows Event Log files (EVTX format) from forensic image or live system
- Chainsaw, Hayabusa, or EvtxECmd for parsing and detection
- Sigma rules for automated threat detection
- Understanding of critical Windows Event IDs
- Python with python-evtx or evtx library for custom parsing
- PowerShell for live system analysis (if applicable)

## Workflow

### Step 1: Collect Windows Event Log Files

```bash
# Extract EVTX files from forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence
mkdir -p /cases/case-2024-001/evtx/
cp /mnt/evidence/Windows/System32/winevt/Logs/*.evtx /cases/case-2024-001/evtx/
# Key event logs to prioritize
# Security.evtx - Authentication, authorization, audit events
# System.evtx - System services, drivers, hardware events
# Application.evtx - Application errors and events
# Microsoft-Windows-Sysmon%4Operational.evtx - Detailed process/network monitoring
# Microsoft-Windows-PowerShell%4Operational.evtx - PowerShell activity
# Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx - RDP sessions
# Microsoft-Windows-TaskScheduler%4Operational.evtx - Scheduled tasks
# Microsoft-Windows-WinRM%4Operational.evtx - Windows Remote Management
# Microsoft-Windows-Bits-Client%4Operational.evtx - BITS transfers
# Microsoft-Windows-Windows Defender%4Operational.evtx - AV detections
# List available log files and sizes
ls -lhS /cases/case-2024-001/evtx/ | head -20
# Hash for integrity
sha256sum /cases/case-2024-001/evtx/*.evtx > /cases/case-2024-001/evtx/evtx_hashes.txt
```

### Step 2: Run Chainsaw for Sigma-Based Detection

```bash
# Install Chainsaw
wget https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip
unzip chainsaw_all_platforms+rules.zip -d /opt/chainsaw
# Run Chainsaw with bundled Sigma rules
/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --output /cases/case-2024-001/analysis/chainsaw_results.txt
# Run with CSV output for easier analysis
/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --csv \
   --output /cases/case-2024-001/analysis/chainsaw_results/
# Run with JSON output
/opt/chainsaw/chainsaw hunt /cases/case-2024-001/evtx/ \
   -s /opt/chainsaw/sigma/rules/ \
   --mapping /opt/chainsaw/mappings/sigma-event-logs-all.yml \
   --json \
   --output /cases/case-2024-001/analysis/chainsaw_results.json
# Search for specific keywords
/opt/chainsaw/chainsaw search /cases/case-2024-001/evtx/ \
   -s "mimikatz" --json
# Search for specific event IDs
/opt/chainsaw/chainsaw search /cases/case-2024-001/evtx/ \
   -e 4688 --json | head -100
```

### Step 3: Run Hayabusa for Fast Timeline Generation

```bash
# Install Hayabusa
wget https://github.com/Yamato-Security/hayabusa/releases/latest/download/hayabusa-linux-x64-musl.zip
unzip hayabusa-linux-x64-musl.zip -d /opt/hayabusa
# Generate CSV timeline with all detection rules
/opt/hayabusa/hayabusa csv-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_timeline.csv \
   -p verbose
# Generate JSON timeline
/opt/hayabusa/hayabusa json-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_timeline.json
# Run with only critical and high severity detections
/opt/hayabusa/hayabusa csv-timeline \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_critical.csv \
   -p verbose \
   --min-level critical
# Generate detection summary (metrics)
/opt/hayabusa/hayabusa metrics \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/hayabusa_metrics.csv
# Logon summary
/opt/hayabusa/hayabusa logon-summary \
   -d /cases/case-2024-001/evtx/ \
   -o /cases/case-2024-001/analysis/logon_summary.csv
```

### Step 4: Parse Specific Critical Event IDs

```bash
# Extract authentication events with python-evtx
pip install evtx
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser
parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")
# Critical Event IDs mapping
critical_events = {
    '4624': 'Successful Logon',
    '4625': 'Failed Logon',
    '4634': 'Logoff',
    '4648': 'Explicit Credential Logon',
    '4672': 'Special Privileges Assigned',
    '4688': 'Process Created',
    '4689': 'Process Exited',
    '4697': 'Service Installed',
    '4698': 'Scheduled Task Created',
    '4720': 'User Account Created',
    '4724': 'Password Reset Attempted',
    '4728': 'Member Added to Global Group',
    '4732': 'Member Added to Local Group',
    '4756': 'Member Added to Universal Group',
    '1102': 'Audit Log Cleared',
    '4688': 'New Process Created'
}
results = {eid: [] for eid in critical_events}
for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])
    if event_id in critical_events:
        event_data = data['Event'].get('EventData', {})
        results[event_id].append({
            'timestamp': data['Event']['System']['TimeCreated']['#attributes']['SystemTime'],
            'event_id': event_id,
            'description': critical_events[event_id],
            'data': event_data
        })
# Print summary
for eid, events in results.items():
    if events:
        print(f"\n[{eid}] {critical_events[eid]}: {len(events)} events")
        for e in events[:3]:
            print(f"  {e['timestamp']}: {json.dumps(e['data'], default=str)[:200]}")
        if len(events) > 3:
            print(f"  ... and {len(events)-3} more")
# Save full results
with open('/cases/case-2024-001/analysis/critical_events.json', 'w') as f:
    json.dump(results, f, indent=2, default=str)
PYEOF
```

### Step 5: Detect Specific Attack Patterns

```bash
# Detect Pass-the-Hash (Logon Type 9 with NTLM)
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser
parser = PyEvtxParser("/cases/case-2024-001/evtx/Security.evtx")
print("=== PASS-THE-HASH INDICATORS ===")
print("Looking for: Event 4624, Logon Type 9, NTLM authentication\n")
for record in parser.records_json():
    data = json.loads(record['data'])
    event_id = str(data['Event']['System']['EventID'])
    if event_id == '4624':
        event_data = data['Event'].get('EventData', {})
        logon_type = str(event_data.get('LogonType', ''))
        auth_package = str(event_data.get('AuthenticationPackageName', ''))
        logon_process = str(event_data.get('LogonProcessName', ''))
        # Pass-the-Hash indicators
        if logon_type == '9' and 'NTLM' in auth_package:
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            target = event_data.get('TargetUserName', 'Unknown')
            source_ip = event_data.get('IpAddress', 'N/A')
            print(f"  [{timestamp}] PtH: User={target}, IP={source_ip}, Auth={auth_package}")
        # Network logon with NTLM (lateral movement)
        if logon_type == '3' and 'NTLM' in auth_package:
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            target = event_data.get('TargetUserName', 'Unknown')
            source_ip = event_data.get('IpAddress', 'N/A')
            workstation = event_data.get('WorkstationName', 'N/A')
            print(f"  [{timestamp}] Network NTLM: User={target}, IP={source_ip}, WS={workstation}")
PYEOF
# Detect log clearing / anti-forensics
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser
for log_file in ['Security.evtx', 'System.evtx']:
    path = f"/cases/case-2024-001/evtx/{log_file}"
    try:
        parser = PyEvtxParser(path)
        for record in parser.records_json():
            data = json.loads(record['data'])
            event_id = str(data['Event']['System']['EventID'])
            if event_id in ('1102', '104'):  # Security log cleared, System log cleared
                timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
                print(f"LOG CLEARED: [{timestamp}] EventID {event_id} in {log_file}")
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| EVTX format | Binary XML-based Windows Event Log format introduced in Vista/Server 2008 |
| Event ID | Numeric identifier for specific event types (e.g., 4624 = successful logon) |
| Logon types | Classification of authentication methods (2=interactive, 3=network, 10=RDP) |
| Sigma rules | Generic detection signatures that map to specific SIEM/log queries |
| Sysmon | Microsoft system monitoring driver providing detailed process and network events |
| Audit policy | GPO settings controlling which events Windows records |
| Event forwarding (WEF) | Windows mechanism for centralized event log collection |
| EVTX channels | Separate log files for different event categories and applications |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Chainsaw | Sigma-based EVTX analysis and threat hunting tool |
| Hayabusa | Fast Windows Event Log forensic timeline generator |
| EvtxECmd | Eric Zimmerman command-line EVTX parser with CSV/JSON output |
| python-evtx | Python library for EVTX file parsing |
| LogParser | Microsoft SQL-like query engine for Windows logs |
| Event Log Explorer | GUI tool for browsing and analyzing EVTX files |
| KAPE | Automated triage collection including event logs |
| Velociraptor | Endpoint agent with EVTX collection and hunting artifacts |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/extracting-windows-event-logs-artifacts
