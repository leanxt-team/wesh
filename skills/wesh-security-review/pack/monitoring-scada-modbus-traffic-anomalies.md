---
name: monitoring-scada-modbus-traffic-anomalies
description: Monitors Modbus TCP traffic on SCADA and ICS networks to detect anomalous function code usage, unauthorized register writes, and suspicious communication patterns.
subdomain: ot-security
facing: defense
mitre_attack:
- T0816
- T0836
- T0830
- T1595
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-05
upstream: monitoring-scada-modbus-traffic-anomalies@54a7988 Apache-2.0, modified by wesh
---
Not for: on networks without authorization from the asset owner, for active injection or fuzzing against production SCADA systems, or as a replacement for safety-instrumented systems (SIS) that provide physical process protection.

## Prerequisites

- Network tap or SPAN port on OT network segment carrying Modbus TCP traffic (port 502)
- Python 3.9+ with pymodbus (>=3.6), scapy (>=2.5), and pandas for traffic analysis
- Zeek (formerly Bro) installed with Modbus protocol analyzer enabled for passive traffic logging
- Wireshark or tshark for initial packet capture and validation of Modbus frame structure
- Baseline period of normal operations (minimum 48-72 hours) to establish communication profiles per device pair
- Network diagram identifying Modbus master-slave relationships, device IP addresses, and expected function code usage

## Workflow

### Step 1: Capture and Parse Modbus TCP Traffic

Establish passive monitoring on OT network segment and begin capturing Modbus TCP frames:

- **Configure network tap**: Position monitoring interface on SPAN port mirroring VLAN carrying Modbus TCP traffic between HMI/SCADA servers and PLCs. Verify bidirectional traffic capture with `tcpdump -i eth0 port 502 -c 100 -w modbus_capture.pcap`.
- **Parse Modbus TCP frame structure**: Each Modbus TCP frame contains 7-byte MBAP (Modbus Application Protocol) header followed by PDU. MBAP header includes:
  - Transaction Identifier (2 bytes): Matches requests to responses
  - Protocol Identifier (2 bytes): Always 0x0000 for Modbus
  - Length (2 bytes): Number of following bytes including Unit ID
  - Unit Identifier (1 byte): Slave device address (0-247)
- **Extract function codes with Scapy**: Use Scapy's Modbus contrib module to dissect captured packets and extract function codes, register addresses, and values:
  ```python
  from scapy.all import rdpcap, TCP
  from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
  packets = rdpcap("modbus_capture.pcap")
  for pkt in packets:
      if pkt.haslayer(ModbusADURequest):
          adu = pkt[ModbusADURequest]
          print(f"Src: {pkt['IP'].src} -> Dst: {pkt['IP'].dst} "
                f"Unit: {adu.unitId} FuncCode: {adu.funcCode}")
  ```
- **Enable Zeek Modbus logging**: Configure Zeek with `@load policy/protocols/modbus/known-masters-slaves` to generate `modbus.log` entries containing timestamp, source/destination IPs, function code, and exception responses. This provides continuous passive logging without custom scripting.
- **Validate frame integrity**: Check for malformed Modbus frames where MBAP length field does not match actual PDU length, Protocol Identifier is not 0x0000, or Unit Identifier falls outside expected range for monitored network.

### Step 2: Baseline Normal Communication Patterns

Build behavioral profile of legitimate Modbus traffic to distinguish normal operations from anomalies:

- **Catalog function code distribution**: Record frequency of each function code per source-destination pair over baseline period. In typical SCADA environments, read operations (FC 01-04) vastly outnumber write operations (FC 05, 06, 15, 16), often at ratios exceeding 100:1. sudden increase in write function codes is strong indicator of process manipulation.
  ```
  Normal baseline example (72-hour period):
  HMI (10.1.1.10) -> PLC (10.1.1.50):
    FC 03 (Read Holding Registers):  432,180 packets  (97.2%)
    FC 04 (Read Input Registers):     10,540 packets  (2.4%)
    FC 06 (Write Single Register):     1,780 packets  (0.4%)
    FC 16 (Write Multiple Registers):      0 packets  (0.0%)
    FC 43 (Read Device ID):               0 packets  (0.0%)
  ```
- **Map register address ranges**: Document which holding register and coil address ranges each master polls. PLCs typically expose specific register blocks for monitoring (e.g., registers 0-99 for process values, 100-199 for setpoints). Access to registers outside documented range indicates reconnaissance or misconfiguration.
- **Establish timing profiles**: Calculate polling interval (mean, standard deviation) for each master-slave pair. SCADA polling is periodic, typically 100ms to 5s intervals. Deviations greater than 3 standard deviations from mean suggest network issues or injected traffic from rogue master.
- **Identify authorized masters**: Record all IP addresses that initiate Modbus requests (master role). In properly segmented OT network, only HMI server and engineering workstation should act as Modbus masters. Any new source IP sending Modbus requests is immediately suspicious.
- **Register value ranges**: For critical process registers (temperatures, pressures, flow rates, setpoints), record observed minimum, maximum, mean, and standard deviation during normal operations. Values outside physical process bounds indicate either sensor failure or malicious manipulation.

### Step 3: Detect Function Code Anomalies

Apply rule-based and statistical detection to identify suspicious function code usage:

- **Unauthorized write detection**: Alert when Modbus write function code (05, 06, 15, 16) originates from source IP not in authorized writers list, or when write operations exceed baseline frequency threshold:
  ```python
  WRITE_FUNCTION_CODES = {5, 6, 15, 16}
  AUTHORIZED_WRITERS = {"10.1.1.10", "10.1.1.11"}  # HMI and engineering WS
  def check_unauthorized_write(src_ip, function_code):
      if function_code in WRITE_FUNCTION_CODES and src_ip not in AUTHORIZED_WRITERS:
          return {
              "alert": "UNAUTHORIZED_MODBUS_WRITE",
              "severity": "CRITICAL",
              "src_ip": src_ip,
              "function_code": function_code,
              "description": f"Write FC {function_code} from unauthorized source {src_ip}"
          }
      return None
  ```
- **Reconnaissance detection**: Function code 43 (Read Device Identification) and function code 08 (Diagnostics) are rarely used during normal operations. Any occurrence from non-engineering workstation indicates device enumeration. Also detect sequential scanning where single source queries multiple Unit IDs within short window.
- **Exception response monitoring**: Modbus exception codes (01: Illegal Function, 02: Illegal Data Address, 03: Illegal Data Value) in responses indicate master sent invalid request. burst of exception responses suggests fuzzing or protocol-level attacks:
  ```
  Exception response correlation:
  - Isolated exception (1-2 per hour): Normal operational error
  - Burst (>10 per minute): Active scanning or fuzzing attempt
  - Continuous (>100 per hour): Denial-of-service or tool malfunction
  ```
- **Forbidden function code detection**: Some environments prohibit certain function codes entirely. Function codes 07 (Read Exception Status), 08 (Diagnostics), 17 (Report Slave ID), and 43 (Read Device Identification) are diagnostic functions that should not appear in production SCADA traffic. Alert on any occurrence.
- **Function code frequency anomaly**: Calculate chi-squared statistic comparing observed function code distribution against baseline distribution. significant deviation (p < 0.01) triggers alert even if no individual function code crosses its threshold.

### Step 4: Monitor Register Values for Process Manipulation

Detect attempts to manipulate physical process parameters through register value analysis:

- **Setpoint change monitoring**: Track all write operations to holding registers that control process setpoints (temperatures, pressures, valve positions, motor speeds). Alert when:
  - New value exceeds defined safe operating range
  - Rate of change exceeds physical process capabilities (e.g., temperature setpoint jumping 50 degrees in one write)
  - Multiple setpoints change simultaneously, which does not match normal operator behavior
  ```python
  REGISTER_LIMITS = {
      40001: {"name": "Reactor Temperature Setpoint", "min": 50, "max": 200, "unit": "C",
              "max_rate": 5},   # Max 5 degrees per write cycle
      40010: {"name": "Pump Speed", "min": 0, "max": 3600, "unit": "RPM",
              "max_rate": 200},  # Max 200 RPM change per cycle
      40020: {"name": "Valve Position", "min": 0, "max": 100, "unit": "%",
              "max_rate": 10},   # Max 10% per cycle
  }
  def check_register_value(register_addr, new_value, previous_value):
      if register_addr not in REGISTER_LIMITS:
          return None
      limits = REGISTER_LIMITS[register_addr]
      alerts = []
      if new_value < limits["min"] or new_value > limits["max"]:
          alerts.append({
              "alert": "REGISTER_VALUE_OUT_OF_RANGE",
              "severity": "CRITICAL",
              "register": register_addr,
              "name": limits["name"],
              "value": new_value,
              "range": f"{limits['min']}-{limits['max']} {limits['unit']}"
          })
      if previous_value is not None:
          rate = abs(new_value - previous_value)
          if rate > limits["max_rate"]:
              alerts.append({
                  "alert": "REGISTER_VALUE_EXCESSIVE_RATE",
                  "severity": "HIGH",
                  "register": register_addr,
                  "name": limits["name"],
                  "change": rate,
                  "max_allowed": limits["max_rate"]
              })
      return alerts if alerts else None
  ```
- **Coil state monitoring**: Track coil writes (FC 05, FC 15) that control discrete outputs (pumps on/off, valves open/close, breakers trip/close). Detect rapid toggling (more than N state changes per minute) which could indicate equipment damage attempts.
- **Register read pattern anomaly**: If master begins reading register ranges it has never accessed before, this may indicate attacker using compromised HMI to map PLC memory layout before launching targeted write attack.
- **Correlation with process data**: Where available, compare Modbus register values against independent process sensors (e.g., historian data). Discrepancies between Modbus-reported value and independent sensor indicate either sensor spoofing or register manipulation.

### Step 5: Detect Network-Level Anomalies

Identify anomalies in communication patterns that may indicate man-in-the-middle, replay, or denial-of-service attacks:

- **Rogue master detection**: Alert when new source IP initiates Modbus TCP connections to port 502 on any slave device. Maintain whitelist of authorized master IPs and generate critical alert for any connection from unknown source:
  ```python
  AUTHORIZED_MASTERS = {"10.1.1.10", "10.1.1.11"}
  def detect_rogue_master(src_ip, dst_ip, dst_port):
      if dst_port == 502 and src_ip not in AUTHORIZED_MASTERS:
          return {
              "alert": "ROGUE_MODBUS_MASTER",
              "severity": "CRITICAL",
              "src_ip": src_ip,
              "target_slave": dst_ip,
              "description": "Unauthorized device initiating Modbus connection"
          }
      return None
  ```
- **Transaction ID anomaly**: Modbus TCP uses transaction IDs to match requests with responses. Under normal operation, transaction IDs increment sequentially per master. Detect:
  - Duplicate transaction IDs from different sources (replay attack indicator)
  - Transaction ID gaps or resets (session hijacking indicator)
  - Responses with transaction IDs that do not match any recent request (injected response)
- **Timing anomaly detection**: Calculate inter-packet arrival times for each master-slave pair. Flag deviations greater than 3 standard deviations using sliding window:
  ```python
  import numpy as np
  from collections import defaultdict
  class TimingAnomalyDetector:
      def __init__(self, window_size=1000, threshold_sigma=3.0):
          self.windows = defaultdict(list)
          self.window_size = window_size
          self.threshold_sigma = threshold_sigma
      def check(self, src_ip, dst_ip, timestamp):
          key = (src_ip, dst_ip)
          window = self.windows[key]
          if len(window) > 0:
              interval = timestamp - window[-1]
              if len(window) >= 100:
                  mean = np.mean(np.diff(window[-100:]))
                  std = np.std(np.diff(window[-100:]))
                  if std > 0 and abs(interval - mean) > self.threshold_sigma * std:
                      return {
                          "alert": "TIMING_ANOMALY",
                          "severity": "MEDIUM",
                          "pair": f"{src_ip}->{dst_ip}",
                          "interval": interval,
                          "expected_mean": mean,
                          "deviation_sigma": abs(interval - mean) / std
                      }
          window.append(timestamp)
          if len(window) > self.window_size:
              window.pop(0)
          return None
  ```
- **Connection flood detection**: Monitor rate of new TCP connections to port 502 per slave device. Modbus slaves typically handle 1-5 persistent connections. More than 10 connection attempts per minute to single slave indicates connection flood DoS or scanning activity.
- **Payload size anomaly**: Modbus PDU max size is 253 bytes. Alert on oversized frames that exceed protocol limits, as these may indicate buffer overflow exploitation attempts against vulnerable PLC firmware.

## Key Concepts

| Term | Definition |
|------|------------|
| **Modbus TCP** | application-layer protocol encapsulating Modbus frames in TCP/IP, communicating on port 502. It uses 7-byte MBAP header (transaction ID, protocol ID, length, unit ID) followed by Modbus PDU containing function code and data. |
| **Function Code** | single-byte identifier in Modbus PDU specifying operation: read coils (01), read discrete inputs (02), read holding registers (03), read input registers (04), write single coil (05), write single register (06), write multiple coils (15), write multiple registers (16), diagnostics (08), and device identification (43). |
| **MBAP Header** | Modbus Application Protocol header used in Modbus TCP. Contains Transaction ID for request-response matching, Protocol ID (always 0x0000 for Modbus), Length of remaining bytes, and Unit Identifier for addressing slaves behind gateways. |
| **Holding Register** | A 16-bit read/write register in Modbus slave addressed at range 40001-49999 (protocol address 0-9998). Used for setpoints, configuration, and control values that can be written by master. Primary target for process manipulation attacks. |
| **Coil** | single-bit read/write data element in Modbus slave addressed at range 00001-09999. Controls discrete outputs (valves, pumps, breakers). Write operations (FC 05/15) to coils can directly affect physical equipment state. |
| **Deep Packet Inspection** | Analysis beyond TCP/IP headers into Modbus application-layer payload to extract function codes, register addresses, and values. Required because standard firewalls only inspect IP/port, missing protocol-level attacks that use legitimate Modbus framing. |
| **Rogue Master** | unauthorized device sending Modbus requests to slave devices. In OT environments, only designated HMI servers and engineering workstations should act as Modbus masters. rogue master can read process data or write dangerous values to PLCs. |
| **Register Value Baseline** | statistical profile (min, max, mean, standard deviation) of values observed in specific registers during normal operations. Deviations beyond physical process bounds indicate sensor failure or malicious manipulation. |

## Tools & Systems

- **pymodbus**: Python library for Modbus protocol implementation supporting TCP, RTU, and ASCII modes. Used for building custom Modbus clients/servers, packet parsing, and simulating master-slave communication in test environments.
- **Scapy (contrib.modbus)**: Packet manipulation framework with Modbus TCP dissector for crafting, parsing, and sniffing Modbus frames. Enables field-level access to MBAP headers, function codes, and register data in captured packets.
- **Zeek (formerly Bro)**: Network security monitor with native Modbus protocol analyzer that generates structured logs (modbus.log) for every Modbus transaction including function codes, register addresses, and exception responses.
- **Wireshark/tshark**: Network protocol analyzer with built-in Modbus TCP dissector for visual inspection of packet captures, filtering by function code (`modbus.func_code == 6`), and exporting specific fields for analysis.
- **GRFICSv2**: open-source virtual ICS environment for security research featuring simulated chemical process with Modbus-connected PLCs, HMI, and historian. Used for testing detection rules against realistic SCADA traffic.
- **Suricata**: Network IDS/IPS with Modbus protocol support via application-layer rules that can match on function codes, register addresses, and values for real-time alerting.

## Modbus Traffic Anomaly Report

**Monitoring Period**: 2026-03-15 00:00:00 UTC to 2026-03-15 23:59:59 UTC
**Network Segment**: OT VLAN 10 (10.1.1.0/24)
**Packets Analyzed**: 2,847,320
**Anomalies Detected**: 4

---

### Alert 1: Unauthorized Write Operation

**Timestamp**: 2026-03-15 14:23:17 UTC
**Severity**: CRITICAL
**Source**: 10.1.2.20 (Engineering Workstation)
**Destination**: 10.1.1.52 (PLC-3 Chemical Dosing)
**Function Code**: 16 (Write Multiple Registers)
**Registers**: 40050-40055
**Values Written**: [250, 100, 0, 1, 3600, 1]
**Baseline**: FC 16 never observed for this source-destination pair

**Context**: Register 40050 (Chlorine Dosing Rate) changed from 25 to 250
(safe range: 10-40). Register 40054 (Dosing Timer) changed from 1800 to 3600.
Combined effect would double chlorine concentration over extended period.

**Recommended Action**: Immediately verify physical process state. Isolate
source device. Check register values against expected setpoints with
plant operator.

---

### Alert 2: Device Enumeration Detected

**Timestamp**: 2026-03-15 14:20:05 to 14:20:47 UTC
**Severity**: HIGH
**Source**: 10.1.2.20
**Targets**: 10.1.1.50, 10.1.1.51, 10.1.1.52, 10.1.1.53, 10.1.1.54 (+10 more)
**Function Code**: 43 (Read Device Identification)
**Baseline**: FC 43 never observed from this source

**Context**: Sequential scanning of 15 devices in 42 seconds. Device
identification responses reveal PLC vendor, model, and firmware versions
for all scanned devices.

**Recommended Action**: Investigate source workstation for compromise
indicators. Block FC 43 from non-engineering subnets at OT firewall.
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/monitoring-scada-modbus-traffic-anomalies
