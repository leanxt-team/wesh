---
name: performing-bluetooth-security-assessment
description: Assess Bluetooth Low Energy (BLE) device security using Python's bleak asyncio library to discover nearby devices, enumerate GATT services and characteristics, and flag unencrypted or unauthenticated read/write access to sensitive data.
subdomain: wireless-security
facing: defense
mitre_attack:
- T1557
- T1040
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
upstream: performing-bluetooth-security-assessment@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.9 or later
- bleak library (`pip install bleak`)
- Bluetooth adapter supporting BLE (Bluetooth 4.0+)
- Linux: BlueZ 5.43+ with D-Bus permissions
- Windows: Windows 10 version 1709+ with Bluetooth support
- macOS: macOS 10.15+ with CoreBluetooth

## Steps

1. **Scan for BLE devices**: Use BleakScanner to discover all advertising BLE devices within range. Capture device name, address (MAC), RSSI signal strength, and advertised service UUIDs.

2. **Identify target devices**: Filter discovered devices by name pattern, address, or minimum signal strength. Flag devices broadcasting default or well-known vulnerable names.

3. **Connect and enumerate GATT services**: Use BleakClient to connect to target device and iterate over all GATT services. For each service, record UUID, description, and contained characteristics.

4. **Analyze characteristic properties**: For each characteristic, examine its properties (read, write, write-without-response, notify, indicate). Flag characteristics that expose read or write access without requiring authentication or encryption.

5. **Check for known vulnerable UUIDs**: Compare discovered service and characteristic UUIDs against database of known vulnerable or sensitive services (Heart Rate, Blood Pressure, Device Information, Battery Level) that should require encryption.

6. **Detect unencrypted data exposure**: Attempt to read characteristics that should be protected. Successful unauthenticated reads of sensitive data indicate missing security controls.

7. **Generate security report**: Compile all findings into structured JSON report with severity classifications and remediation recommendations.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-bluetooth-security-assessment
