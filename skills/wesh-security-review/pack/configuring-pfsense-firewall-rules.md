---
name: configuring-pfsense-firewall-rules
description: Configures pfSense firewall rules, NAT policies, IPsec/OpenVPN tunnels, and traffic shaping to enforce network segmentation and control traffic between zones such as DMZ, internal, guest, and IoT.
subdomain: network-security
facing: defense
mitre_attack:
- T1071.001
- T1095
- T1572
- T1571
- T1041
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: configuring-pfsense-firewall-rules@54a7988 Apache-2.0, modified by wesh
---
Not for: as a substitute for host-based firewalls on individual systems, for SSL/TLS deep packet inspection without dedicated hardware acceleration, or as the sole security control without complementary IDS/IPS.

## Prerequisites

- pfSense 2.7+ installed on dedicated hardware or virtual machine with at least two network interfaces
- Access to pfSense WebConfigurator (default: https://192.168.1.1)
- Network topology diagram showing all interfaces, VLANs, and desired traffic flow
- DNS and DHCP configuration planned for each network zone
- Understanding of TCP/IP, NAT, and stateful firewall concepts

## Workflow

### Step 1: Configure Network Interfaces and VLANs

Access pfSense WebConfigurator and define interfaces:

```
Navigate: Interfaces > Assignments
WAN Interface (igb0):
  - Type: DHCP or Static IP from ISP
  - Block private networks: Enabled
  - Block bogon networks: Enabled
LAN Interface (igb1):
  - IPv4: 10.10.1.1/24
  - Description: CORPORATE_LAN
Create VLANs:
  Navigate: Interfaces > VLANs > Add
  - VLAN 10 on igb1: DMZ (10.10.10.1/24)
  - VLAN 20 on igb1: SERVERS (10.10.20.1/24)
  - VLAN 30 on igb1: GUEST (10.10.30.1/24)
  - VLAN 40 on igb1: IOT (10.10.40.1/24)
Assign VLANs:
  Navigate: Interfaces > Assignments > Add each VLAN
  Enable each interface and assign the gateway IP
```

### Step 2: Configure DHCP and DNS for Each Zone

```
Navigate: Services > DHCP Server
CORPORATE_LAN (10.10.1.0/24):
  Range: 10.10.1.100 - 10.10.1.200
  DNS: 10.10.20.10 (internal DNS server)
  Gateway: 10.10.1.1
DMZ (10.10.10.0/24):
  Range: 10.10.10.100 - 10.10.10.200
  DNS: 10.10.20.10
  Gateway: 10.10.10.1
GUEST (10.10.30.0/24):
  Range: 10.10.30.100 - 10.10.30.200
  DNS: 1.1.1.1, 8.8.8.8 (public DNS only)
  Gateway: 10.10.30.1
Navigate: Services > DNS Resolver
  Enable DNS Resolver on all interfaces except GUEST
  Enable DNSSEC
  Configure forwarding to upstream DNS servers
```

### Step 3: Create Firewall Rule Aliases

```
Navigate: Firewall > Aliases
RFC1918_Networks:
  Type: Network
  Values: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
WebPorts:
  Type: Port
  Values: 80, 443
ManagementPorts:
  Type: Port
  Values: 22, 3389, 5900
CriticalServers:
  Type: Host
  Values: 10.10.20.10, 10.10.20.11, 10.10.20.12
BlockedCountries:
  Type: URL Table
  URL: https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone
  Update: 24 hours
```

### Step 4: Implement Firewall Rules by Zone

```
Navigate: Firewall > Rules
=== WAN Rules ===
# Block all inbound by default (implicit deny)
# Allow established/related traffic (automatic in pfSense stateful mode)
# Allow inbound to DMZ web server (via NAT)
Action: Pass | Interface: WAN | Protocol: TCP
Source: any | Destination: WAN Address | Port: 80, 443
Description: Allow HTTP/HTTPS to DMZ web server
=== LAN Rules ===
# Allow LAN to access internal servers
Action: Pass | Interface: LAN | Protocol: TCP
Source: LAN net | Destination: SERVERS net | Port: WebPorts, 3306, 5432
Description: Allow LAN to internal web and database servers
# Allow LAN to internet
Action: Pass | Interface: LAN | Protocol: any
Source: LAN net | Destination: ! RFC1918_Networks
Description: Allow LAN to internet (block inter-VLAN via RFC1918 exclusion)
# Block LAN to IoT (explicit deny before implicit allow)
Action: Block | Interface: LAN | Protocol: any
Source: LAN net | Destination: IOT net
Description: Block direct LAN to IoT communication
=== DMZ Rules ===
# Allow DMZ web servers to query internal DNS
Action: Pass | Interface: DMZ | Protocol: TCP/UDP
Source: DMZ net | Destination: 10.10.20.10 | Port: 53
Description: Allow DMZ DNS queries to internal resolver
# Allow DMZ to internet for updates only
Action: Pass | Interface: DMZ | Protocol: TCP
Source: DMZ net | Destination: any | Port: 80, 443
Description: Allow DMZ outbound HTTP/HTTPS for updates
# Block all other DMZ traffic
Action: Block | Interface: DMZ | Protocol: any
Source: DMZ net | Destination: any
Description: Default deny for DMZ
=== GUEST Rules ===
# Allow guest to internet only (DNS and web)
Action: Pass | Interface: GUEST | Protocol: TCP/UDP
Source: GUEST net | Destination: ! RFC1918_Networks | Port: 53, 80, 443
Description: Allow guest internet access only
# Block all guest to internal
Action: Block | Interface: GUEST | Protocol: any
Source: GUEST net | Destination: RFC1918_Networks
Description: Block guest access to all internal networks
=== IOT Rules ===
# Allow IoT to specific cloud endpoints
Action: Pass | Interface: IOT | Protocol: TCP
Source: IOT net | Destination: ! RFC1918_Networks | Port: 443, 8883
Description: Allow IoT HTTPS and MQTT to cloud
# Block IoT inter-device communication
Action: Block | Interface: IOT | Protocol: any
Source: IOT net | Destination: IOT net
Description: Prevent IoT lateral movement
# Block IoT to all internal networks
Action: Block | Interface: IOT | Protocol: any
Source: IOT net | Destination: RFC1918_Networks
Description: Block IoT access to internal
```

### Step 5: Configure NAT Rules

```
Navigate: Firewall > NAT > Port Forward
# Web server in DMZ
Interface: WAN | Protocol: TCP
Destination: WAN address | Port: 443
Redirect target IP: 10.10.10.50 | Port: 443
NAT Reflection: Enable
Description: HTTPS to DMZ web server
# SSH jump host (non-standard port)
Interface: WAN | Protocol: TCP
Destination: WAN address | Port: 2222
Redirect target IP: 10.10.20.11 | Port: 22
Description: SSH to internal jump host via port 2222
Navigate: Firewall > NAT > Outbound
Mode: Hybrid Outbound NAT
# Add rule for DMZ servers to use a dedicated public IP
Interface: WAN | Source: 10.10.10.0/24
Translation Address: <dedicated_public_ip>
Description: DMZ outbound NAT via dedicated IP
```

### Step 6: Enable Logging and Monitoring

```
Navigate: Status > System Logs > Settings
  Remote Logging: Enable
  Remote log servers: 10.10.20.15:514 (Syslog/SIEM)
  Log firewall default blocks: Enabled
Navigate: Firewall > Rules
  Enable logging on critical rules:
  - All BLOCK rules
  - WAN inbound PASS rules
  - Inter-VLAN PASS rules
Navigate: Diagnostics > pfTop
  Monitor real-time connection states and bandwidth usage
Install pfBlockerNG package:
  Navigate: System > Package Manager > Available Packages
  Install pfBlockerNG-devel
  Configure IP blocklists (Spamhaus DROP, Emerging Threats)
  Configure DNSBL for malware domain blocking
```

### Step 7: Backup and Test Configuration

```bash
# Export configuration backup
Navigate: Diagnostics > Backup & Restore
Download XML configuration file
# Test rules from each zone
# From LAN:
curl -I https://10.10.20.10  # Should succeed (LAN to SERVERS)
curl -I https://10.10.40.5   # Should fail (LAN to IOT blocked)
# From GUEST:
curl -I https://www.google.com  # Should succeed (internet)
curl -I https://10.10.20.10     # Should fail (guest to internal blocked)
# From DMZ:
nslookup google.com 10.10.20.10  # Should succeed (DNS allowed)
ssh 10.10.1.50                    # Should fail (DMZ to LAN blocked)
# Verify logging
Navigate: Status > System Logs > Firewall
Check that blocked and passed traffic is logging correctly
# Schedule automated config backups
Navigate: Diagnostics > AutoConfigBackup
Enable automatic backups to Netgate cloud or local storage
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Stateful Firewall** | Firewall that tracks state of network connections and automatically allows return traffic for established sessions without explicit rules |
| **Alias** | Named group of IP addresses, networks, or ports in pfSense that simplifies rule management and improves readability |
| **NAT (Network Address Translation)** | Translation of IP addresses between internal and external networks, including port forwarding for inbound access to internal services |
| **Floating Rules** | pfSense rules that apply across multiple interfaces simultaneously, processed before per-interface rules |
| **pfBlockerNG** | pfSense package that integrates IP reputation blocklists and DNS-based blocklists for automated threat blocking |
| **Rule Processing Order** | pfSense evaluates rules top-to-bottom within each interface tab; first match wins, and unmatched traffic is blocked by default |

## Tools & Systems

- **pfSense 2.7+**: Open-source firewall and router platform based on FreeBSD with web-based management and extensive package ecosystem
- **pfBlockerNG**: IP and DNS blocklist package for automated threat intelligence integration
- **Snort/Suricata packages**: IDS/IPS integration available as pfSense packages for inline traffic inspection
- **OpenVPN/IPsec**: Built-in VPN implementations for site-to-site and remote access connectivity
- **Netgate AutoConfigBackup**: Cloud-based configuration backup service for pfSense disaster recovery

## pfSense Firewall Configuration Report

**Device**: pfSense 2.7.2 on Netgate 4100
**Interfaces**: WAN (igb0), LAN (igb1), DMZ (igb2), MGMT (igb3)
**VLANs**: 4 configured (Staff, Servers, Guest, IoT)
**Total Rules**: 28 active rules across all interfaces

### Rule Summary by Interface

| Interface | Pass Rules | Block Rules | Logging Enabled |
|-----------|-----------|-------------|-----------------|
| WAN | 2 | 1 (default) | Yes |
| LAN | 4 | 2 | Yes (blocks) |
| DMZ | 3 | 1 (default) | Yes |
| GUEST | 1 | 2 | Yes |
| IOT | 1 | 3 | Yes |

### Security Controls
- pfBlockerNG: 12 IP blocklists + DNSBL enabled
- Snort IDS: Running on WAN and LAN interfaces
- VPN: OpenVPN remote access configured with MFA
- Logging: All traffic forwarded to SIEM (10.10.20.15)
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/configuring-pfsense-firewall-rules
