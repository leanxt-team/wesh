---
name: conducting-wireless-network-penetration-test
description: Conducts authorized wireless network penetration tests to assess the security of WiFi infrastructure by testing for weak encryption protocols, captive portal bypasses, evil twin attacks, WPA2/WPA3 handshake capture, rogue access point detection, and client-side attacks.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1557.004
- T1040
- T1110.002
- T1557
- T1669
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: conducting-wireless-network-penetration-test@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: wireless networks without written authorization from the network owner, for jamming or denial-of-service attacks against wireless infrastructure unless explicitly authorized, or in environments where wireless disruption could affect life-safety systems.

## Prerequisites

- Written authorization specifying target SSIDs, BSSIDs, and physical testing locations
- External WiFi adapter supporting monitor mode and packet injection (Alfa AWUS036ACH, TP-Link TL-WN722N v1)
- Kali Linux or equivalent with up-to-date wireless tools (aircrack-ng suite, hostapd, bettercap)
- Physical access to testing location during authorized testing hours
- Knowledge of target's wireless architecture (SSIDs, authentication types, RADIUS infrastructure)

## Workflow

### Step 1: Wireless Reconnaissance

Discover and map all wireless networks in target environment:

- Enable monitor mode: `airmon-ng start wlan0`
- Capture wireless traffic: `airodump-ng wlan0mon -w recon --output-format csv,pcap` to discover all SSIDs, BSSIDs, channels, encryption types, and connected clients
- Identify target networks from authorized scope and note their security configurations (WEP, WPA2-Personal, WPA2-Enterprise, WPA3-SAE, WPA3-Transition)
- Enumerate connected clients and their signal strengths to understand client distribution
- Check for hidden SSIDs by capturing probe requests from clients: `airodump-ng wlan0mon --essid-regex ".*" -c <channel>`
- Identify rogue access points by comparing discovered BSSIDs against client's authorized AP inventory

### Step 2: WPA2-Personal Handshake Capture and Cracking

For WPA2-PSK networks, capture the 4-way handshake and attempt offline cracking:

- Target specific AP: `airodump-ng wlan0mon -c <channel> --bssid <bssid> -w capture`
- Deauthenticate connected client to force re-authentication: `aireplay-ng -0 5 -a <bssid> -c <client_mac> wlan0mon`
- Verify handshake capture in airodump-ng (WPA handshake indicator appears)
- Crack captured handshake:
  - Dictionary attack: `aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap`
  - GPU-accelerated: `hashcat -m 22000 capture.hc22000 /usr/share/wordlists/rockyou.txt`
  - Rule-based: `hashcat -m 22000 capture.hc22000 wordlist.txt -r /usr/share/hashcat/rules/best64.rule`
- For PMKID capture (clientless): `hcxdumptool -i wlan0mon --enable_status=1 -o pmkid.pcapng --filtermode=2 --filterlist_ap=<bssid>`

### Step 3: WPA2-Enterprise Attack

For 802.1X/EAP networks, attempt credential capture through rogue RADIUS:

- Identify EAP type in use (PEAP-MSCHAPv2, EAP-TLS, EAP-TTLS) by capturing association requests
- Set up rogue AP mimicking enterprise SSID using `hostapd-mana` with rogue RADIUS server
- Configure hostapd-mana to accept all EAP authentication attempts and capture RADIUS handshakes
- When clients connect to rogue AP, capture MSCHAPv2 challenge-response pairs
- Crack captured credentials with `asleap` or convert to hashcat format: `hashcat -m 5500 captured_ntlm.txt wordlist.txt`
- If EAP-TLS is in use (certificate-based), document that credential capture is not feasible and organization has implemented strong wireless authentication

### Step 4: Evil Twin Attack

Deploy rogue access point to intercept client connections:

- Create evil twin AP matching target SSID: configure `hostapd` with same SSID and channel
- Set up captive portal using `dnsmasq` for DHCP and DNS, and web server presenting fake login page
- Deauthenticate clients from legitimate AP to force reconnection to evil twin
- Capture credentials submitted through captive portal
- For WPA3-Transition mode networks: exploit downgrade vulnerability by creating WPA2-only evil twin that transition-mode clients will connect to
- Document all captured credentials and attack path from wireless access to internal network

### Step 5: Post-Compromise Network Assessment

After gaining wireless network access, assess network segmentation:

- Connect to compromised wireless network using captured credentials
- Scan network segment for accessible hosts and services: `nmap -sn <wireless_subnet>`
- Test if wireless clients can reach internal servers, databases, or management interfaces
- Verify that VLAN segmentation properly isolates guest, corporate, and IoT wireless networks
- Test if wireless-to-wired segmentation is enforced by attempting to access servers on wired network
- Document all accessible resources from wireless network to demonstrate segmentation failures

## Key Concepts

| Term | Definition |
|------|------------|
| **Evil Twin** | Rogue access point that mimics legitimate SSID to trick clients into connecting, enabling man-in-the-middle attacks and credential capture |
| **4-Way Handshake** | WPA2 authentication exchange between client and AP that establishes encryption keys; captured handshakes can be cracked offline |
| **WPA3-SAE** | Simultaneous Authentication of Equals; WPA3's key exchange protocol that resists offline dictionary attacks and provides forward secrecy |
| **Transition Mode** | WPA3 backward compatibility mode that supports both WPA2 and WPA3 clients, potentially vulnerable to downgrade attacks |
| **PMKID Attack** | Clientless attack that captures Pairwise Master Key Identifier from AP's first EAPOL frame, allowing offline cracking without capturing full handshake |
| **802.1X/EAP** | Enterprise wireless authentication using RADIUS and Extensible Authentication Protocol, providing per-user credentials instead of shared pre-shared key |
| **Deauthentication Attack** | Sending spoofed deauthentication frames to disconnect clients from AP, forcing them to reconnect and enabling handshake capture or evil twin attacks |

## Tools & Systems

- **Aircrack-ng Suite**: Comprehensive wireless auditing toolkit including airodump-ng (capture), aireplay-ng (injection), and aircrack-ng (cracking)
- **Hostapd-mana**: Modified hostapd for creating rogue access points with EAP credential capture capability
- **Bettercap**: Network attack framework with WiFi modules for deauthentication, handshake capture, and evil twin deployment
- **Hashcat**: GPU-accelerated password cracking supporting WPA2 (mode 22000), MSCHAPv2 (mode 5500), and PMKID formats
- **Kismet**: Wireless network detector, sniffer, and intrusion detection system for passive monitoring

### Scenario: Wireless Security Assessment for Corporate Office

**Context**: Financial services company has 3 SSIDs: CorpWiFi (WPA2-Enterprise for employees), GuestWiFi (captive portal), and IoT-Net (WPA2-PSK for printers and conferencing systems). Tester is authorized to test all three networks from lobby and conference rooms.

**Approach**:
1. Wireless reconnaissance identifies all 3 SSIDs across 12 access points with 87 connected clients
2. IoT-Net WPA2-PSK handshake captured and cracked in 3 minutes (password: Company2024!)
3. From IoT-Net, scan reveals subnet can reach internal servers including print server and file shares, demonstrating inadequate segmentation
4. Evil twin attack against CorpWiFi captures 4 employee MSCHAPv2 hashes via hostapd-mana; 2 are cracked revealing passwords
5. GuestWiFi captive portal bypass achieved using MAC address spoofing of already-authenticated device
6. Document that IoT-Net provides direct path to internal network bypassing WPA2-Enterprise authentication

**Pitfalls**:
- Conducting deauthentication attacks during business hours without coordinating with client, causing visible WiFi disruptions
- Not testing WPA3 transition mode for downgrade vulnerabilities when organization has begun WPA3 migration
- Focusing only on password cracking and missing network segmentation issues that are often higher-risk finding
- Testing from single location and missing rogue APs deployed in other areas of facility

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-wireless-network-penetration-test
