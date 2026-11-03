---
name: performing-initial-access-with-evilginx3
description: Perform authorized initial access using EvilGinx3 adversary-in-the-middle phishing framework to capture session tokens and bypass multi-factor authentication during red team engagements.
subdomain: red-teaming
facing: config
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1003
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: performing-initial-access-with-evilginx3@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Familiarity with red teaming concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1566.002** - Phishing: Spearphishing Link
- **T1557** - Adversary-in-the-Middle
- **T1539** - Steal Web Session Cookie
- **T1078** - Valid Accounts
- **T1556** - Modify Authentication Process
- **T1550.004** - Use Alternate Authentication Material: Web Session Cookie

## Workflow

### Phase 1: Infrastructure Setup

1. Register convincing lookalike domain (e.g., using homoglyphs or typosquatting)
2. Provision VPS and point domain's DNS Record to server IP
3. Install EvilGinx3:
   ```bash
   git clone https://github.com/kgretzky/evilginx2.git
   cd evilginx2
   make
   sudo ./bin/evilginx -p ./phishlets
   ```
4. Configure domain and IP in EvilGinx3:
   ```
   config domain example-phish.com
   config ipv4 <server-ip>
   ```
5. EvilGinx3 automatically provisions Let's Encrypt certificates for configured hostnames

### Phase 2: Phishlet Configuration

1. Select or create phishlet for target service (e.g., Microsoft 365, Google Workspace):
   ```
   phishlets hostname o365 login.example-phish.com
   phishlets enable o365
   ```
2. Verify phishlet is active and SSL certificate is issued:
   ```
   phishlets
   ```
3. Create lure URL for phishing campaign:
   ```
   lures create o365
   lures get-url 0
   ```
4. Optionally configure redirect URL for post-capture:
   ```
   lures edit 0 redirect_url https://legitimate-site.com
   ```

### Phase 3: Phishing Delivery

1. Craft pretext email with lure URL embedded
2. Use GoPhish or manual SMTP for email delivery:
   ```
   # Integration with EvilGoPhish for combined campaigns
   # Provides GoPhish email tracking + EvilGinx3 credential capture
   ```
3. Implement URL masking or shortening if needed for link obfuscation
4. Deploy landing page with appropriate social engineering pretext

### Phase 4: Session Hijacking

1. Monitor EvilGinx3 for captured sessions:
   ```
   sessions
   sessions <session-id>
   ```
2. Extract captured session cookies from session:
   ```
   # Session output includes:
   # - Username and password
   # - Session cookies (authentication tokens)
   # - Custom captured parameters
   ```
3. Import session cookies into browser using cookie editor extension:
   - Export cookies in JSON format
   - Use Cookie-Editor or EditThisCookie browser extension
   - Navigate to target service to validate session hijack
4. Establish persistent access by creating application passwords or OAuth tokens

### Phase 5: Post-Access Activities

1. Enumerate mailbox contents, contacts, and shared drives
2. Identify additional targets for lateral phishing
3. Check for access to connected cloud applications (SharePoint, Teams, OneDrive)
4. Document all captured credentials and access achieved

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| EvilGinx3 | AiTM phishing framework | Linux |
| GoPhish | Phishing campaign management | Cross-platform |
| EvilGoPhish | Combined EvilGinx3 + GoPhish integration | Linux |
| Cookie-Editor | Browser cookie import/export | Browser Extension |
| Modlishka | Alternative AiTM proxy framework | Linux |
| Muraena | Alternative AiTM phishing proxy | Linux |

## Phishlet Targets

| Target Service | Phishlet | Captured Data |
|---------------|----------|---------------|
| Microsoft 365 | o365 | Session cookies, credentials |
| Google Workspace | google | Session cookies, credentials |
| Okta | okta | Session tokens, credentials |
| GitHub | github | Session cookies, credentials |
| AWS Console | aws | Session tokens, credentials |

## Detection Indicators

| Indicator | Detection Method |
|-----------|-----------------|
| Newly registered lookalike domains | Domain monitoring and certificate transparency logs |
| SSL certificates for suspicious domains | CT log monitoring (crt.sh, Censys) |
| Unusual login locations after phishing | SIEM correlation of authentication events |
| Session cookie replay from different IP | Conditional access policy alerts |
| AiTM proxy headers in traffic | Network inspection for proxy artifacts |

## Validation Criteria

- [ ] EvilGinx3 deployed with valid SSL certificates
- [ ] Phishlet configured and enabled for target service
- [ ] Lure URL generated and accessible
- [ ] Test credentials captured successfully through phishing flow
- [ ] Session cookies captured and validated for MFA bypass
- [ ] Session hijack demonstrated in browser with stolen cookies
- [ ] Post-authentication access to target service confirmed
- [ ] Evidence documented with screenshots and session logs

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-initial-access-with-evilginx3
