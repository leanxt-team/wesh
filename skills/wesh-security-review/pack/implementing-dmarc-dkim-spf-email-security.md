---
name: implementing-dmarc-dkim-spf-email-security
description: Configures SPF, DKIM, and DMARC DNS TXT records to authenticate outbound email, prevent domain spoofing, and enforce a rejection/quarantine policy on unauthenticated mail, including auditing a domain's current DNS state.
subdomain: phishing-defense
facing: defense
mitre_attack:
- T1566
- T1598
- T1534
- T1036
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
- DE.AE-02
upstream: implementing-dmarc-dkim-spf-email-security@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- DNS management access for your domain
- Access to email server/MTA configuration (Postfix, Exchange, Google Workspace, Microsoft 365)
- Basic understanding of DNS TXT records
- Python 3.8+ for validation scripts

## Key Concepts

### SPF (Sender Policy Framework)
Publishes DNS TXT record listing authorized IP addresses and mail servers that can send email on behalf of your domain. Receiving servers check envelope sender's IP against this list.

### DKIM (DomainKeys Identified Mail)
Adds cryptographic signature to outgoing emails using private key. corresponding public key is published in DNS. Receivers verify signature to ensure message was not altered in transit.

### DMARC (Domain-based Message Authentication, Reporting and Conformance)
Builds on SPF and DKIM by specifying policy (none/quarantine/reject) for messages that fail authentication, and provides reporting mechanism to monitor spoofing attempts.

## Workflow

### Step 1: Audit Current State
```bash
# Check existing SPF record
dig TXT example.com | grep spf
# Check existing DKIM selector
dig TXT selector1._domainkey.example.com
# Check existing DMARC record
dig TXT _dmarc.example.com
```

### Step 2: Implement SPF
```
# DNS TXT record for example.com
v=spf1 ip4:203.0.113.0/24 include:_spf.google.com include:spf.protection.outlook.com -all
```

Key SPF mechanisms:
- `ip4:` / `ip6:` - Authorize specific IP ranges
- `include:` - Include another domain's SPF record
- `a` - Authorize domain's A record IPs
- `mx` - Authorize domain's MX record IPs
- `-all` - Hard fail all others (recommended)
- `~all` - Soft fail (monitoring phase)

### Step 3: Implement DKIM
```bash
# Generate DKIM key pair (2048-bit RSA)
openssl genrsa -out dkim_private.pem 2048
openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem
# Format public key for DNS (remove headers, join lines)
grep -v "PUBLIC KEY" dkim_public.pem | tr -d '\n'
```

DNS TXT record at `selector1._domainkey.example.com`:
```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhki...
```

### Step 4: Implement DMARC
```
# DNS TXT record at _dmarc.example.com
# Phase 1 (Monitor):
v=DMARC1; p=none; rua=mailto:dmarc-aggregate@example.com; ruf=mailto:dmarc-forensic@example.com; pct=100
# Phase 2 (Quarantine):
v=DMARC1; p=quarantine; rua=mailto:dmarc-aggregate@example.com; pct=25
# Phase 3 (Reject):
v=DMARC1; p=reject; rua=mailto:dmarc-aggregate@example.com; pct=100
```

### Step 5: Monitor and Analyze DMARC Reports
Use the `scripts/process.py` to parse DMARC aggregate XML reports and identify authentication failures, unauthorized senders, and spoofing attempts.

## Tools & Resources
- **MXToolbox**: https://mxtoolbox.com/SuperTool.aspx
- **DMARC Analyzer (dmarcian)**: https://dmarcian.com/
- **Google Postmaster Tools**: https://postmaster.google.com/
- **Valimail DMARC Monitor**: https://www.valimail.com/
- **DMARC Report Analyzer**: https://dmarc.postmarkapp.com/

## Validation
- SPF record passes validation at mxtoolbox.com
- DKIM signature verified on test emails
- DMARC record properly formatted and reporting enabled
- Test emails pass all three checks in recipient's Authentication-Results header

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-dmarc-dkim-spf-email-security
