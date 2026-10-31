---
name: deploying-honeytokens-and-canarytokens
description: Plants Canarytokens-based decoy artifacts (honey credentials, DNS tokens, web-bug URLs, AWS keys, documents, kubeconfigs) using Thinkst's open-source Canarytokens project and alerts via email or webhook when a token is touched.
subdomain: deception-technology
facing: defense
mitre_attack:
- T1556
nist_csf:
- DE.CM-01
upstream: deploying-honeytokens-and-canarytokens@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** Deception assets described here are defensive controls deployed inside your own environment. Deploying tokens, decoy credentials, or honeypots on infrastructure you do not own or administer, or using them to entrap third parties, may violate computer-misuse and privacy law. Deploy only on assets you own or are explicitly authorized to instrument, and route all alert data through approved monitoring channels.

## Prerequisites

- Docker Engine and Docker Compose v2 for self-hosting (`docker compose version`).
- Registered domain you control plus DNS delegation for DNS-based tokens (NS records pointing at your switchboard host).
- Public IPv4 address reachable on 80/443 (HTTP tokens) and 53/udp (DNS tokens).
- SMTP relay or Mailgun account, and/or Slack/Teams/generic webhook URL for alert delivery.
- Python 3.8+ for helper script:
  ```bash
  python3 -m pip install requests
  ```
- For quick use with no hosting, account-free token from public service at https://canarytokens.org.

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance |
|----|------------------------|-----------|
| T1556 | Modify Authentication Process | triggered honey credential reveals adversary harvesting/abusing authentication material; decoy provides detection tripwire for credential abuse activity. |

**Related MITRE D3FEND defensive techniques** (offensive counter-mapping for this control):

| D3FEND ID | Technique | Role |
|-----------|-----------|------|
| D3-DF | Decoy File | Canary documents, fake configs, decoy archives placed and monitored. |
| D3-DUC | Decoy User Credential | Honey credentials (AWS keys, AD accounts, kubeconfig) integrated with monitored decoy asset. |
| D3-DO | Decoy Object | Umbrella for honeytokens/canarytokens as monitored decoy artifacts. |

## Workflow

### 1. Deploy self-hosted Canarytokens switchboard
Clone official Docker repo and create two environment files from their distributed templates:
```bash
git clone https://github.com/thinkst/canarytokens-docker
cd canarytokens-docker
cp switchboard.env.dist switchboard.env
cp frontend.env.dist frontend.env
```
Set core variables. In `frontend.env`:
```ini
CANARY_DOMAINS=canary.example.com          # general-purpose token domains (comma-separated)
CANARY_NXDOMAINS=nx.example.com            # domains reserved for PDF/DNS tokens
CANARY_PUBLIC_IP=203.0.113.10              # public IP of this host
```
In `switchboard.env`:
```ini
CANARY_PUBLIC_DOMAIN=canary.example.com
CANARY_MAILGUN_DOMAIN_NAME=mg.example.com
CANARY_MAILGUN_API_KEY=key-xxxxxxxxxxxxxxxx
CANARY_ALERT_EMAIL_FROM_ADDRESS=canary@example.com
CANARY_ALERT_EMAIL_FROM_DISPLAY=Canarytokens
CANARY_ALERT_EMAIL_SUBJECT=Canarytoken Triggered
# WireGuard token seed:
# dd bs=32 count=1 if=/dev/urandom 2>/dev/null | base64
CANARY_WG_PRIVATE_KEY_SEED=<base64-seed>
```

### 2. Bring stack up
```bash
docker compose up -d
# HTTPS with automatic Let's Encrypt certs (after editing certbot.env):
# docker compose -f docker-compose-letsencrypt.yml up -d
docker compose ps
docker compose logs -f frontend
```
Frontend (token generator UI) is now served on your `CANARY_PUBLIC_DOMAIN`; switchboard listens on 80/443 and 53/udp to receive triggers.

### 3. Generate HTTP (web-bug) token via API
Both public service and self-hosted frontend expose a `POST /generate` endpoint. Create HTTP token that fires on any GET:
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=http' \
  -F 'email=soc@example.com' \
  -F 'memo=Internal wiki - IT admin passwords page' \
  -F 'webhook_url=https://hooks.slack.com/services/T000/B000/XXXX'
# Response JSON includes: token, auth, hostname, url, url_components
```
Returned `url` is trip-wire link; place it where only intruder would find it (fake bookmark, hidden link in wiki page, email signature).

### 4. Generate cloud credential (AWS API key) honeytoken
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=aws_keys' \
  -F 'email=soc@example.com' \
  -F 'memo=Decoy AWS keys - jenkins build host /root/.aws/credentials'
# Response contains access_key_id and secret_access_key plus a downloadable
# credentials file via /download?token=<token>&auth=<auth>&fmt=aws_keys
```
Drop keys into plausible `~/.aws/credentials` on monitored host. Any `sts:GetCallerIdentity` or other AWS call using them triggers alert with source IP and user agent.

### 5. Generate document token (MS Word / PDF) for data-theft detection
```bash
# MS Word
curl -s https://canarytokens.org/generate \
  -F 'type=msword' \
  -F 'email=soc@example.com' \
  -F 'memo=Q4-Layoffs-DRAFT.docx on FILESERVER01\\HR$' \
  -o token-meta.json
# Download the weaponized document:
curl -s "https://canarytokens.org/download?fmt=msword&token=<token>&auth=<auth>" -o Q4-Layoffs-DRAFT.docx
```
For PDFs use `type=adobe_pdf`. document phones home when opened (DNS/HTTP callback), exposing reader's IP.

### 6. Plant DNS token for resolver-level tripwires
```bash
curl -s https://canarytokens.org/generate \
  -F 'type=dns' \
  -F 'email=soc@example.com' \
  -F 'memo=DNS canary referenced in backup script comments'
# Response 'hostname' is a unique FQDN; any resolution of it fires an alert.
```
Embed hostname in scripts, configs, or `/etc/hosts` comments. Because resolution alone triggers it, DNS tokens catch reconnaissance even when egress HTTP is blocked.

### 7. Generate infrastructure tokens (Slack, kubeconfig, Azure)
```bash
# Slack API token canary (fires when the fake token is used against Slack)
curl -s https://canarytokens.org/generate -F 'type=slack_api' \
  -F 'email=soc@example.com' -F 'memo=Decoy Slack bot token in repo .env'
# Kubeconfig canary (fires when used against the kube API)
curl -s https://canarytokens.org/generate -F 'type=kubeconfig' \
  -F 'email=soc@example.com' -F 'memo=Decoy kubeconfig in /home/deploy/.kube/config'
```
Commit decoy `.env` / `kubeconfig` files only to repos and hosts you instrument, never to public repos.

### 8. Plant Active Directory honey credentials (decoy user)
Create non-privileged-looking but never-used AD account whose authentication is alerted on. Set SPN so it appears Kerberoastable bait, and forward Event ID 4768/4769/4625 for it to your SIEM:
```powershell
New-ADUser -Name "svc_backup_legacy" -SamAccountName "svc_backup_legacy" `
  -AccountPassword (ConvertTo-SecureString 'C0mpl3xDecoy!2026' -AsPlainText -Force) `
  -Enabled $true -Description "Legacy backup service (do not use)"
Set-ADUser svc_backup_legacy -ServicePrincipalNames @{Add="MSSQLSvc/decoy.example.com:1433"}
```
Add Windows audit ACL/SACL or SIEM correlation rule so any 4768/4769 for `svc_backup_legacy` pages SOC — no legitimate logon should ever occur.

### 9. Validate and catalogue
Trigger each token from controlled host and confirm alert lands:
```bash
# HTTP token
curl -s "https://canary.example.com/<token-url>" >/dev/null
# DNS token
dig +short <unique-hostname>
# AWS key token
AWS_ACCESS_KEY_ID=<id> AWS_SECRET_ACCESS_KEY=<secret> aws sts get-caller-identity
```
Record each deployed token (type, memo, location, alert channel, D3FEND mapping) in inventory. Use helper script below to bulk-generate and export this inventory as JSON.

## Tools and Resources

| Tool / Resource | Purpose | Link |
|-----------------|---------|------|
| Canarytokens (public) | Free hosted token generation | https://canarytokens.org |
| canarytokens-docker | Self-hosted switchboard + frontend | https://github.com/thinkst/canarytokens-docker |
| canarytokens (core) | Source for token engine | https://github.com/thinkst/canarytokens |
| Canarytokens docs | Per-token-type usage guides | https://docs.canarytokens.org |
| MITRE D3FEND | Defensive technique taxonomy (D3-DF, D3-DUC) | https://d3fend.mitre.org |
| MITRE ATT&CK T1556 | Modify Authentication Process | https://attack.mitre.org/techniques/T1556/ |

## Token Type Reference

| `type` value | Token | Fires when |
|--------------|-------|-----------|
| `http` | Web-bug URL | URL is requested (GET) |
| `dns` | DNS name | Hostname is resolved |
| `aws_keys` | AWS API key | Keys used against AWS |
| `msword` / `adobe_pdf` | Office/PDF document | Document is opened |
| `slack_api` | Slack API token | Token used against Slack |
| `kubeconfig` | Kubernetes config | Used against kube API |
| `azure_id` | Azure login certificate | Cert used to authenticate to Azure |
| `qr_code` | QR code | Encoded URL is requested |
| `web_image` | Image web-bug | Image is loaded |
| `log4shell` | Log4j JNDI string | Vulnerable logger evaluates it |
| `cmd` | Sensitive command (Windows) | Process/command is executed |

## Validation Criteria

- [ ] Self-hosted switchboard (or public service) deployed and reachable on 80/443 and 53/udp.
- [ ] Alert channel (email and/or webhook) configured and test alert received.
- [ ] At least one each of HTTP, DNS, cloud-credential, and document tokens generated with descriptive memos.
- [ ] Decoy credentials planted in realistic, monitored locations (no production secrets co-located).
- [ ] AD honey account created with SACL/SIEM rule firing on any authentication.
- [ ] Each token validated by controlled trigger; alert confirmed end-to-end.
- [ ] Token inventory exported (type, memo, location, alert channel, D3-DF/D3-DUC mapping).
- [ ] No tokens committed to public repositories or planted on out-of-scope systems.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-honeytokens-and-canarytokens
