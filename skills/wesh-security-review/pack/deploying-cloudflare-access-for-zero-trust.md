---
name: deploying-cloudflare-access-for-zero-trust
description: Deploys Cloudflare Access with Cloudflare Tunnel for zero trust access to self-hosted apps, configuring identity-aware policies, device posture checks, and WARP client enrollment as a VPN replacement.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1133
- T1078
- T1190
- T1021
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: deploying-cloudflare-access-for-zero-trust@54a7988 Apache-2.0, modified by wesh
---
Not for: applications requiring persistent UDP connections not supported by Cloudflare Tunnel, for environments requiring air-gapped or fully on-premises access control, or when regulatory requirements prohibit routing traffic through third-party cloud infrastructure.

## Prerequisites

- Cloudflare account with Zero Trust subscription (Free for up to 50 users, paid plans for larger teams)
- Domain name managed by Cloudflare DNS (or ability to add CNAME records)
- Linux, Windows, or macOS server to run `cloudflared` tunnel daemon
- Identity provider: Okta, Microsoft Entra ID, Google Workspace, GitHub, or any SAML/OIDC provider
- Cloudflare WARP client for device-level enrollment (optional but recommended)

## Workflow

### Step 1: Create Cloudflare Tunnel to Internal Applications

Install `cloudflared` and create persistent tunnel to expose internal services.

```bash
# Install cloudflared on Ubuntu/Debian
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb \
  -o cloudflared.deb
sudo dpkg -i cloudflared.deb
# Authenticate cloudflared with your Cloudflare account
cloudflared tunnel login
# Create a named tunnel
cloudflared tunnel create internal-apps
# Output: Created tunnel internal-apps with id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Configure tunnel routes to internal applications
cat > ~/.cloudflared/config.yml << 'EOF'
tunnel: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
credentials-file: /home/admin/.cloudflared/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.json
ingress:
  - hostname: wiki.company.com
    service: http://localhost:8080
  - hostname: git.company.com
    service: http://10.1.1.50:3000
  - hostname: grafana.company.com
    service: http://10.1.1.60:3000
  - hostname: ssh.company.com
    service: ssh://localhost:22
  - hostname: rdp.company.com
    service: rdp://10.1.1.100:3389
  # Catch-all rule (required)
  - service: http_status:404
EOF
# Route DNS to the tunnel
cloudflared tunnel route dns internal-apps wiki.company.com
cloudflared tunnel route dns internal-apps git.company.com
cloudflared tunnel route dns internal-apps grafana.company.com
# Run tunnel as a systemd service
sudo cloudflared service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
# Verify tunnel status
cloudflared tunnel info internal-apps
```

### Step 2: Configure Identity Provider Integration

Set up authentication with your organization's identity provider.

```bash
# Using Cloudflare API to configure Okta as IdP
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/identity_providers" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Corporate Okta",
    "type": "okta",
    "config": {
      "client_id": "OKTA_CLIENT_ID",
      "client_secret": "OKTA_CLIENT_SECRET",
      "okta_account": "company.okta.com",
      "api_token": "OKTA_API_TOKEN",
      "claims": ["email", "groups", "name"],
      "email_claim_name": "email"
    }
  }'
# Configure Microsoft Entra ID as additional IdP
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/identity_providers" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Microsoft Entra ID",
    "type": "azureAD",
    "config": {
      "client_id": "AZURE_APP_CLIENT_ID",
      "client_secret": "AZURE_APP_CLIENT_SECRET",
      "directory_id": "AZURE_TENANT_ID",
      "support_groups": true,
      "claims": ["email", "groups", "name"]
    }
  }'
```

### Step 3: Create Access Applications and Policies

Define Access applications with identity-aware policies for each internal service.

```bash
# Create Access application for internal wiki
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Internal Wiki",
    "domain": "wiki.company.com",
    "type": "self_hosted",
    "session_duration": "8h",
    "auto_redirect_to_identity": true,
    "http_only_cookie_attribute": true,
    "same_site_cookie_attribute": "lax",
    "logo_url": "https://company.com/wiki-logo.png",
    "allowed_idps": ["OKTA_IDP_ID", "AZURE_IDP_ID"]
  }'
# Create Allow policy for the wiki application
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps/{app_id}/policies" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Allow Engineering Team",
    "decision": "allow",
    "precedence": 1,
    "include": [
      {"group": {"id": "ENGINEERING_GROUP_ID"}},
      {"okta": {"name": "Engineering", "identity_provider_id": "OKTA_IDP_ID"}}
    ],
    "require": [
      {"device_posture": {"integration_uid": "CROWDSTRIKE_INTEGRATION_ID"}}
    ]
  }'
# Create Access application for SSH access
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/access/apps" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "SSH Access",
    "domain": "ssh.company.com",
    "type": "ssh",
    "session_duration": "4h",
    "auto_redirect_to_identity": true
  }'
```

### Step 4: Deploy WARP Client for Device Enrollment

Enroll corporate devices using Cloudflare WARP for private network access and device posture.

```bash
# Create device enrollment rule
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/policy" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Corporate Device Enrollment",
    "match": "identity.email matches \".*@company\\.com$\"",
    "precedence": 100,
    "enabled": true,
    "gateway_unique_id": "GATEWAY_ID",
    "support_url": "https://helpdesk.company.com/warp-help"
  }'
# Install WARP on macOS via MDM (Jamf/Intune)
# Download: https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/download-warp/
# Deploy with MDM configuration profile:
cat > warp_mdm_config.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>organization</key>
    <string>company</string>
    <key>auto_connect</key>
    <integer>1</integer>
    <key>switch_locked</key>
    <true/>
    <key>onboarding</key>
    <false/>
</dict>
</plist>
EOF
# Install Cloudflare root certificate for TLS inspection
# Download from: https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/user-side-certificates/
sudo cp cloudflare-root-ca.pem /usr/local/share/ca-certificates/cloudflare-root-ca.crt
sudo update-ca-certificates
# Configure split tunnel to route private network through WARP
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/policy/{policy_id}/fallback_domains" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '[
    {"suffix": "internal.corp", "description": "Internal corporate domain"},
    {"suffix": "10.0.0.0/8", "description": "Private network range"}
  ]'
```

### Step 5: Configure Device Posture Checks

Integrate endpoint security signals into Access policies.

```bash
# Add CrowdStrike device posture integration
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture/integration" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "CrowdStrike Falcon",
    "type": "crowdstrike_s2s",
    "config": {
      "api_url": "https://api.crowdstrike.com",
      "client_id": "CS_API_CLIENT_ID",
      "client_secret": "CS_API_CLIENT_SECRET",
      "customer_id": "CS_CUSTOMER_ID"
    },
    "interval": "10m"
  }'
# Create device posture rule for disk encryption
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Disk Encryption Required",
    "type": "disk_encryption",
    "match": [{"platform": "windows"}, {"platform": "mac"}],
    "input": {"requireAll": true}
  }'
# Create device posture rule for OS version
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/devices/posture" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "Minimum OS Version",
    "type": "os_version",
    "match": [{"platform": "windows"}],
    "input": {"version": "10.0.19045", "operator": ">="}
  }'
```

### Step 6: Set Up Audit Logging and Analytics

Configure logging for access decisions and tunnel health monitoring.

```bash
# Enable Logpush for Access audit logs to S3
curl -X POST "https://api.cloudflare.com/client/v4/accounts/{account_id}/logpush/jobs" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "name": "access-audit-logs",
    "output_options": {
      "field_names": ["RayID","Action","Allowed","AppDomain","AppUUID","Connection","Country","CreatedAt","Email","IPAddress","PurposeJustificationPrompt","PurposeJustificationResponse","TemporaryAccessDuration","UserUID"],
      "timestamp_format": "rfc3339"
    },
    "destination_conf": "s3://security-logs-bucket/cloudflare-access/?region=us-east-1&access-key-id=AKID&secret-access-key=SECRET",
    "dataset": "access_requests",
    "enabled": true
  }'
# Query access logs via GraphQL Analytics API
curl -X POST "https://api.cloudflare.com/client/v4/graphql" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data '{
    "query": "{ viewer { accounts(filter: {accountTag: \"ACCOUNT_ID\"}) { accessLoginRequestsAdaptiveGroups(filter: {datetime_gt: \"2026-02-22T00:00:00Z\"}, limit: 100, orderBy: [count_DESC]) { dimensions { action appName userEmail country } count } } } }"
  }'
```

## Key Concepts

| Term | Definition |
|------|------------|
| Cloudflare Tunnel | Encrypted outbound-only connection from your infrastructure to Cloudflare's network, exposing internal services without opening inbound firewall ports |
| Cloudflare Access | Identity-aware reverse proxy evaluating every request against access policies before granting access to protected applications |
| WARP Client | Cloudflare's endpoint agent that routes device traffic through Cloudflare's network for policy enforcement and private network access |
| Access Application | Configuration object defining protected resource (self-hosted, SaaS, or infrastructure) with associated access policies |
| Device Posture | Endpoint health signals (OS version, disk encryption, EDR status) evaluated as conditions in Access policies |
| Cloudflare One | Unified SASE platform combining ZTNA (Access), SWG (Gateway), CASB, DLP, and RBI |

## Tools & Systems

- **Cloudflare Access**: Identity-aware application proxy providing per-request authorization
- **Cloudflare Tunnel (cloudflared)**: Daemon creating encrypted tunnels from internal networks to Cloudflare edge
- **WARP Client**: Cross-platform endpoint agent for device enrollment, DNS filtering, and private network routing
- **Cloudflare Gateway**: Secure Web Gateway providing DNS/HTTP filtering and DLP inspection
- **Cloudflare Logpush**: Real-time log streaming to external SIEM and storage destinations
- **Access for Infrastructure**: SSH and RDP access with short-lived certificates and session recording

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/deploying-cloudflare-access-for-zero-trust
