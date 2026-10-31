---
name: implementing-beyondcorp-zero-trust-access-model
description: Implement Google's BeyondCorp zero trust access model using Cloud IAP, Access Context Manager, Endpoint Verification, Chrome Enterprise Premium, and BeyondCorp Enterprise Connectors to enforce identity- and device-aware access for VPN-less application access.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1078.004
- T1530
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: implementing-beyondcorp-zero-trust-access-model@54a7988 Apache-2.0, modified by wesh
---
Not for: applications require raw network-level access (e.g., UDP-based protocols not supported by IAP), for consumer-facing public applications, or when the organization lacks an identity provider with MFA capabilities.

## Prerequisites

- Google Cloud organization with Cloud Identity or Google Workspace
- Identity-Aware Proxy (IAP) API enabled on GCP project
- Chrome Enterprise Premium license for endpoint verification
- Applications deployed behind Google Cloud Load Balancer or on App Engine/Cloud Run
- Endpoint Verification extension deployed on all corporate devices
- Access Context Manager API enabled

## Workflow

### Step 1: Configure Access Context Manager with Access Levels

Define access levels that represent trust tiers based on device and user attributes.

```bash
# Enable required APIs
gcloud services enable iap.googleapis.com
gcloud services enable accesscontextmanager.googleapis.com
gcloud services enable beyondcorp.googleapis.com
# Create an access policy (organization level)
gcloud access-context-manager policies create \
  --organization=ORG_ID \
  --title="BeyondCorp Enterprise Policy"
# Create a basic access level for corporate managed devices
cat > corporate-device-level.yaml << 'EOF'
- devicePolicy:
    allowedEncryptionStatuses:
      - ENCRYPTED
    osConstraints:
      - osType: DESKTOP_CHROME_OS
        minimumVersion: "13816.0.0"
      - osType: DESKTOP_WINDOWS
        minimumVersion: "10.0.19045"
      - osType: DESKTOP_MAC
        minimumVersion: "13.0.0"
    requireScreenlock: true
    requireAdminApproval: true
  regions:
    - US
    - GB
    - DE
EOF
gcloud access-context-manager levels create corporate-managed \
  --policy=POLICY_ID \
  --title="Corporate Managed Device" \
  --basic-level-spec=corporate-device-level.yaml
# Create a custom access level using CEL expressions
gcloud access-context-manager levels create high-trust \
  --policy=POLICY_ID \
  --title="High Trust Level" \
  --custom-level-spec=high-trust-cel.yaml
```

### Step 2: Deploy Identity-Aware Proxy on Applications

Enable IAP on backend services to enforce identity verification before granting access.

```bash
# Create OAuth consent screen
gcloud iap oauth-brands create \
  --application_title="Corporate Applications" \
  --support_email=security@company.com
# Create OAuth client for IAP
gcloud iap oauth-clients create BRAND_NAME \
  --display_name="BeyondCorp IAP Client"
# Enable IAP on a backend service (GCE/GKE behind HTTPS LB)
gcloud compute backend-services update internal-app-backend \
  --iap=enabled,oauth2-client-id=CLIENT_ID,oauth2-client-secret=CLIENT_SECRET \
  --global
# Enable IAP on App Engine
gcloud iap web enable \
  --resource-type=app-engine \
  --oauth2-client-id=CLIENT_ID \
  --oauth2-client-secret=CLIENT_SECRET
# Enable IAP on Cloud Run service
gcloud run services add-iam-policy-binding internal-api \
  --member="serviceAccount:service-PROJECT_NUM@gcp-sa-iap.iam.gserviceaccount.com" \
  --role="roles/run.invoker" \
  --region=us-central1
```

### Step 3: Configure IAM Bindings with Access Level Conditions

Bind IAP access to specific groups with access level requirements.

```bash
# Grant access to engineering group with corporate device requirement
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=internal-app-backend \
  --member="group:engineering@company.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition="expression=accessPolicies/POLICY_ID/accessLevels/corporate-managed,title=Require Corporate Device"
# Grant access to contractors with high-trust requirement
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --service=internal-app-backend \
  --member="group:contractors@company.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --condition="expression=accessPolicies/POLICY_ID/accessLevels/high-trust,title=Require High Trust"
# Configure re-authentication settings (session duration)
gcloud iap settings set --project=PROJECT_ID \
  --resource-type=compute \
  --service=internal-app-backend \
  --reauth-method=LOGIN \
  --max-session-duration=3600s
```

### Step 4: Deploy Endpoint Verification on Corporate Devices

Roll out Chrome Enterprise Endpoint Verification for device posture collection.

```bash
# Deploy Endpoint Verification via Chrome policy (managed browsers)
# In Google Admin Console > Devices > Chrome > Apps & extensions
# Force-install: Endpoint Verification extension ID: callobklhcbilhphinckomhgkigmfocg
# Verify device inventory in Admin SDK
gcloud endpoint-verification list-endpoints \
  --filter="deviceType=CHROME_BROWSER" \
  --format="table(deviceId, osVersion, isCompliant, encryptionStatus)"
# Create device trust connector for third-party EDR signals
gcloud beyondcorp app connections create crowdstrike-connector \
  --project=PROJECT_ID \
  --location=global \
  --application-endpoint=host=crowdstrike-api.internal:443,port=443 \
  --type=TCP_PROXY_TUNNEL \
  --connectors=projects/PROJECT_ID/locations/us-central1/connectors/connector-1
# List enrolled devices and their compliance status
gcloud alpha devices list --format="table(name,deviceType,complianceState)"
```

### Step 5: Implement BeyondCorp Enterprise Threat Protection

Enable URL filtering, malware scanning, and DLP for Chrome Enterprise users.

```bash
# Configure Chrome Enterprise Premium threat protection rules
# In Google Admin Console > Security > Chrome Enterprise Premium
# Create a BeyondCorp Enterprise connector for on-prem apps
gcloud beyondcorp app connectors create onprem-connector \
  --project=PROJECT_ID \
  --location=us-central1 \
  --display-name="On-Premises App Connector"
gcloud beyondcorp app connections create hr-portal \
  --project=PROJECT_ID \
  --location=us-central1 \
  --application-endpoint=host=hr.internal.company.com,port=443 \
  --type=TCP_PROXY_TUNNEL \
  --connectors=projects/PROJECT_ID/locations/us-central1/connectors/onprem-connector
# Enable security investigation tool for access anomaly detection
gcloud logging read '
  resource.type="iap_tunnel"
  jsonPayload.decision="DENY"
  timestamp >= "2026-02-22T00:00:00Z"
' --project=PROJECT_ID --format=json --limit=100
```

### Step 6: Monitor and Audit BeyondCorp Access Decisions

Set up comprehensive logging and alerting for zero trust policy enforcement.

```bash
# Create a log sink for IAP access decisions
gcloud logging sinks create iap-access-audit \
  --destination=bigquery.googleapis.com/projects/PROJECT_ID/datasets/beyondcorp_audit \
  --log-filter='resource.type="iap_tunnel" OR resource.type="gce_backend_service"'
# Query BigQuery for access pattern analysis
bq query --use_legacy_sql=false '
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail AS user,
  resource.labels.backend_service_name AS application,
  JSON_EXTRACT_SCALAR(protopayload_auditlog.requestMetadata.callerSuppliedUserAgent, "$") AS device,
  protopayload_auditlog.status.code AS decision_code,
  COUNT(*) AS request_count
FROM `PROJECT_ID.beyondcorp_audit.cloudaudit_googleapis_com_data_access`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
GROUP BY user, application, device, decision_code
ORDER BY request_count DESC
LIMIT 50
'
# Create an alert policy for repeated access denials
gcloud alpha monitoring policies create \
  --display-name="BeyondCorp Repeated Access Denials" \
  --condition-display-name="High denial rate" \
  --condition-filter='resource.type="iap_tunnel" AND jsonPayload.decision="DENY"' \
  --condition-threshold-value=10 \
  --condition-threshold-duration=300s \
  --notification-channels=projects/PROJECT_ID/notificationChannels/CHANNEL_ID
```

## Key Concepts

| Term | Definition |
|------|------------|
| BeyondCorp | Google's zero trust security framework that shifts access controls from network perimeter to per-request identity and device verification |
| Identity-Aware Proxy (IAP) | Google Cloud service that intercepts HTTP requests and verifies user identity and device context before forwarding to backend applications |
| Access Context Manager | GCP service that defines fine-grained attribute-based access control policies using access levels and service perimeters |
| Endpoint Verification | Chrome Enterprise extension that collects device attributes (OS version, encryption, screen lock) for access level evaluation |
| Access Levels | Named conditions in Access Context Manager that define minimum requirements (device posture, IP range, geography) for resource access |
| Chrome Enterprise Premium | Google's commercial BeyondCorp offering providing threat protection, URL filtering, DLP, and continuous access evaluation |

## Tools & Systems

- **Google Cloud IAP**: Identity-aware reverse proxy enforcing per-request authentication and authorization for GCP-hosted applications
- **Access Context Manager**: Policy engine defining access levels based on device attributes, IP ranges, and geographic locations
- **Chrome Enterprise Premium**: Extended BeyondCorp capabilities including real-time threat protection and data loss prevention
- **Endpoint Verification**: Device posture collection agent deployed as Chrome extension to all corporate endpoints
- **BeyondCorp Enterprise Connectors**: Secure tunnel connectors enabling IAP protection for on-premises applications
- **Cloud Audit Logs**: Immutable log records of all IAP access decisions for compliance and forensic analysis

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-beyondcorp-zero-trust-access-model
