---
name: implementing-gcp-vpc-firewall-rules
description: Implements and audits GCP VPC firewall rules using gcloud, covering auditing overly permissive rules, creating restrictive ingress/egress rules, hierarchical firewall policies, and monitoring rule effectiveness with VPC Flow Logs.
subdomain: cloud-security
facing: config
mitre_attack:
- T1078.004
- T1530
- T1537
- T1580
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: implementing-gcp-vpc-firewall-rules@54a7988 Apache-2.0, modified by wesh
---
Not for: application-layer filtering (use Cloud Armor WAF), for DNS-based filtering (use Cloud DNS response policies), or for VPN/interconnect traffic filtering without understanding that VPC firewall rules apply to traffic within the VPC.

## Prerequisites

- GCP project with Compute Engine API enabled
- IAM roles: `roles/compute.securityAdmin` for firewall management, `roles/compute.networkViewer` for auditing
- Organization Admin role for hierarchical firewall policies
- gcloud CLI authenticated with appropriate permissions
- VPC Flow Logs enabled on target subnets for monitoring

## Workflow

### Step 1: Audit Existing Firewall Rules for Security Gaps

Enumerate all firewall rules and identify overly permissive configurations.

```bash
# List all firewall rules in the project
gcloud compute firewall-rules list \
  --format="table(name, network, direction, priority, allowed[].map().firewall_rule().list():label=ALLOWED, sourceRanges, targetTags)"
# Find rules allowing all traffic from 0.0.0.0/0
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0" \
  --format="table(name, network, allowed, priority, targetTags)" \
  --sort-by=priority
# Find rules allowing all protocols and ports
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND allowed[].IPProtocol=all" \
  --format="table(name, network, sourceRanges, targetTags)"
# Find rules with SSH (22) or RDP (3389) open to the internet
gcloud compute firewall-rules list \
  --filter="direction=INGRESS AND sourceRanges=0.0.0.0/0 AND (allowed[].ports=22 OR allowed[].ports=3389)" \
  --format="table(name, network, allowed, sourceRanges)"
# Check for disabled rules
gcloud compute firewall-rules list \
  --filter="disabled=true" \
  --format="table(name, network, direction)"
```

### Step 2: Create Restrictive Ingress Firewall Rules

Implement least-privilege ingress rules using network tags and service accounts for targeting.

```bash
# Create rule allowing HTTPS from the internet to web servers only
gcloud compute firewall-rules create allow-https-web \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --source-ranges=0.0.0.0/0 \
  --target-tags=web-server \
  --priority=1000 \
  --description="Allow HTTPS to web servers from internet"
# Create rule allowing SSH only from bastion host subnet
gcloud compute firewall-rules create allow-ssh-bastion \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --source-ranges=10.0.1.0/24 \
  --target-tags=ssh-allowed \
  --priority=1000 \
  --description="Allow SSH only from bastion subnet"
# Create rule allowing internal communication between app tiers
gcloud compute firewall-rules create allow-app-to-db \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:5432 \
  --source-tags=app-server \
  --target-tags=db-server \
  --priority=1000 \
  --description="Allow PostgreSQL from app tier to database tier"
# Create service-account-based rule (more secure than tags)
gcloud compute firewall-rules create allow-api-internal \
  --network=production-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8080 \
  --source-service-accounts=api-client@project.iam.gserviceaccount.com \
  --target-service-accounts=api-server@project.iam.gserviceaccount.com \
  --priority=1000
```

### Step 3: Implement Egress Restrictions

Configure egress firewall rules to control outbound traffic and prevent data exfiltration.

```bash
# Deny all egress by default (low priority)
gcloud compute firewall-rules create deny-all-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=DENY \
  --rules=all \
  --destination-ranges=0.0.0.0/0 \
  --priority=65534 \
  --description="Default deny all egress traffic"
# Allow egress to Google APIs via restricted VIP
gcloud compute firewall-rules create allow-google-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=199.36.153.4/30 \
  --priority=1000 \
  --description="Allow HTTPS to Google APIs restricted VIP"
# Allow DNS resolution
gcloud compute firewall-rules create allow-dns-egress \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=udp:53,tcp:53 \
  --destination-ranges=169.254.169.254/32,8.8.8.8/32,8.8.4.4/32 \
  --priority=1000 \
  --description="Allow DNS resolution to metadata and Google DNS"
# Allow egress to specific external services
gcloud compute firewall-rules create allow-external-apis \
  --network=production-vpc \
  --direction=EGRESS \
  --action=ALLOW \
  --rules=tcp:443 \
  --destination-ranges=PARTNER_CIDR/32 \
  --target-tags=api-client \
  --priority=1000
```

### Step 4: Deploy Hierarchical Firewall Policies

Create organization and folder-level firewall policies that apply across all projects.

```bash
# Create an organization-level firewall policy
gcloud compute firewall-policies create \
  --organization=ORG_ID \
  --short-name=org-security-policy \
  --description="Organization-wide security firewall policy"
# Add rule to block known malicious IP ranges at org level
gcloud compute firewall-policies rules create 100 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=deny \
  --src-ip-ranges=THREAT_INTEL_CIDR_1,THREAT_INTEL_CIDR_2 \
  --layer4-configs=all \
  --description="Block known malicious IPs organization-wide"
# Add rule to enforce HTTPS-only ingress at org level
gcloud compute firewall-policies rules create 200 \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID \
  --direction=INGRESS \
  --action=allow \
  --src-ip-ranges=0.0.0.0/0 \
  --layer4-configs=tcp:443 \
  --description="Allow only HTTPS from external sources"
# Associate policy with the organization
gcloud compute firewall-policies associations create \
  --firewall-policy=org-security-policy \
  --organization=ORG_ID
```

### Step 5: Enable VPC Flow Logs for Monitoring

Configure VPC Flow Logs to monitor traffic patterns and validate firewall rule effectiveness.

```bash
# Enable flow logs on a subnet
gcloud compute networks subnets update production-subnet \
  --region=us-central1 \
  --enable-flow-logs \
  --logging-aggregation-interval=interval-5-sec \
  --logging-flow-sampling=1.0 \
  --logging-metadata=include-all
# Query flow logs in Cloud Logging for denied traffic
gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.disposition="DENIED"
  AND timestamp>="2026-02-22T00:00:00Z"
' --limit=50 --format=json
# Find traffic hitting overly permissive rules
gcloud logging read '
  resource.type="gce_subnetwork"
  AND jsonPayload.rule_details.reference:"/firewall-rules/default-allow-"
' --limit=100 --format="table(jsonPayload.connection.src_ip,jsonPayload.connection.dest_ip,jsonPayload.connection.dest_port)"
# Export flow logs to BigQuery for analysis
gcloud logging sinks create vpc-flow-bq \
  bigquery.googleapis.com/projects/PROJECT/datasets/vpc_flow_logs \
  --log-filter='resource.type="gce_subnetwork"'
```

## Key Concepts

| Term | Definition |
|------|------------|
| VPC Firewall Rule | Stateful network-level access control that allows or denies traffic to and from VM instances based on IP ranges, protocols, ports, and tags |
| Hierarchical Firewall Policy | Organization or folder-level firewall policy i.e. evaluated before VPC-level rules and applies across all child projects |
| Network Tag | Label applied to VM instances that determines which firewall rules apply, used for targeting ingress and egress rules |
| Service Account Firewall Rule | Firewall rule that targets instances based on their attached service account, providing more secure targeting than mutable network tags |
| VPC Flow Logs | Network telemetry captured at subnet level that records traffic metadata for monitoring, forensics, and firewall rule validation |
| Implied Rules | Default GCP firewall rules that allow egress to all destinations and deny ingress from all sources, with lowest priority (65535) |

## Tools & Systems

- **gcloud compute firewall-rules**: CLI commands for creating, listing, and managing VPC firewall rules in GCP
- **Hierarchical Firewall Policies**: Organization and folder-level policies enforcing security controls across all projects
- **VPC Flow Logs**: Subnet-level traffic logging for monitoring, troubleshooting, and validating firewall effectiveness
- **Cloud Logging**: Query engine for analyzing VPC Flow Logs and firewall rule hit counts
- **Security Command Center**: GCP-native security platform with findings for overly permissive firewall configurations

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-gcp-vpc-firewall-rules
