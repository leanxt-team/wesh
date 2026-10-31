---
name: implementing-microsegmentation-with-guardicore
description: Implements microsegmentation with Akamai Guardicore Segmentation to map application dependencies, visualize east-west traffic flows, and create granular, least-privilege network policies across VMs, containers, bare metal, and cloud.
subdomain: zero-trust-architecture
facing: config
mitre_attack:
- T1078
- T1190
- T1059
- T1021
- T1550
nist_csf:
- PR.AA-01
- PR.AA-05
- PR.IR-01
- GV.PO-01
upstream: implementing-microsegmentation-with-guardicore@54a7988 Apache-2.0, modified by wesh
---
Not for: perimeter-only security (use traditional firewalls), for environments with fewer than 50 workloads where VLANs/security groups suffice, or when network team lacks capacity for ongoing policy management.

## Prerequisites

- Akamai Guardicore Segmentation license (Enterprise or Premium)
- Guardicore Management Server deployed (on-prem or SaaS)
- Agent deployment access to target workloads (Linux, Windows, Kubernetes)
- Network visibility: SPAN/TAP ports or VPC flow logs for agentless collection
- Application owner engagement for dependency validation

## Workflow

### Step 1: Deploy Guardicore Agents on Workloads

Install agents to collect process-level network communication data.

```bash
# Linux agent installation
curl -sSL https://management.guardicore.com/api/v3.0/agents/download/linux \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -o gc-agent-installer.sh
chmod +x gc-agent-installer.sh
sudo ./gc-agent-installer.sh \
  --management-url=https://management.guardicore.com \
  --site-id=datacenter-east \
  --label="web-tier"
# Windows agent installation (PowerShell)
# Invoke-WebRequest -Uri "https://management.guardicore.com/api/v3.0/agents/download/windows" `
#   -Headers @{"Authorization"="Bearer $GC_API_TOKEN"} `
#   -OutFile gc-agent-installer.exe
# Start-Process -FilePath .\gc-agent-installer.exe `
#   -ArgumentList "--management-url=https://management.guardicore.com","--site-id=datacenter-east" `
#   -Wait
# Kubernetes DaemonSet deployment
cat > gc-daemonset.yaml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: guardicore-agent
  namespace: guardicore
spec:
  selector:
    matchLabels:
      app: gc-agent
  template:
    metadata:
      labels:
        app: gc-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: gc-agent
        image: guardicore/agent:latest
        securityContext:
          privileged: true
        env:
        - name: GC_MANAGEMENT_URL
          value: "https://management.guardicore.com"
        - name: GC_API_KEY
          valueFrom:
            secretKeyRef:
              name: gc-credentials
              key: api-key
        volumeMounts:
        - mountPath: /host
          name: host-root
      volumes:
      - name: host-root
        hostPath:
          path: /
EOF
kubectl apply -f gc-daemonset.yaml
# Verify agent enrollment
curl -s "https://management.guardicore.com/api/v3.0/agents?status=active" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" | python3 -m json.tool
```

### Step 2: Map Application Dependencies with Reveal

Use Guardicore Reveal to discover and visualize application communication patterns.

```bash
# Query discovered application flows via API
curl -s "https://management.guardicore.com/api/v3.0/connections" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{
    "time_range": {"from": "2026-02-17T00:00:00Z", "to": "2026-02-24T00:00:00Z"},
    "filter": {
      "source_label": "web-tier",
      "destination_label": "app-tier"
    },
    "aggregation": "process",
    "limit": 1000
  }' | python3 -m json.tool
# Export application dependency map
curl -s "https://management.guardicore.com/api/v3.0/maps/export" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{
    "format": "json",
    "labels": ["web-tier", "app-tier", "db-tier"],
    "time_range": "7d"
  }' -o app-dependency-map.json
# Typical discovery findings:
# web-tier -> app-tier: TCP 8080, 8443 (expected)
# app-tier -> db-tier: TCP 5432, 3306 (expected)
# web-tier -> db-tier: TCP 5432 (UNEXPECTED - should be blocked)
# app-tier -> internet: TCP 443 (verify if needed)
```

### Step 3: Create Segmentation Labels and Policies

Define labels and create ring-fence policies around applications.

```bash
# Create labels for application tiers
curl -X POST "https://management.guardicore.com/api/v3.0/labels" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PCI-CDE",
    "description": "Cardholder Data Environment workloads",
    "criteria": {"ip_ranges": ["10.10.0.0/16"]},
    "color": "#FF0000"
  }'
# Create segmentation policy: Allow web-to-app communication
curl -X POST "https://management.guardicore.com/api/v3.0/policies" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Web-to-App Allowed",
    "action": "ALLOW",
    "priority": 100,
    "source": {"labels": ["web-tier"]},
    "destination": {"labels": ["app-tier"]},
    "services": [
      {"protocol": "TCP", "port": 8080},
      {"protocol": "TCP", "port": 8443}
    ],
    "log": true,
    "enabled": true,
    "section": "application-segmentation"
  }'
# Create deny policy: Block web-to-database direct access
curl -X POST "https://management.guardicore.com/api/v3.0/policies" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Web-to-DB Direct",
    "action": "DENY",
    "priority": 200,
    "source": {"labels": ["web-tier"]},
    "destination": {"labels": ["db-tier"]},
    "services": [{"protocol": "TCP", "port_range": "1-65535"}],
    "log": true,
    "alert": true,
    "enabled": true
  }'
# Create ring-fence policy for PCI CDE
curl -X POST "https://management.guardicore.com/api/v3.0/policies" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PCI CDE Ring Fence",
    "action": "DENY",
    "priority": 50,
    "source": {"labels": ["!PCI-CDE"]},
    "destination": {"labels": ["PCI-CDE"]},
    "services": [{"protocol": "TCP", "port_range": "1-65535"}],
    "log": true,
    "alert": true,
    "enabled": true
  }'
```

### Step 4: Test Policies in Reveal Mode Before Enforcement

Simulate policy enforcement without blocking traffic.

```bash
# Enable reveal mode (log-only) for new policies
curl -X PATCH "https://management.guardicore.com/api/v3.0/policies/POLICY_ID" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{"enforcement_mode": "REVEAL"}'
# Check what would be blocked in reveal mode
curl -s "https://management.guardicore.com/api/v3.0/violations" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{
    "time_range": "24h",
    "policy_id": "POLICY_ID",
    "limit": 100
  }' | python3 -c "
import json, sys
data = json.load(sys.stdin)
for v in data.get('violations', []):
    print(f\"{v['source_ip']}:{v['source_process']} -> {v['dest_ip']}:{v['dest_port']} [{v['action']}]\")
"
# After validation, switch to enforcement
curl -X PATCH "https://management.guardicore.com/api/v3.0/policies/POLICY_ID" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{"enforcement_mode": "ENFORCE"}'
```

### Step 5: Monitor and Respond to Policy Violations

Set up alerting and continuous monitoring for segmentation violations.

```bash
# Configure SIEM integration for policy violations
curl -X POST "https://management.guardicore.com/api/v3.0/integrations/syslog" \
  -H "Authorization: Bearer ${GC_API_TOKEN}" \
  -d '{
    "name": "Splunk SIEM",
    "host": "splunk-syslog.company.com",
    "port": 514,
    "protocol": "TCP",
    "format": "CEF",
    "events": ["policy_violation", "agent_status", "deception_alert"]
  }'
# Splunk query for microsegmentation violations
# index=guardicore sourcetype=guardicore:policy
# | where action="DENY" AND enforcement_mode="ENFORCE"
# | stats count by src_ip, dst_ip, dst_port, policy_name
# | sort -count
```

## Key Concepts

| Term | Definition |
|------|------------|
| Microsegmentation | Network security technique creating granular security zones around individual workloads or applications to control east-west traffic |
| Reveal Mode | Guardicore's simulation mode that logs policy decisions without enforcing them, allowing validation before blocking |
| Ring-Fence Policy | Isolation policy that restricts all traffic into or out of defined group of assets (e.g., PCI CDE) |
| Application Dependency Map | Visual representation of discovered network communication patterns between workloads showing processes, ports, and protocols |
| East-West Traffic | Network traffic flowing laterally between workloads within data center, as opposed to north-south traffic crossing perimeter |
| Process-Level Visibility | Guardicore's ability to identify which process on workload initiated or received network connection |

## Tools & Systems

- **Akamai Guardicore Segmentation**: Agent-based microsegmentation platform with application visualization and policy enforcement
- **Guardicore Reveal**: Network visualization engine mapping application dependencies across hybrid environments
- **Guardicore Centra**: Management console for policy creation, monitoring, and incident investigation
- **Guardicore Agents**: Lightweight agents deployed on workloads collecting process-level network telemetry
- **Guardicore Insight**: Analytics engine for compliance reporting and segmentation effectiveness measurement

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-microsegmentation-with-guardicore
