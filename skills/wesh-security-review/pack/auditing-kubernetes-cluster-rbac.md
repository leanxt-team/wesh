---
name: auditing-kubernetes-cluster-rbac
description: Auditing Kubernetes cluster RBAC configurations to identify overly permissive roles, wildcard permissions, dangerous ClusterRoleBindings, service account abuse, and privilege escalation paths using kubectl, rbac-tool, KubiScan, and Kubeaudit.
subdomain: cloud-security
facing: config
mitre_attack:
- T1098.006
- T1552.007
- T1611
- T1613
- T1078.004
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
upstream: auditing-kubernetes-cluster-rbac@54a7988 Apache-2.0, modified by wesh
---
Not for: network policy auditing (use Cilium or Calico network policy tools), for container image scanning (use Trivy or Grype), or for runtime security monitoring (use Falco or Sysdig Secure).

## Prerequisites

- kubectl configured with cluster-admin or equivalent read permissions to target cluster
- rbac-tool installed (`kubectl krew install rbac-tool` or binary from GitHub)
- KubiScan installed (`pip install kubiscan`)
- Kubeaudit installed (`brew install kubeaudit` or from GitHub releases)
- Access to cluster's audit logs for correlating RBAC findings with actual API access

## Workflow

### Step 1: Enumerate ClusterRoles and Roles with Dangerous Permissions

Identify roles with wildcard permissions, secret access, pod exec, or escalation capabilities.

```bash
# List all ClusterRoles with wildcard verb access
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        verbs = rule.get('verbs', [])
        resources = rule.get('resources', [])
        if '*' in verbs or '*' in resources:
            print(f'ClusterRole: {name}')
            print(f'  Verbs: {verbs}')
            print(f'  Resources: {resources}')
            print(f'  API Groups: {rule.get(\"apiGroups\", [])}')
            print()
"
# Find roles that can read secrets
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        resources = rule.get('resources', [])
        verbs = rule.get('verbs', [])
        if ('secrets' in resources or '*' in resources) and ('get' in verbs or 'list' in verbs or '*' in verbs):
            if not name.startswith('system:'):
                print(f'ClusterRole: {name} -> can access secrets (verbs: {verbs})')
"
# Find roles with pod/exec permissions (container escape risk)
kubectl get clusterroles -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for role in data['items']:
    name = role['metadata']['name']
    for rule in role.get('rules', []):
        resources = rule.get('resources', [])
        if 'pods/exec' in resources or 'pods/*' in resources:
            print(f'ClusterRole: {name} -> has pods/exec access')
"
```

### Step 2: Audit ClusterRoleBindings and RoleBindings

Review bindings to identify who has elevated access and detect overly broad group assignments.

```bash
# List all ClusterRoleBindings with the subjects
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    name = binding['metadata']['name']
    role = binding['roleRef']['name']
    subjects = binding.get('subjects', [])
    for subject in subjects:
        kind = subject.get('kind', '')
        subj_name = subject.get('name', '')
        ns = subject.get('namespace', 'cluster-wide')
        print(f'{name} -> Role: {role} | {kind}: {subj_name} ({ns})')
" | sort
# Find bindings to cluster-admin
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    if binding['roleRef']['name'] == 'cluster-admin':
        print(f\"Binding: {binding['metadata']['name']}\")
        for subject in binding.get('subjects', []):
            print(f\"  {subject.get('kind')}: {subject.get('name')} (ns: {subject.get('namespace', 'N/A')})\")
"
# Find bindings granting access to all authenticated users
kubectl get clusterrolebindings -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for binding in data['items']:
    for subject in binding.get('subjects', []):
        if subject.get('name') in ['system:authenticated', 'system:unauthenticated']:
            print(f\"WARNING: {binding['metadata']['name']} grants {binding['roleRef']['name']} to {subject['name']}\")
"
```

### Step 3: Scan with rbac-tool for Comprehensive Analysis

Use rbac-tool for automated RBAC analysis including who-can queries and policy generation.

```bash
# Who can get secrets across all namespaces
kubectl rbac-tool who-can get secrets
# Who can create pods (potential for container escape)
kubectl rbac-tool who-can create pods
# Who can exec into pods
kubectl rbac-tool who-can create pods/exec
# Who can escalate privileges (bind/escalate verbs)
kubectl rbac-tool who-can bind clusterroles
kubectl rbac-tool who-can escalate clusterroles
# Generate RBAC policy report
kubectl rbac-tool analysis
# Visualize RBAC relationships
kubectl rbac-tool viz --outformat dot > rbac-graph.dot
dot -Tpng rbac-graph.dot -o rbac-graph.png
```

### Step 4: Run KubiScan for Risky Permissions Detection

Use KubiScan to automatically identify risky service accounts, pods, and RBAC configurations.

```bash
# Run KubiScan to find risky roles
python3 -m kubiscan -rroles   # List risky Roles
python3 -m kubiscan -rcr      # List risky ClusterRoles
python3 -m kubiscan -rrb      # List risky RoleBindings
python3 -m kubiscan -rcrb     # List risky ClusterRoleBindings
# Find risky service accounts
python3 -m kubiscan -rs       # Risky service accounts
# Find pods running with risky service accounts
python3 -m kubiscan -rp       # Risky pods
# Check for privilege escalation paths
python3 -m kubiscan -pe       # Privilege escalation vectors
# Generate full report
python3 -m kubiscan -a        # All checks
```

### Step 5: Audit Service Account Token Mounting and Usage

Check for unnecessary service account token mounts that could enable lateral movement from compromised pods.

```bash
# Find pods with automounted service account tokens
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pod in data['items']:
    name = pod['metadata']['name']
    ns = pod['metadata']['namespace']
    sa = pod['spec'].get('serviceAccountName', 'default')
    automount = pod['spec'].get('automountServiceAccountToken', True)
    if automount and sa != 'default':
        print(f'{ns}/{name} -> SA: {sa} (token auto-mounted)')
"
# Find service accounts with non-default token secrets
kubectl get serviceaccounts --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for sa in data['items']:
    name = sa['metadata']['name']
    ns = sa['metadata']['namespace']
    secrets = sa.get('secrets', [])
    if name != 'default' and len(secrets) > 0:
        print(f'{ns}/{name}: {len(secrets)} secret(s) bound')
"
# Check for pods running as privileged or with host access
kubectl get pods --all-namespaces -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pod in data['items']:
    name = pod['metadata']['name']
    ns = pod['metadata']['namespace']
    for container in pod['spec'].get('containers', []):
        sc = container.get('securityContext', {})
        if sc.get('privileged', False) or sc.get('runAsUser', 1) == 0:
            print(f'RISK: {ns}/{name}/{container[\"name\"]} - privileged={sc.get(\"privileged\",False)} runAsRoot={sc.get(\"runAsUser\",\"not set\")==0}')
"
```

### Step 6: Run Kubeaudit for RBAC and Security Policy Validation

Execute Kubeaudit for comprehensive security checks including RBAC-related findings.

```bash
# Run all kubeaudit checks
kubeaudit all --kubeconfig ~/.kube/config
# Run specific RBAC-related checks
kubeaudit privesc    # Check for allowPrivilegeEscalation
kubeaudit rootfs     # Check for readOnlyRootFilesystem
kubeaudit nonroot    # Check for runAsNonRoot
kubeaudit capabilities  # Check for dangerous capabilities
# Output as JSON for processing
kubeaudit all --kubeconfig ~/.kube/config -f json > kubeaudit-results.json
```

## Key Concepts

| Term | Definition |
|------|------------|
| RBAC | Role-Based Access Control in Kubernetes, method for regulating access to cluster resources based on roles of individual users or service accounts |
| ClusterRole | Cluster-wide role definition that specifies permissions (verbs on resources) applicable across all namespaces |
| ClusterRoleBinding | Associates ClusterRole with subjects (users, groups, service accounts) at cluster scope |
| Service Account | Identity associated with pods for authenticating to Kubernetes API server, automatically mounted unless disabled |
| automountServiceAccountToken | Pod spec field controlling whether service account token is automatically mounted into pod filesystem |
| Privilege Escalation | RBAC verbs (bind, escalate, impersonate) that allow user to grant themselves or others elevated permissions |

## Tools & Systems

- **kubectl**: Primary CLI for querying Kubernetes RBAC resources (roles, bindings, service accounts)
- **rbac-tool**: kubectl plugin for RBAC analysis including who-can queries, visualization, and policy generation
- **KubiScan**: Python tool for scanning Kubernetes RBAC for risky permissions and privilege escalation paths
- **Kubeaudit**: Security auditing tool that checks pods and workloads for security anti-patterns including RBAC issues
- **rakkess**: kubectl plugin showing access matrix for current user across all resource types

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-kubernetes-cluster-rbac
