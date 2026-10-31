---
name: implementing-container-network-policies-with-calico
description: Uses Calico's own policy CRDs beyond the upstream Kubernetes API - GlobalNetworkPolicy, HostEndpoint, NetworkSet, policy tiers, and DNS-based egress rules - applied and audited with calicoctl.
subdomain: container-security
facing: config
mitre_attack:
- T1610
- T1611
- T1609
- T1525
nist_csf:
- PR.PS-01
- PR.IR-01
- ID.AM-08
- DE.CM-01
upstream: implementing-container-network-policies-with-calico@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Kubernetes cluster with Calico CNI installed
- Python 3.9+ with `kubernetes` client library
- calicoctl CLI tool installed and configured
- kubectl access with RBAC permissions for network policy management

## Steps

### Step 1: Audit Existing Network Policies
Use calicoctl and kubectl to inventory current network policies and identify unprotected namespaces.

### Step 2: Implement Default-Deny Policies
Create default-deny ingress and egress policies per namespace as zero-trust baseline.

### Step 3: Create Workload-Specific Allow Rules
Define granular allow rules for legitimate pod-to-pod and pod-to-service communication.

### Step 4: Validate Policy Enforcement
Test connectivity between pods to verify policies are correctly enforced.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/implementing-container-network-policies-with-calico
