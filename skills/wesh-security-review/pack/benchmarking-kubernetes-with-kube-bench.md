---
name: benchmarking-kubernetes-with-kube-bench
description: Installs and runs the kube-bench tool against a Kubernetes cluster as a Job, DaemonSet, or standalone binary, selecting the correct benchmark version and targets (control plane, etcd, kubelet, worker nodes) and emitting JSON or JUnit output for pipelines.
subdomain: container-security
facing: config
mitre_attack:
- T1610
nist_csf:
- PR.PS-01
upstream: benchmarking-kubernetes-with-kube-bench@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Access to cluster: either SSH access to control-plane/worker node (binary mode) or `kubectl` with permission to create Jobs (in-cluster mode).
- Knowledge of cluster's Kubernetes version (kube-bench auto-detects, or specify with `--version` / `--benchmark`).
- Install kube-bench (Aqua Security official methods):

```bash
# Binary release (Linux)
KB_VERSION=0.10.7
curl -L -o kube-bench.tgz \
  "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VERSION}/kube-bench_${KB_VERSION}_linux_amd64.tar.gz"
tar -xzf kube-bench.tgz
sudo mv kube-bench /usr/local/bin/
sudo cp -R cfg /etc/kube-bench/cfg
# Via Go install
go install github.com/aquasecurity/kube-bench@latest
# Run as a one-off container directly on a node (mounts host config)
docker run --rm --pid=host \
  -v /etc:/etc:ro -v /var:/var:ro \
  -t docker.io/aquasec/kube-bench:latest run --targets node
# Verify
kube-bench version
```

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|--------------|------|--------|-----------|
| T1610 | Deploy Container | Execution / Defense Evasion | CIS Benchmark hardening enforced by kube-bench restricts privileged/host-namespace deployments, anonymous API access, and insecure kubelet settings that adversaries abuse when deploying malicious containers. |

## Workflow

### 1. Run default scan (auto-detect)

Run all applicable targets, letting kube-bench detect Kubernetes version and benchmark:

```bash
sudo kube-bench
```

### 2. Run as Kubernetes Job (in-cluster)

Apply provided Job manifest from kube-bench repo and read results from pod logs:

```bash
# General-purpose job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
# Wait, then retrieve results
kubectl get pods -l app=kube-bench
kubectl logs -l app=kube-bench
# Platform-specific jobs are available, e.g. EKS:
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job-eks.yaml
```

### 3. Target specific components

Use `run --targets` to scope scan to particular component groups:

```bash
# Control-plane (API server, scheduler, controller manager)
sudo kube-bench run --targets master
# Worker node (kubelet, proxy)
sudo kube-bench run --targets node
# etcd datastore
sudo kube-bench run --targets etcd
# Cluster-wide policies (RBAC, pod security, network policy)
sudo kube-bench run --targets policies
# Combine multiple targets
sudo kube-bench run --targets master,node,etcd,policies
```

### 4. Pin specific benchmark or Kubernetes version

When auto-detection is wrong or you must audit against specific revision, pin benchmark explicitly:

```bash
# Pin to a specific CIS benchmark revision
sudo kube-bench run --benchmark cis-1.8
# Or map by Kubernetes version
sudo kube-bench --version 1.27
# Managed/distribution-specific benchmarks
sudo kube-bench run --benchmark eks-1.5.0
sudo kube-bench run --benchmark gke-1.6.0
sudo kube-bench run --benchmark rke2-cis-1.7
```

### 5. Run or skip individual checks

Focus on or exclude specific check IDs during remediation cycles:

```bash
# Run only specific checks
sudo kube-bench run --targets master --check 1.2.1,1.2.2
# Skip noisy/known-accepted checks
sudo kube-bench run --targets node --skip 4.2.6
```

### 6. Produce machine-readable output

Emit JSON or JUnit for ingestion into pipelines, SIEM, or dashboards, and write to file:

```bash
# JSON to a file
sudo kube-bench run --targets master,node --json --outputfile kube-bench-report.json
# JUnit (for CI test reporting)
sudo kube-bench --junit --outputfile kube-bench-junit.xml
# AWS Security Finding Format (for Security Hub)
sudo kube-bench run --targets node --asff
```

### 7. Triage and remediate FAIL/WARN findings

Each failing check prints remediation. Apply CIS-recommended fix on node/manifest, e.g. tightening API server flags in static pod manifest:

```bash
# Example remediation for a common control-plane FAIL:
# CIS 1.2.x — ensure anonymous-auth is disabled on the API server.
# Edit the static pod manifest and set the flag:
sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
#   - --anonymous-auth=false
# The kubelet restarts the static pod automatically.
# Example node remediation — kubelet config file permissions (CIS 4.1.x):
sudo chmod 600 /etc/kubernetes/kubelet/kubelet-config.json
sudo chown root:root /etc/kubernetes/kubelet/kubelet-config.json
```

### 8. Re-validate after remediation

Re-run relevant target and confirm previously failing checks now PASS, then track score over time:

```bash
sudo kube-bench run --targets master --check 1.2.1 --json --outputfile recheck.json
# Optional: persist results to PostgreSQL for trend tracking
sudo kube-bench run --targets master,node --pgsql
```

## Tools and Resources

| Tool / Resource | Purpose | Link |
|------------------|---------|------|
| kube-bench | CIS Kubernetes Benchmark checker | https://github.com/aquasecurity/kube-bench |
| kube-bench docs | Running / platforms / flags | https://aquasecurity.github.io/kube-bench/ |
| CIS Kubernetes Benchmark | Source hardening standard | https://www.cisecurity.org/benchmark/kubernetes |
| Trivy Operator | Continuous in-cluster compliance + vuln scanning | https://github.com/aquasecurity/trivy-operator |
| kube-hunter | Complementary penetration-testing tool | https://github.com/aquasecurity/kube-hunter |

## Validation Criteria

- [ ] kube-bench installed (`kube-bench version`) or running as Job.
- [ ] Scan run against correct benchmark for cluster's Kubernetes version.
- [ ] master, node, etcd, and policies targets each scanned.
- [ ] JSON/JUnit output produced for pipeline/dashboard ingestion.
- [ ] FAIL and WARN findings triaged and prioritized.
- [ ] CIS remediation applied to control-plane manifests and node configs.
- [ ] Re-run confirms previously failing checks now PASS.
- [ ] Results tracked over time (file archive or PostgreSQL).

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/benchmarking-kubernetes-with-kube-bench
