---
name: analyzing-ethereum-smart-contract-vulnerabilities
description: Perform static and symbolic analysis of Solidity smart contracts using Slither and Mythril to detect reentrancy, integer overflow, access control, and other vulnerability classes before deployment to Ethereum mainnet.
subdomain: blockchain-security
facing: config
mitre_attack:
- T1190
- T1059
nist_csf:
- PR.DS-01
- PR.DS-02
- ID.RA-01
upstream: analyzing-ethereum-smart-contract-vulnerabilities@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Python 3.10+ with pip
- Slither (pip install slither-analyzer) and solc compiler
- Mythril (pip install mythril) with solc-select for compiler version management
- Solidity source code or compiled contract bytecode
- Foundry or Hardhat development framework (optional, for project-level analysis)

## Steps

### Step 1: Run Slither Static Analysis

Execute Slither against contract codebase to identify vulnerability patterns, optimization opportunities, and code quality issues using its 90+ built-in detectors.

### Step 2: Run Mythril Symbolic Execution

Run Mythril deep analysis to explore execution paths and discover reentrancy, unchecked external calls, and arithmetic vulnerabilities that require path-sensitive analysis.

### Step 3: Triage and Correlate Findings

Combine results from both tools, deduplicate findings, assess severity based on exploitability and financial impact, and filter false positives.

### Step 4: Generate Audit Report

Produce structured audit report with vulnerability descriptions, affected code locations, exploit scenarios, and remediation recommendations.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-ethereum-smart-contract-vulnerabilities
