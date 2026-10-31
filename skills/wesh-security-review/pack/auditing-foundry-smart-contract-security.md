---
name: auditing-foundry-smart-contract-security
description: Pre-deployment security audit of Solidity smart contracts in a Foundry project.
subdomain: blockchain-security
facing: config
mitre_attack:
- T1190
- T1059
upstream: auditing-foundry-smart-contract-security@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- **Foundry** installed (`forge`, `cast`, `anvil`): `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **Slither** + solc: `pip install slither-analyzer` and `solc-select install <ver> && solc-select use <ver>`
- **Aderyn** (recommended): `cargo install aderyn` (or `npm i -g @cyfrin/aderyn`)
- **Mythril** (optional, slow symbolic exec): `pip install mythril`
- **gitleaks** (key-leak scan): see companion `implementing-secret-scanning-with-gitleaks` skill
- A Foundry project that **compiles** (`forge build` succeeds) — analyzers need build artifacts.
- Solidity ^0.8.x is assumed (built-in overflow checks); pre-0.8 contracts need extra SafeMath review.

> Install Python tools in virtualenv (recommended on externally-managed distros). Never run
> analysis against untrusted contract source on machine with funded wallets unlocked.

## Steps

### Step 1: Build and sanity-check project

```bash
forge build                    # analyzers require fresh artifacts
forge fmt --check              # style gate (optional)
cat foundry.toml               # note solc version, optimizer, remappings, evm_version
```

### Step 2: Static analysis (fast, run every time)

```bash
# Slither — full project (uses foundry.toml + remappings automatically)
slither . --json slither-report.json
# Aderyn — Cyfrin Rust analyzer, complementary detectors
aderyn . -o aderyn-report.json
```

Or run bundled orchestrator that runs both, deduplicates, and gates result:

```bash
python3 scripts/agent.py --project . --output audit-report.json
```

### Step 3: Symbolic execution on critical contracts (optional, slow)

```bash
# Only on the highest-value contract(s) — Mythril is path-explosive
myth analyze src/Vault.sol --solc-json mythril.config.json --execution-timeout 300 -o json
# or: python3 scripts/agent.py --project . --mythril src/Vault.sol
```

### Step 4: Property-based testing — fuzz + invariants

```bash
forge test -vvv                                  # unit + fuzz tests
forge coverage --report summary                  # coverage of value-moving code
forge test --match-test invariant_ -vvv          # invariant suite (handler-based)
```

Every value-moving contract should have **invariant tests with handler** (bounded
inputs, ghost variables, `targetContract(handler)`) — not unit tests. See
`references/api-reference.md` for handler pattern, and write a
`test_RevertWhen_*` (with `vm.expectRevert`) for each access-control guard.

### Step 5: Manual review against checklist

Walk `references/vulnerability-checklist.md` for every contract: reentrancy
(checks-effects-interactions / `nonReentrant`), access control, oracle manipulation,
`delegatecall`/proxy storage layout, unchecked return values, `tx.origin`, weak
randomness, DoS, front-running/MEV, and ERC-specific pitfalls (approve race,
fee-on-transfer, rebasing).

### Step 6: Key hygiene & secure deploy

```bash
gitleaks detect --no-banner            # no private keys / mnemonics / .env committed
git ls-files | grep -E '\.env$|keystore' && echo "WARN: secrets tracked by git"
# Import the deploy key ONCE into an encrypted keystore — never a plaintext PRIVATE_KEY env
cast wallet import deployer --interactive
# Deploy via the keystore account (testnet first), simulate before --broadcast
forge script script/Deploy.s.sol --account deployer --rpc-url <testnet> --broadcast --verify
```

See `references/secure-deployment-and-keys.md` for full hardening rules
(MetaMask hygiene, hardware wallet for mainnet, RPC trust, post-deploy verification).

### Step 7: Triage and report

Combine Slither + Aderyn + Mythril + test results, deduplicate by (file, line),
drop confirmed false positives, rank by exploitability × financial impact, and map
each to its SWC id. orchestrator emits `audit-report.json` with PASS/FAIL gate.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-foundry-smart-contract-security
