---
name: analyzing-ransomware-payment-wallets
description: Traces ransomware cryptocurrency payment flows using blockchain analysis tools such as Chainalysis Reactor, WalletExplorer, and blockchain.com APIs, identifying wallet clusters and tracking fund movement through mixers and exchanges to support law enforcement attribution.
subdomain: ransomware-defense
facing: defense
mitre_attack:
- T1657
- T1486
nist_csf:
- PR.DS-11
- RS.MA-01
- RC.RP-01
- PR.IR-01
upstream: analyzing-ransomware-payment-wallets@54a7988 Apache-2.0, modified by wesh
---
Not for: this skill for live payment interception or to interact directly with ransomware operators. All analysis should be passive and read-only against public blockchain data.

## Prerequisites

- Python 3.8+ with `requests`, `json`, and `hashlib` libraries
- Access to blockchain explorer APIs (blockchain.com, WalletExplorer.com, Blockstream.info)
- Familiarity with Bitcoin transaction model (UTXOs, inputs, outputs, change addresses)
- Understanding of common obfuscation techniques (mixers, tumblers, peel chains, cross-chain swaps)
- Optional: Chainalysis Reactor license for enterprise-grade cluster analysis
- Optional: OXT.me for advanced transaction graph visualization

## Workflow

### Step 1: Extract Wallet Address from Ransom Note

Parse ransom note to identify payment address(es):

```
Common address formats:
  Bitcoin (P2PKH):   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  (starts with 1)
  Bitcoin (P2SH):    3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy  (starts with 3)
  Bitcoin (Bech32):  bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq (starts with bc1)
  Monero:            4... (95 characters, much harder to trace)
  Ethereum:          0x... (40 hex chars)
```

### Step 2: Query Blockchain Explorer for Transaction History

Retrieve all transactions associated with wallet:

```python
import requests
def get_wallet_transactions(address):
    """Query blockchain.com API for address transactions."""
    url = f"https://blockchain.info/rawaddr/{address}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "address": address,
        "n_tx": data.get("n_tx", 0),
        "total_received_satoshi": data.get("total_received", 0),
        "total_sent_satoshi": data.get("total_sent", 0),
        "final_balance_satoshi": data.get("final_balance", 0),
        "transactions": data.get("txs", []),
    }
```

### Step 3: Map Fund Flow and Identify Clusters

Trace outputs from ransom wallet to downstream addresses:

```
Fund Flow Analysis:
━━━━━━━━━━━━━━━━━━
Victim Payment ──► Ransom Wallet ──► Consolidation Wallet
                                  ├─► Mixer/Tumbler Service
                                  ├─► Exchange Deposit Address
                                  └─► Peel Chain (sequential small outputs)
Key indicators:
  - Consolidation: Multiple ransom payments aggregated into one wallet
  - Peel chains: Sequential transactions with diminishing outputs
  - Mixer usage: Funds sent to known mixer addresses (Wasabi, Samourai, ChipMixer)
  - Exchange cashout: Deposits to known exchange wallets (Binance, Kraken hot wallets)
```

### Step 4: Cross-Reference with Known Wallet Databases

Check addresses against known ransomware infrastructure:

```python
# Check WalletExplorer for entity identification
def check_wallet_explorer(address):
    url = f"https://www.walletexplorer.com/api/1/address?address={address}&caller=research"
    resp = requests.get(url, timeout=30)
    data = resp.json()
    return {
        "wallet_id": data.get("wallet_id"),
        "label": data.get("label", "Unknown"),
        "is_exchange": data.get("is_exchange", False),
    }
```

### Step 5: Generate Attribution Report

Compile findings into structured intelligence report:

```
RANSOMWARE WALLET ANALYSIS REPORT
====================================
Ransom Address:      bc1q...xyz
Family Attribution:  LockBit 3.0 (based on ransom note format)
Total Received:      4.25 BTC ($178,500 at time of payment)
Total Sent:          4.25 BTC (wallet fully drained)
Number of Payments:  3 (likely 3 separate victims)
FUND FLOW:
  Payment 1: 1.5 BTC → Consolidation wallet → Binance deposit
  Payment 2: 1.0 BTC → Wasabi Mixer → Unknown
  Payment 3: 1.75 BTC → Peel chain (12 hops) → OKX deposit
CLUSTER ANALYSIS:
  Related wallets: 47 addresses identified in same cluster
  Total cluster volume: 156.3 BTC ($6.5M USD)
  First activity: 2024-01-15
  Last activity: 2024-09-22
```

## Verification

- Confirm wallet address format is valid before querying APIs
- Cross-reference transaction timestamps with known incident timelines
- Validate cluster associations by checking common-input-ownership heuristic
- Compare findings against OFAC SDN list for sanctioned addresses
- Verify exchange attribution against multiple sources (WalletExplorer, OXT, Chainalysis)

## Key Concepts

| Term | Definition |
|------|------------|
| **UTXO** | Unspent Transaction Output; fundamental unit of Bitcoin that tracks ownership through chain of transactions |
| **Cluster Analysis** | Grouping multiple Bitcoin addresses believed to be controlled by same entity using common-input-ownership and change-address heuristics |
| **Peel Chain** | laundering pattern where funds are sent through many sequential transactions, each peeling off small amount to new address |
| **CoinJoin/Mixer** | Privacy techniques that combine multiple users' transactions to obscure link between sender and receiver |
| **Common Input Ownership** | Heuristic that assumes all inputs to single transaction are controlled by same entity |

## Tools & Systems

- **Chainalysis Reactor**: Enterprise blockchain investigation platform with entity attribution and cross-chain tracing
- **WalletExplorer**: Free tool that clusters Bitcoin addresses and labels known services (exchanges, mixers, markets)
- **OXT.me**: Advanced Bitcoin transaction visualization with UTXO graph analysis
- **Blockstream.info**: Open-source Bitcoin block explorer with full API access
- **blockchain.com API**: Free API for querying Bitcoin address balances and transaction histories
- **OFAC SDN List**: U.S. Treasury sanctioned address list for compliance checking

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/analyzing-ransomware-payment-wallets
