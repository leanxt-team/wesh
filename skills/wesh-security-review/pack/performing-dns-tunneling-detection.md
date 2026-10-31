---
name: performing-dns-tunneling-detection
description: Detects DNS tunneling by computing Shannon entropy of DNS query names, analyzing query length distributions, inspecting TXT record payloads, and identifying high subdomain cardinality.
subdomain: security-operations
facing: defense
mitre_attack:
- T1078
- T1190
- T1059
- T1048
- T1041
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
upstream: performing-dns-tunneling-detection@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Familiarity with security operations concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Analyze DNS traffic for indicators of DNS tunneling using entropy analysis and
statistical methods on query name characteristics.

```python
import math
from collections import Counter
def shannon_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counter.values())
# Legitimate domain: low entropy (~3.0-3.5)
print(shannon_entropy("www.google.com"))
# DNS tunnel: high entropy (~4.0-5.0)
print(shannon_entropy("aGVsbG8gd29ybGQ.tunnel.example.com"))
```

Key detection indicators:
1. High Shannon entropy in query names (> 3.5 for subdomain labels)
2. Unusually long query names (> 50 characters)
3. High volume of TXT record requests to single domain
4. High unique subdomain count per parent domain
5. Non-standard character distribution in labels

## Examples

```python
from scapy.all import rdpcap, DNS, DNSQR
packets = rdpcap("dns_traffic.pcap")
for pkt in packets:
    if pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode()
        entropy = shannon_entropy(query)
        if entropy > 4.0:
            print(f"Suspicious: {query} (entropy={entropy:.2f})")
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-dns-tunneling-detection
