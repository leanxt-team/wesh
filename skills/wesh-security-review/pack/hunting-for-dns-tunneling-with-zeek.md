---
name: hunting-for-dns-tunneling-with-zeek
description: Detects DNS tunneling and covert-channel data exfiltration by analyzing Zeek dns.log for high-entropy subdomain queries, excessive query volume, abnormally long query lengths, and unusual DNS record types (TXT/NULL/CNAME).
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1046
- T1057
- T1082
- T1083
- T1048
nist_csf:
- DE.CM-01
- DE.AE-02
- DE.AE-07
- ID.RA-05
upstream: hunting-for-dns-tunneling-with-zeek@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites

- Zeek deployed on network tap or SPAN port capturing DNS traffic
- Zeek dns.log with full query and response fields
- SIEM platform for dns.log analysis (Splunk, Elastic)
- RITA (Real Intelligence Threat Analytics) for automated DNS analysis
- Passive DNS data for historical domain resolution context

## Workflow

1. **Analyze Query Length Distribution**: DNS tunneling encodes data in subdomain labels, producing queries significantly longer than normal. Normal DNS queries average 20-30 characters; tunneling queries often exceed 50+ characters. Calculate mean and standard deviation of query lengths per domain.
2. **Calculate Subdomain Entropy**: Tunneling encodes data using Base32/Base64, producing high-entropy subdomain strings. Calculate Shannon entropy of subdomain labels -- values above 3.5 bits/character strongly suggest encoded data.
3. **Count Unique Subdomains Per Domain**: Legitimate domains have relatively few unique subdomains. DNS tunneling generates hundreds or thousands of unique subdomains under single parent domain.
4. **Monitor DNS Record Type Distribution**: TXT, NULL, CNAME, and MX records can carry more data than A records. Excessive TXT queries to single domain indicate data transfer via DNS.
5. **Detect High Query Volume**: Flag domains receiving more than 100 queries per hour from single source, especially when combined with high subdomain uniqueness.
6. **Analyze Query Timing**: DNS tunneling tools produce regular query patterns (beaconing) or burst patterns (data transfer). Apply frequency analysis to DNS query timestamps.
7. **Cross-Reference with conn.log**: Correlate DNS queries with connection metadata to identify process or endpoint generating suspicious queries.
8. **Validate with Domain Intelligence**: Check suspicious domains against WHOIS data, certificate transparency, and threat intelligence feeds.

## Key Concepts

| Concept | Description |
|---------|-------------|
| T1071.004 | Application Layer Protocol: DNS |
| T1048.003 | Exfiltration Over Alternative Protocol: DNS |
| T1572 | Protocol Tunneling |
| Shannon Entropy | Measure of randomness in subdomain strings |
| Zeek dns.log | DNS query/response metadata |
| RITA | Automated DNS tunneling detection from Zeek logs |
| iodine | IPv4-over-DNS tunneling tool |
| dnscat2 | DNS-based command-and-control tool |
| DNSExfiltrator | Data exfiltration tool using DNS requests |

## Detection Queries

### Zeek Script -- DNS Tunnel Detection
```zeek
@load base/protocols/dns
module DNSTunnel;
export {
    redef enum Notice::Type += { DNSTunnel::Long_DNS_Query };
    const query_length_threshold = 50 &redef;
    const query_count_threshold = 100 &redef;
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( |query| > query_length_threshold ) {
        NOTICE([$note=DNSTunnel::Long_DNS_Query,
                $msg=fmt("Long DNS query detected: %s (%d chars)", query, |query|),
                $conn=c]);
    }
}
```

### Splunk -- DNS Tunneling Indicators from Zeek
```spl
index=zeek sourcetype=bro_dns
| rex field=query "(?<subdomain>[^.]+)\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(subdomain) as unique_subs avg(len(query)) as avg_len max(len(query)) as max_len by src basedomain
| where count > 100 AND (unique_subs > 50 OR avg_len > 40)
| sort -unique_subs
```

### Splunk -- High Entropy Subdomain Detection
```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval char_count=len(subdomain)
| stats count dc(query) as unique_queries avg(char_count) as avg_sub_len by src query_type_name basedomain
| where unique_queries > 30 AND avg_sub_len > 25
| sort -unique_queries
```

### RITA Analysis
```bash
rita import /path/to/zeek/logs dataset_name
rita show-dns-fqdn-ips-long dataset_name
rita show-exploded-dns dataset_name
rita show-dns-tunneling dataset_name --csv > dns_tunnel_results.csv
```

Not vendored (scripts/, references/, assets/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/hunting-for-dns-tunneling-with-zeek
