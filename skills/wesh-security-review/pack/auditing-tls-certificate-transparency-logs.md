---
name: auditing-tls-certificate-transparency-logs
description: Monitors Certificate Transparency (CT) logs to detect unauthorized certificate issuance, discover subdomains via CT data, and alert on suspicious certificate activity for owned domains.
subdomain: threat-intelligence
facing: defense
mitre_attack:
- T1596.003
- T1583.001
- T1587.003
- T1593
- T1566.002
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
upstream: auditing-tls-certificate-transparency-logs@54a7988 Apache-2.0, modified by wesh
---
Not for: attacking or disrupting Certificate Authorities, for scraping CT logs in violation of rate limits or terms of service, or as the sole method of subdomain enumeration without corroborating results through DNS verification.

## Prerequisites

- Python 3.10+ with `requests`, `cryptography`, and `pyOpenSSL` libraries installed
- Network access to crt.sh (HTTPS) and public CT log servers
- List of domains to monitor (owned domains, brand variations, typosquat candidates)
- SMTP credentials or webhook URL for alerting on new certificate discoveries
- Basic understanding of X.509 certificate structure and TLS certificate chain validation

## Workflow

### Step 1: Domain Inventory and Baseline

Build initial certificate inventory for monitored domains:

- **Define monitoring scope**: List all owned root domains, registered brand names, and known subsidiaries. Include wildcard patterns (`%.example.com`) for comprehensive subdomain coverage.
- **Query crt.sh for historical certificates**: Use crt.sh JSON API to retrieve all known certificates for each domain. API endpoint `https://crt.sh/?q=%.example.com&output=json` returns certificates matching wildcard pattern with fields including `issuer_ca_id`, `issuer_name`, `common_name`, `name_value`, `not_before`, `not_after`, and `serial_number`.
- **Build baseline database**: Store initial certificate set in local SQLite database with columns for certificate ID, domain, issuer, validity dates, SANs (Subject Alternative Names), and first-seen timestamp. This baseline prevents alerting on already-known certificates.
- **Identify authorized CAs**: From baseline, extract set of Certificate Authorities that have legitimately issued certificates for your domains. Any future issuance from CA not in this set triggers high-priority alert.
- **Map subdomains**: Extract all unique subdomains from the `name_value` field across all certificates to build initial subdomain inventory.

### Step 2: Continuous CT Log Monitoring

Set up ongoing monitoring for new certificate issuances:

- **Poll crt.sh periodically**: Query crt.sh API at regular intervals (every 15-60 minutes) for new certificates. Use the `exclude=expired` parameter to focus on currently valid certificates. Compare results against baseline database to identify new entries.
- **Parse certificate details**: For each new certificate, extract full SAN list, issuer chain, validity period, key type and size, CT log SCT (Signed Certificate Timestamp) details, and certificate fingerprint (SHA-256).
- **Detect precertificates**: CT logs include precertificates (poisoned certificates submitted before final issuance). Track these as early warnings since they indicate certificate is about to be issued but may not yet be active.
- **Monitor CT log Signed Tree Heads (STH)**: For advanced monitoring, query CT log servers directly to fetch latest STH and verify consistency proofs between consecutive tree heads. inconsistency indicates log misbehavior (split-view attack).
- **Rate limiting awareness**: Respect crt.sh rate limits by spacing queries and caching responses. Implement exponential backoff on HTTP 429 responses. For high-volume monitoring, consider querying crt.sh PostgreSQL interface directly at `crt.sh:5432`.
- **Atom/RSS feed alternative**: Subscribe to crt.sh's Atom feed for lighter-weight monitoring: `https://crt.sh/atom?q=%25.example.com` provides real-time notification of new log entries.

### Step 3: Subdomain Discovery via CT Data

Extract and validate subdomains found in certificate transparency data:

- **Wildcard expansion**: Certificates with wildcard SANs (`*.dev.example.com`) reveal existence of subdomains that may not be in DNS zone files. Record parent domain as target for further enumeration.
- **Historical certificate mining**: Query crt.sh without the `exclude=expired` parameter to find subdomains from expired certificates that may still resolve in DNS. These represent historical infrastructure that could be vulnerable to subdomain takeover.
- **DNS validation**: For each discovered subdomain, perform DNS resolution (A, AAAA, CNAME records) to determine if subdomain is currently active. Cross-reference with known IP ranges to identify shadow IT or unauthorized services.
- **Typosquat detection**: Generate permutations of monitored domain (bitsquatting, homograph, insertion, omission, transposition, keyboard-adjacent replacement) and query CT logs for certificates issued to these variations. Certificates for typosquat domains strongly indicate phishing infrastructure.
- **Deduplication and enrichment**: Normalize discovered subdomains (lowercase, remove trailing dots), deduplicate, and enrich with WHOIS data, IP geolocation, and HTTP response headers to prioritize investigation.

### Step 4: Certificate Issuance Alerting

Configure alerting rules for security-relevant certificate events:

- **Unauthorized CA alert**: Trigger when certificate is issued by CA not in authorized CA list. This is highest-priority alert as it may indicate domain hijacking, BGP hijacking for domain validation, or compromised CA.
- **New subdomain alert**: Trigger when certificate contains SAN with previously unseen subdomain. This catches shadow IT deployments and unauthorized services.
- **Wildcard certificate alert**: Trigger on any new wildcard certificate issuance, as wildcard certificates have broader impact if compromised and their issuance should be tightly controlled.
- **Short-lived certificate anomaly**: Alert when certificates have unusually short validity periods (under 24 hours) that deviate from organization's normal certificate lifecycle, as this may indicate Let's Encrypt abuse or automated phishing infrastructure.
- **Expiration warning**: Alert when certificates for critical services approach expiration (30, 14, 7 days) based on the `not_after` field from CT log data.
- **Alert delivery**: Send alerts via email (SMTP), Slack webhook, PagerDuty, or write to SIEM-compatible JSON log format for integration with existing security monitoring.

### Step 5: CT Log Integrity Verification and Reporting

Verify log integrity and produce compliance evidence:

- **Signed Tree Head (STH) monitoring**: Fetch latest STH from each monitored CT log via the `get-sth` API endpoint. STH contains tree size and signed timestamp. Verify signature using log's public key.
- **Consistency proof verification**: Between consecutive STH fetches, request consistency proof via `get-sth-consistency` to verify log remains append-only and no entries have been modified or removed.
- **Certificate inventory report**: Produce complete inventory of all certificates issued for monitored domains, grouped by issuer, with validity status and key strength metrics.
- **CA diversity analysis**: Report on how many different CAs issue certificates for organization, identifying consolidation opportunities and single-points-of-failure.
- **Compliance evidence**: For organizations subject to PCI-DSS, SOC 2, or similar frameworks, CT monitoring logs provide evidence of certificate lifecycle management and unauthorized issuance detection capabilities.

## Key Concepts

| Term | Definition |
|------|------------|
| **Certificate Transparency (CT)** | open framework (RFC 6962) requiring Certificate Authorities to log all issued certificates in publicly auditable append-only logs, enabling domain owners to detect unauthorized issuance |
| **Signed Certificate Timestamp (SCT)** | promise from CT log that certificate will be included within Maximum Merge Delay (typically 24 hours); browsers require SCTs from multiple logs before trusting certificate |
| **Merkle Tree** | cryptographic data structure used by CT logs where leaf nodes are certificate hashes and parent nodes are hashes of their children, enabling efficient consistency and inclusion proofs |
| **Precertificate** | certificate submitted to CT logs before final issuance, containing poison extension (OID 1.3.6.1.4.1.11129.2.4.3) that prevents it from being used for TLS but reserves its place in log |
| **crt.sh** | free web service operated by Sectigo that aggregates certificates from all major CT logs into searchable PostgreSQL database, providing both web and API access |
| **Subdomain Takeover** | vulnerability where subdomain's DNS record points to decommissioned service (cloud provider, CDN) that attacker can reclaim, made discoverable through expired CT certificates |
| **Maximum Merge Delay (MMD)** | maximum time (typically 24 hours) CT log has to incorporate submitted certificate into its Merkle tree after returning SCT |
| **CAA Record** | DNS Certification Authority Authorization record that specifies which CAs are permitted to issue certificates for domain; CT monitoring detects violations of CAA policy |

## Tools & Systems

- **crt.sh**: Primary CT log aggregator providing JSON API access at `https://crt.sh/?q=<query>&output=json` with support for wildcard queries, identity filtering, and certificate detail retrieval
- **ct-woodpecker**: Open-source CT log monitoring tool from Let's Encrypt that integrates with Prometheus and Grafana for operational monitoring of log health and consistency
- **certspotter**: SSLMate's CT log monitor that watches for newly issued certificates and sends notifications; available as hosted service or self-hosted tool
- **Google Argon / Xenon / Icarus**: Google-operated CT logs that are among most widely used, queryable via RFC 6962 API at their respective log URLs
- **OpenSSL**: Command-line tool for parsing certificate details, verifying chains, and extracting SAN lists from certificates retrieved through CT monitoring

## CT Log Monitoring Report

**Domain**: example.com
**Monitoring Period**: 2026-03-01 to 2026-03-19
**Total Certificates Tracked**: 142
**New Certificates Detected**: 7
**Alerts Generated**: 2

### Alert: Unauthorized CA Issuance
- **Severity**: Critical
- **Certificate CN**: secure-login.example.com
- **SANs**: secure-login.example.com, www.secure-login.example.com
- **Issuer**: Unknown Free CA (NOT in authorized CA list)
- **Serial**: 04:A3:B7:2F:...:9E
- **Not Before**: 2026-03-18T00:00:00Z
- **Not After**: 2026-06-16T00:00:00Z
- **CT Log**: Google Argon 2026
- **SCT Timestamp**: 2026-03-17T22:15:33Z
- **Action Required**: Investigate immediately, request revocation

### Subdomain Discovery Summary
- **Total Unique Subdomains**: 89
- **New Subdomains This Period**: 3
  - api-v3.example.com (DigiCert, valid)
  - staging-new.example.com (Let's Encrypt, valid)
  - old-portal.example.com (expired 2025-12-01, CNAME to Azure -- takeover risk)

### Typosquatting Alerts
| Domain | Certificate Count | Issuer | Action Required |
|--------|-------------------|--------|-----------------|
| exarnple.com | 2 | Let's Encrypt | Investigate phishing |
| examp1e.com | 1 | ZeroSSL | Investigate phishing |
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-tls-certificate-transparency-logs
