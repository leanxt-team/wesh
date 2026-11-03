---
name: conducting-external-reconnaissance-with-osint
description: Conduct external recon using OSINT techniques to map an organization's external attack surface without touching target systems, gathering DNS records, certificate transparency logs, search results, social media, code repositories, and breach databases into a target profile.
subdomain: penetration-testing
facing: config
mitre_attack:
- T1595
- T1592
- T1589
- T1590
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: conducting-external-reconnaissance-with-osint@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: stalking, harassment, or unauthorized surveillance of individuals. OSINT gathering must be conducted within the scope of an authorized engagement and comply with applicable privacy laws (GDPR, CCPA).

## Prerequisites

- Written authorization to perform reconnaissance against target organization
- Dedicated research workstation with VPN or Tor for anonymized queries when required
- OSINT framework tools installed: Amass, theHarvester, Shodan CLI, Recon-ng, SpiderFoot
- API keys for Shodan, Censys, SecurityTrails, Hunter.io, VirusTotal, and GitHub for enhanced results
- Disposable email accounts for accessing services that require registration during research

## Workflow

### Step 1: Domain and DNS Enumeration

Enumerate all domains, subdomains, and DNS records associated with target:

- **Root domain identification**: Start with primary domain and identify all related domains through reverse WHOIS lookups on registrant name, email, and organization using `whoxy.com` or `domaintools.com`
- **Subdomain enumeration**: Run multiple tools for comprehensive coverage:
  - `amass enum -passive -d target.com -o amass_subs.txt` for passive subdomain discovery from 40+ data sources
  - `subfinder -d target.com -all -o subfinder_subs.txt` for fast passive enumeration
  - `crt.sh` certificate transparency log queries: `curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u`
- **DNS record analysis**: Query for all record types: `dig target.com ANY`, check for SPF, DKIM, DMARC records that reveal email infrastructure, and enumerate MX records to identify email providers
- **Zone transfer attempt**: `dig axfr @ns1.target.com target.com` to check for misconfigured DNS servers
- **Consolidate results**: Merge, deduplicate, and resolve all discovered subdomains to IP addresses. Map IP addresses to ASN and hosting providers.

### Step 2: Infrastructure and Service Discovery

Identify internet-facing infrastructure without directly scanning target systems:

- **Shodan**: `shodan search "ssl.cert.subject.cn:target.com"` to find all internet-facing services with TLS certificates for target domain. Also search by organization name and IP ranges.
- **Censys**: Search for target's IP ranges and TLS certificates to identify services, technologies, and potential vulnerabilities indexed from internet-wide scanning
- **Cloud asset discovery**: Check for S3 buckets (`target-com`, `target-backup`, `target-dev`), Azure Blob storage (`target.blob.core.windows.net`), and GCP storage using tools like `cloud_enum`
- **WAF and CDN identification**: Use `wafw00f target.com` to identify web application firewalls and CDN providers that may mask origin server IP
- **Historical data**: Use Wayback Machine (`web.archive.org`) to find removed pages, old application versions, and forgotten endpoints

### Step 3: Email and Personnel Intelligence

Gather employee information and email addresses for social engineering preparation:

- **Email harvesting**: `theHarvester -d target.com -b all -f harvest_results.html` to collect emails from search engines, LinkedIn, and data sources
- **Email format identification**: Use `hunter.io` to determine email format (first.last, flast, firstl) and verify deliverability
- **LinkedIn reconnaissance**: Identify employees by department, particularly IT administrators, security team members, and executives. Note technologies mentioned in job postings and employee profiles.
- **Organizational chart**: Build org chart from LinkedIn data to understand reporting structures, identify key personnel, and map departments
- **Social media analysis**: Review employee social media profiles for information about internal tools, technologies, office locations, badge photos, and security practices
- **Job postings**: Analyze current and historical job postings on company career page and job boards for technology stack details, tools, and infrastructure information

### Step 4: Credential and Data Leak Analysis

Search for exposed credentials and sensitive data:

- **Breach databases**: Check `haveibeenpwned.com` API for breached email addresses associated with target domain
- **Paste sites**: Search Pastebin, GitHub Gists, and similar paste sites for leaked credentials, configuration files, or internal documents
- **Code repositories**: Search GitHub, GitLab, and Bitbucket for:
  - `org:target "password"`, `org:target "api_key"`, `org:target "secret"`
  - Use `trufflehog` or `gitleaks` for automated secret scanning across target's public repositories
- **Document metadata**: Download publicly available documents (PDF, DOCX, XLSX) from target website and extract metadata using `exiftool` to reveal internal usernames, software versions, printer names, and file paths
- **Google dorking**: Use targeted search operators:
  - `site:target.com filetype:pdf` for public documents
  - `site:target.com inurl:admin` for admin panels
  - `site:target.com "index of /"` for directory listings
  - `site:pastebin.com "target.com"` for paste site mentions

### Step 5: Technology Stack Profiling

Identify technologies, frameworks, and services used by target:

- **Web technology fingerprinting**: Use `whatweb target.com` or Wappalyzer browser extension to identify CMS, frameworks, JavaScript libraries, analytics, and server software
- **SSL/TLS analysis**: `sslyze target.com` or `testssl.sh target.com` to identify cipher suites, protocol versions, certificate details, and cryptographic weaknesses
- **JavaScript analysis**: Download and review JavaScript files for framework identifiers, API endpoints, internal hostnames, and version strings
- **DNS-based service identification**: Review TXT records for service providers (e.g., `v=spf1 include:_spf.google.com` indicates Google Workspace, `MS=msXXXXXX` indicates Microsoft 365)
- **Mobile app analysis**: Download target's mobile applications from app stores and analyze with `apktool` (Android) or `frida` for hardcoded URLs, API endpoints, and embedded credentials

## Key Concepts

| Term | Definition |
|------|------------|
| **OSINT** | Open Source Intelligence; intelligence collected from publicly available sources including websites, social media, public records, and government data |
| **Passive Reconnaissance** | Information gathering without directly interacting with target systems, leaving no footprint in target logs |
| **Active Reconnaissance** | Information gathering that involves direct interaction with target systems (scanning, probing) and may be logged |
| **Certificate Transparency** | Public logs of TLS certificates issued by certificate authorities, queryable to discover subdomains and infrastructure |
| **Attack Surface** | Sum of all points where unauthorized user can attempt to enter or extract data from environment |
| **Google Dorking** | Using advanced Google search operators to find sensitive information indexed by search engines that was not intended to be public |
| **Shadow IT** | Technology systems and services deployed by employees or departments without knowledge or approval of IT department |

## Tools & Systems

- **Amass (OWASP)**: Comprehensive subdomain enumeration tool that combines passive sources, DNS brute-forcing, and certificate transparency log analysis
- **Shodan**: Internet-wide scanning database that indexes services, banners, and metadata for internet-connected devices, searchable by IP, domain, or organization
- **theHarvester**: OSINT tool for gathering emails, subdomains, hosts, employee names, and open ports from public sources
- **SpiderFoot**: Automated OSINT collection platform that queries 200+ data sources and correlates findings into unified graph
- **Recon-ng**: Modular web reconnaissance framework with database backend for organizing and cross-referencing discovered intelligence

### Scenario: Pre-Engagement Reconnaissance for Red Team Exercise

**Context**: Technology company has contracted red team assessment. Before active testing begins, team conducts passive OSINT to map attack surface and identify potential entry points. Target is SaaS company with 500 employees and primary domain of techcorp.io.

**Approach**:
1. Enumerate 147 subdomains via Amass and crt.sh, including staging.techcorp.io, jenkins.techcorp.io, and vpn.techcorp.io
2. Shodan reveals forgotten Elasticsearch instance on port 9200 with no authentication exposed to internet
3. theHarvester collects 89 employee email addresses, revealing format first.last@techcorp.io
4. GitHub search discovers former developer's public repository containing a `.env` file with AWS access keys
5. LinkedIn analysis reveals company uses Okta for SSO, Jira for project management, and AWS for hosting
6. Google dorking finds directory listing on docs.techcorp.io exposing internal architecture diagrams
7. Compile all intelligence into reconnaissance report that feeds directly into threat modeling and attack planning phases

**Pitfalls**:
- Relying on single subdomain enumeration tool and missing assets found by other tools using different data sources
- Failing to check cloud storage services (S3, Azure Blob, GCP) for publicly accessible buckets
- Not searching for credentials in public code repositories, which frequently yield immediate access
- Conducting active scanning (port scans, vulnerability scans) during what should be passive-only phase

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-external-reconnaissance-with-osint
