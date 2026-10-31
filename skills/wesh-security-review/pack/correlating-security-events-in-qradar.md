---
name: correlating-security-events-in-qradar
description: Correlates security events in IBM QRadar SIEM using AQL (Ariel Query Language), custom rules, building blocks, and offense management to detect multi-stage attacks across network, endpoint, and application log sources.
subdomain: soc-operations
facing: defense
mitre_attack:
- T1078
- T1110.003
- T1021
- T1071.001
- T1041
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
upstream: correlating-security-events-in-qradar@54a7988 Apache-2.0, modified by wesh
---
Not for: log source onboarding or parsing — that requires QRadar administrator access and DSM editor knowledge.

## Prerequisites

- IBM QRadar SIEM 7.5+ with offense management enabled
- AQL knowledge for ad-hoc event and flow queries
- Log sources normalized with proper QID mappings (Windows, firewall, proxy, endpoint)
- User role with offense management, rule creation, and AQL search permissions
- Reference sets/maps configured for whitelist and watchlist management

## Workflow

### Step 1: Investigate Offense with AQL

Open offense in QRadar and query contributing events using AQL (Ariel Query Language):

```sql
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       sourceIP, destinationIP, username,
       LOGSOURCENAME(logSourceId) AS log_source,
       QIDNAME(qid) AS event_name,
       category, magnitude
FROM events
WHERE INOFFENSE(12345)
ORDER BY startTime ASC
LIMIT 500
```

Pivot on source IP to find all activity:

```sql
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
       destinationIP, destinationPort, username,
       QIDNAME(qid) AS event_name,
       eventCount, category
FROM events
WHERE sourceIP = '192.168.1.105'
  AND startTime > NOW() - 24*60*60*1000
ORDER BY startTime ASC
LIMIT 1000
```

### Step 2: Build Custom Correlation Rule

Create multi-condition rule detecting brute force followed by successful login:

**Rule 1 — Brute Force Detection (Building Block):**
```
Rule Type: Event
Rule Name: BB: Multiple Failed Logins from Same Source
Tests:
  - When the event(s) were detected by one or more of [Local]
  - AND when the event QID is one of [Authentication Failure (5000001)]
  - AND when at least 10 events are seen with the same Source IP
    in 5 minutes
Rule Action: Dispatch new event (Category: Authentication, QID: Custom_BruteForce)
```

**Rule 2 — Brute Force Succeeded (Correlation Rule):**
```
Rule Type: Offense
Rule Name: COR: Brute Force with Subsequent Successful Login
Tests:
  - When an event matches the building block BB: Multiple Failed Logins from Same Source
  - AND when an event with QID [Authentication Success (5000000)] is detected
    from the same Source IP within 10 minutes
  - AND the Destination IP is the same for both events
Rule Action: Create offense, set severity to High, set relevance to 8
```

### Step 3: Use AQL for Cross-Source Correlation

Correlate authentication failures with network flows to detect lateral movement:

```sql
SELECT e.sourceIP, e.destinationIP, e.username,
       QIDNAME(e.qid) AS event_name,
       e.eventCount,
       f.sourceBytes, f.destinationBytes
FROM events e
LEFT JOIN flows f ON e.sourceIP = f.sourceIP
  AND e.destinationIP = f.destinationIP
  AND f.startTime BETWEEN e.startTime AND e.startTime + 300000
WHERE e.category = 'Authentication'
  AND e.sourceIP IN (
    SELECT sourceIP FROM events
    WHERE QIDNAME(qid) = 'Authentication Failure'
      AND startTime > NOW() - 3600000
    GROUP BY sourceIP
    HAVING COUNT(*) > 20
  )
  AND e.startTime > NOW() - 3600000
ORDER BY e.startTime ASC
```

Detect data exfiltration by correlating DNS queries with large outbound flows:

```sql
SELECT sourceIP, destinationIP,
       SUM(sourceBytes) AS total_bytes_out,
       COUNT(*) AS flow_count
FROM flows
WHERE sourceIP IN (
    SELECT sourceIP FROM events
    WHERE QIDNAME(qid) ILIKE '%DNS%'
      AND destinationIP NOT IN (
        SELECT ip FROM reference_data.sets('Internal_DNS_Servers')
      )
      AND startTime > NOW() - 86400000
    GROUP BY sourceIP
    HAVING COUNT(*) > 500
  )
  AND destinationPort NOT IN (80, 443, 53)
  AND startTime > NOW() - 86400000
GROUP BY sourceIP, destinationIP
HAVING SUM(sourceBytes) > 104857600
ORDER BY total_bytes_out DESC
```

### Step 4: Configure Reference Sets for Context Enrichment

Create reference sets for dynamic whitelists and watchlists:

```bash
# Create reference set via QRadar API
curl -X POST "https://qradar.example.com/api/reference_data/sets" \
  -H "SEC: YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Known_Pen_Test_IPs",
    "element_type": "IP",
    "timeout_type": "LAST_SEEN",
    "time_to_live": "30 days"
  }'
# Add entries
curl -X POST "https://qradar.example.com/api/reference_data/sets/Known_Pen_Test_IPs" \
  -H "SEC: YOUR_API_TOKEN" \
  -d "value=10.0.5.100"
```

Use reference sets in rule conditions to exclude known benign activity:

```
Test: AND when the Source IP is NOT contained in any of [Known_Pen_Test_IPs]
Test: AND when the Destination IP is contained in any of [Critical_Asset_IPs]
```

### Step 5: Tune Offense Generation

Reduce false positives by adding building block filters:

```sql
-- Find top false positive generators
SELECT QIDNAME(qid) AS event_name,
       LOGSOURCENAME(logSourceId) AS log_source,
       COUNT(*) AS event_count,
       COUNT(DISTINCT sourceIP) AS unique_sources
FROM events
WHERE INOFFENSE(
    SELECT offenseId FROM offenses
    WHERE status = 'CLOSED'
      AND closeReason = 'False Positive'
      AND startTime > NOW() - 30*24*60*60*1000
  )
GROUP BY qid, logSourceId
ORDER BY event_count DESC
LIMIT 20
```

Apply tuning:
- Add high-frequency false positive sources to reference set exclusions
- Increase event thresholds on noisy rules (e.g., 10 failed logins -> 25 for service accounts)
- Set offense coalescing to group related events under single offense

### Step 6: Build Custom Dashboard for Correlation Monitoring

Create QRadar Pulse dashboard with key correlation metrics:

```sql
-- Active offenses by category
SELECT offenseType, status, COUNT(*) AS offense_count,
       AVG(magnitude) AS avg_magnitude
FROM offenses
WHERE status = 'OPEN'
GROUP BY offenseType, status
ORDER BY offense_count DESC
-- Mean time to close offenses
SELECT DATEFORMAT(startTime, 'yyyy-MM-dd') AS day,
       AVG(closeTime - startTime) / 60000 AS avg_close_minutes,
       COUNT(*) AS closed_count
FROM offenses
WHERE status = 'CLOSED'
  AND startTime > NOW() - 30*24*60*60*1000
GROUP BY DATEFORMAT(startTime, 'yyyy-MM-dd')
ORDER BY day
```

## Key Concepts

| Term | Definition |
|------|-----------|
| **AQL** | Ariel Query Language — QRadar's SQL-like query language for searching events, flows, and offenses |
| **Offense** | QRadar's correlated incident grouping multiple events/flows under single investigation unit |
| **Building Block** | Reusable rule component that categorizes events without generating offenses, used as input to correlation rules |
| **Magnitude** | QRadar's calculated offense severity combining relevance, severity, and credibility scores (1-10) |
| **Reference Set** | Dynamic lookup table in QRadar for whitelists, watchlists, and enrichment data used in rules |
| **QID** | QRadar Identifier — unique numeric ID mapping vendor-specific events to normalized categories |
| **Coalescing** | QRadar's mechanism for grouping related events into single offense to reduce analyst workload |

## Tools & Systems

- **IBM QRadar SIEM**: Enterprise SIEM platform with event correlation, offense management, and AQL query engine
- **QRadar Pulse**: Dashboard framework for building custom visualizations of offense and event metrics
- **QRadar API**: RESTful API for automating reference set management, offense operations, and rule deployment
- **QRadar Use Case Manager**: App for mapping detection rules to MITRE ATT&CK framework coverage
- **QRadar Assistant**: AI-powered analysis tool helping analysts investigate offenses with natural language

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/correlating-security-events-in-qradar
