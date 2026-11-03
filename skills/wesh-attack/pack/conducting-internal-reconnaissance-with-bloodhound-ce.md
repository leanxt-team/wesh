---
name: conducting-internal-reconnaissance-with-bloodhound-ce
description: Conduct internal Active Directory reconnaissance using BloodHound Community Edition's graph database with the SharpHound (AD) and AzureHound (Entra ID) collectors, mapping ACLs, sessions, and group memberships into attack paths from a low-privileged foothold to Domain Admin.
subdomain: red-teaming
facing: config
mitre_attack:
- T1087.002
- T1069.002
- T1482
- T1018
nist_csf:
- ID.RA-01
- GV.OV-02
- DE.AE-07
upstream: conducting-internal-reconnaissance-with-bloodhound-ce@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Prerequisites

- Familiarity with red teaming concepts and tools
- Access to test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## MITRE ATT&CK Mapping

- **T1087.002** - Account Discovery: Domain Account
- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1482** - Domain Trust Discovery
- **T1615** - Group Policy Discovery
- **T1018** - Remote System Discovery
- **T1033** - System Owner/User Discovery
- **T1016** - System Network Configuration Discovery

## Workflow

### Phase 1: BloodHound CE Deployment

1. Deploy BloodHound CE using Docker Compose:
   ```bash
   curl -L https://ghst.ly/getbhce -o docker-compose.yml
   docker compose pull
   docker compose up -d
   ```
2. Access web interface at https://localhost:8080
3. Log in with default admin credentials (displayed in Docker logs):
   ```bash
   docker compose logs | grep "Initial Password"
   ```
4. Change default admin password immediately

### Phase 2: Data Collection with SharpHound v2

1. Transfer SharpHound v2 to compromised Windows host:
   ```powershell
   # Execute full collection
   .\SharpHound.exe -c All --outputdirectory C:\Temp

   # DCOnly collection (LDAP only, stealthier)
   .\SharpHound.exe -c DCOnly

   # Session collection for logged-on user mapping
   .\SharpHound.exe -c Session --loop --loopduration 02:00:00

   # Collect from specific domain
   .\SharpHound.exe -c All -d child.domain.local
   ```
2. Alternative: Use BloodHound.py from Linux:
   ```bash
   bloodhound-python -u user -p 'Password123' -d domain.local -ns 10.10.10.1 -c All
   ```
3. Exfiltrate generated ZIP file to analysis workstation

### Phase 3: Data Import and Initial Analysis

1. Upload collected data via BloodHound CE web interface (File Ingest)
2. Mark compromised accounts as "Owned" in interface
3. Run built-in analysis queries:
   - Shortest Path to Domain Admin
   - Kerberoastable Users with Path to DA
   - AS-REP Roastable Users
   - Users with DCSync Rights
   - Computers with Unconstrained Delegation

### Phase 4: Custom Cypher Queries

1. Execute custom Cypher queries in BloodHound CE search bar:
   ```cypher
   // Find shortest path from owned principals to Domain Admins
   MATCH p=shortestPath((n {owned:true})-[*1..]->(m:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
   RETURN p

   // Find Kerberoastable users with path to DA
   MATCH (u:User {hasspn:true})
   MATCH p=shortestPath((u)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}))
   RETURN p

   // Find computers with sessions of DA members
   MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})
   RETURN c.name, u.name

   // Find ACL-based attack paths (GenericAll, WriteDACL, GenericWrite)
   MATCH p=(u:User)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(t)
   WHERE u.owned = true
   RETURN p

   // Find users who can DCSync
   MATCH (u)-[:MemberOf*0..]->()-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
   RETURN u.name, d.name

   // Find computers with LAPS but readable by non-admins
   MATCH (c:Computer {haslaps:true})
   MATCH p=(u:User)-[:ReadLAPSPassword]->(c)
   RETURN p
   ```

### Phase 5: Attack Path Prioritization

1. Score identified attack paths by:
   - Number of hops (shorter = higher priority)
   - Stealth requirements (avoid noisy techniques)
   - Tool availability for each hop
   - Likelihood of detection at each step
2. Create execution plan for highest-priority paths
3. Identify required tools for each step in chain
4. Plan OPSEC considerations for each technique

## Tools and Resources

| Tool | Purpose | Platform |
|------|---------|----------|
| BloodHound CE | Web-based graph analysis platform | Docker |
| SharpHound v2 | AD data collection (.NET, for CE) | Windows |
| BloodHound.py | AD data collection (Python) | Linux |
| AzureHound | Azure AD / Entra ID data collection | Cross-platform |
| PlumHound | Automated BloodHound reporting | Python |
| BloodHound Query Library | Community Cypher query repository | Web |

## Key Attack Path Types

| Path Type | Description | Example |
|-----------|-------------|---------|
| ACL Abuse | Exploit misconfigured ACLs | GenericAll on DA group |
| Kerberoasting | Crack service account passwords | SPN account → DA |
| AS-REP Roasting | Attack accounts without pre-auth | No-preauth user → password crack |
| Delegation Abuse | Exploit unconstrained/constrained delegation | Computer → impersonate DA |
| GPO Abuse | Modify GPOs applied to privileged OUs | GPO write → code execution on DA |
| Session Hijack | Leverage DA sessions on compromised hosts | Admin session → token theft |

## Validation Criteria

- [ ] BloodHound CE deployed and accessible
- [ ] SharpHound v2 data collected from all domains in scope
- [ ] Data successfully imported into BloodHound CE
- [ ] Owned principals marked in interface
- [ ] Shortest paths to Domain Admin identified
- [ ] ACL-based attack paths documented
- [ ] Kerberoastable and AS-REP roastable accounts listed
- [ ] Custom Cypher queries executed for advanced analysis
- [ ] Attack paths prioritized by feasibility and stealth
- [ ] Report generated with all identified paths and evidence

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/conducting-internal-reconnaissance-with-bloodhound-ce
