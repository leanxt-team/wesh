---
name: auditing-mcp-servers-for-tool-poisoning
description: Audit MCP servers for tool poisoning, tool shadowing, rug pulls, SSRF, and unauthenticated exposure using Invariant Labs' mcp-scan for static/runtime scanning plus manual SSRF/auth checks and description pinning.
subdomain: ai-security
facing: config
upstream: auditing-mcp-servers-for-tool-poisoning@54a7988 Apache-2.0, modified by wesh
---
> **Authorized-use-only notice:** Auditing MCP servers can connect to and probe live tool endpoints. Only scan servers you own or are authorized to assess. Treat scanned tool descriptions as untrusted input — do not load unaudited MCP server into privileged agent. Probing third-party MCP endpoints for SSRF or auth weaknesses without permission may be illegal.

## Prerequisites

- Python 3.10+ and `uv` (for `uvx`), or pip.
- MCP config file(s) you want to scan (e.g. `~/.cursor/mcp.json`, `~/.vscode/mcp.json`, Claude Desktop config).
- Install tooling:

```bash
# uv provides uvx (recommended runner for mcp-scan)
curl -LsSf https://astral.sh/uv/install.sh | sh    # or: pipx install uv
# mcp-scan (Invariant Labs) — no global install needed with uvx
uvx mcp-scan@latest --help
# For the runtime proxy mode (separate extra)
uvx --with "mcp-scan[proxy]" mcp-scan@latest proxy --help
# Manual probing helpers
pip install requests mcp
```

## MITRE ATT&CK Mapping

| ID | Official Name | Relevance |
|----|---------------|-----------|
| AML.T0010 | ML Supply Chain Compromise | poisoned third-party MCP server is supply-chain compromise of agent |
| AML.T0051.001 | LLM Prompt Injection: Indirect | Poisoned tool descriptions are indirect injection into agent context |
| AML.T0053 | LLM Plugin Compromise | MCP tools are agent's plugins; poisoning compromises them |
| AML.T0057 | LLM Data Leakage | Common payload of poisoned tool: exfiltrate files/secrets |

## Workflow

### 1. Static scan of installed MCP configs
mcp-scan auto-discovers known config locations; you can also pass path explicitly.

```bash
# Scan all auto-discovered MCP configs
uvx mcp-scan@latest
# Scan a specific config file
uvx mcp-scan@latest ~/.vscode/mcp.json
# Emit machine-readable JSON for CI
uvx mcp-scan@latest --json ~/.cursor/mcp.json > mcp_scan_report.json
```

mcp-scan flags tool poisoning, tool shadowing, cross-origin escalation, rug pulls, and toxic flows.

### 2. Inspect raw tool descriptions
Print every tool/prompt/resource description without verification, then read them for hidden instructions, `<important>`-style blocks, or imperative text aimed at model.

```bash
uvx mcp-scan@latest inspect ~/.cursor/mcp.json
```

Look for red flags: instructions to assistant ("do not tell user", "read ~/.ssh/id_rsa"), nested fake documentation, zero-width/Unicode-smuggled text, or directives to call other tools.

### 3. Pin tool hashes to detect rug pulls
mcp-scan tracks tool description hashes so later silent change is flagged. Run scans on schedule; hash mismatch on previously approved tool indicates rug pull.

```bash
# Re-run regularly; mcp-scan reports changed tool hashes since last approval
uvx mcp-scan@latest ~/.cursor/mcp.json
```

### 4. Enumerate tools programmatically and audit metadata
Connect to server with official MCP SDK and inspect advertised schema directly.

```python
# enumerate_tools.py (stdio MCP server example)
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    params = StdioServerParameters(command="node", args=["./suspect-mcp-server.js"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"{t.name}: {len(t.description or '')} chars")
                print((t.description or "")[:400])
asyncio.run(main())
```

### 5. Test URL-fetching tools for SSRF
If tool accepts URL and fetches it server-side, attempt to reach internal metadata/loopback targets (only on systems you own).

```python
# ssrf_probe.py
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://127.0.0.1:22/", "http://localhost:6379/", "file:///etc/passwd",
]
async def main():
    params = StdioServerParameters(command="node", args=["./suspect-mcp-server.js"])
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            for url in SSRF_TARGETS:
                res = await s.call_tool("fetch_url", {"url": url})
                body = str(res.content)[:200]
                print(f"[SSRF?] {url} -> {body}")
asyncio.run(main())
```

### 6. Verify authentication and network exposure
Check that remote MCP servers (HTTP/SSE transport) require authentication and are not bound to `0.0.0.0` on untrusted networks.

```bash
# Confirm whether an SSE/HTTP MCP endpoint responds without credentials
curl -s -i http://mcp-host:8000/sse | head -n 20
# Check listening interfaces of a locally running MCP server
ss -tlnp | grep -E ':(8000|3000|6277)'
```

MCP endpoint that returns tool listings or accepts `tools/call` without auth is unauthenticated exposure — remediate with token/OAuth and bind to localhost or authenticated gateway.

### 7. Enforce runtime guardrails (optional)
For continuous protection, route agent MCP traffic through mcp-scan proxy, which checks tool calls, data-flow constraints, PII, and indirect injection in real time.

```bash
uvx --with "mcp-scan[proxy]" mcp-scan@latest proxy
```

### 8. Report findings
Document each finding with server, tool, evidence (poisoned description / SSRF response / unauth listing), severity, and ATLAS mapping. Recommend removing or sandboxing poisoned servers, adding auth, pinning approved tools, and enabling proxy.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| mcp-scan | Static + runtime MCP security scanner | https://github.com/invariantlabs-ai/mcp-scan |
| MCP Python SDK | Programmatic tool enumeration / calls | https://github.com/modelcontextprotocol/python-sdk |
| OWASP MCP Top 10 | MCP risk reference (MCP03 Tool Poisoning) | https://owasp.org/www-project-mcp-top-10/ |
| Invariant Labs blog | Tool poisoning disclosure | https://invariantlabs.ai/blog/introducing-mcp-scan |
| MITRE ATLAS | AI threat technique taxonomy | https://atlas.mitre.org/ |

## MCP Threat Reference

| Threat | Description | Detection |
|--------|-------------|-----------|
| Tool poisoning | Hidden instructions in tool description | mcp-scan scan / inspect |
| Tool shadowing | Malicious server overrides trusted tool | mcp-scan cross-origin checks |
| Rug pull | Description changes after approval | mcp-scan tool pinning (hash) |
| Toxic flow | Tool combo enabling exfiltration | mcp-scan toxic-flow analysis |
| SSRF | URL-fetch tool reaches internal targets | ssrf_probe against owned server |
| Unauth exposure | MCP endpoint with no auth | curl/ss interface and auth check |

## Validation Criteria

- [ ] All installed MCP configs statically scanned with mcp-scan
- [ ] Raw tool/prompt/resource descriptions inspected for hidden instructions
- [ ] Tool hashes pinned and rug-pull detection enabled
- [ ] Tools enumerated programmatically via MCP SDK
- [ ] URL-fetching tools tested for SSRF against owned targets
- [ ] Authentication and network exposure of remote servers verified
- [ ] Runtime proxy guardrails evaluated or deployed where appropriate
- [ ] Findings mapped to MITRE ATLAS AML.T0010 and OWASP MCP03:2025
- [ ] Severity assigned and remediation documented for each finding
- [ ] Re-scan scheduled to catch future rug pulls

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/auditing-mcp-servers-for-tool-poisoning
