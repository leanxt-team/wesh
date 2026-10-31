---
name: fleet-hunting-with-velociraptor
description: Deploy a Velociraptor server and agents, then author VQL (Velociraptor Query Language) artifacts and run them as fleet-wide hunts, on-demand forensic collections, or standalone offline collectors.
subdomain: threat-hunting
facing: defense
mitre_attack:
- T1059
nist_csf:
- DE.CM-01
upstream: fleet-hunting-with-velociraptor@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** Velociraptor agents provide deep endpoint visibility and remote collection. Deploy only on assets you own or are authorized to monitor, in accordance with your monitoring policy and applicable law.

## Prerequisites

- A Linux or Windows host for server (Linux recommended for production).
- Velociraptor binary from official release page: https://github.com/Velocidex/velociraptor/releases
- Outbound/inbound connectivity from clients to server frontend port (default 8000) and admin GUI (default 8889).
- Make binary executable on Linux:
  ```bash
  chmod +x velociraptor-v0.*-linux-amd64
  sudo mv velociraptor-v0.*-linux-amd64 /usr/local/bin/velociraptor
  ```

## MITRE ATT&CK Mapping

| ID | Official Technique Name | Relevance to this skill |
|----|------------------------|--------------------------|
| T1059 | Command and Scripting Interpreter | primary hunt target — VQL artifacts surface anomalous interpreter execution (PowerShell, cmd, wscript) across fleet for detection and triage. |

Velociraptor is defensive hunting platform; mapping reflects adversary behavior hunts are designed to detect.

## Workflow

### 1. Generate server configuration
Interactive generator writes server config (TLS, datastore paths, GUI users, frontend URL). Use `config generate` for self-signed lab build or interactive `-i` wizard for production.
```bash
# Non-interactive: dump a default server config
velociraptor config generate > server.config.yaml
# Interactive wizard (recommended for production deployments)
velociraptor config generate -i
```

### 2. Add GUI admin user
Create at least one administrator to log into console.
```bash
velociraptor --config server.config.yaml user add admin --role administrator
```

### 3. Start server frontend and GUI
Frontend accepts client connections; GUI is served per config (default https://127.0.0.1:8889).
```bash
velociraptor --config server.config.yaml frontend -v
```
For quick all-in-one local lab (server + frontend + local client in one process):
```bash
velociraptor gui
```

### 4. Generate client configuration and deploy agents
Derive client config from server config and run it as client on each endpoint.
```bash
# Produce the client config (embeds server URL + CA)
velociraptor --config server.config.yaml config client > client.config.yaml
# On a Linux endpoint, run as a client (or install as a service)
velociraptor --config client.config.yaml client -v
```
On Windows, build MSI/service installer from GUI ("Server Artifacts" > deployment) or run:
```cmd
velociraptor.exe --config client.config.yaml service install
```

### 5. Test VQL interactively before hunting
Validate query locally with `query` (`-q`) before deploying it fleet-wide. VQL is SQL-like: `SELECT ... FROM plugin(...) WHERE ...`.
```bash
# List running processes with their command lines
velociraptor query "SELECT Pid, Name, CommandLine FROM pslist()"
# Hunt for suspicious PowerShell command lines
velociraptor query "
SELECT Pid, Name, CommandLine
FROM pslist()
WHERE Name =~ 'powershell'
  AND CommandLine =~ '(?i)(-enc|frombase64string|downloadstring|-w hidden|iex)'
"
```

### 6. List and run built-in artifact
Artifacts wrap VQL into reusable, parameterized collections.
```bash
# Show available artifacts
velociraptor artifacts list
# Collect a built-in artifact and write results to a directory
velociraptor artifacts collect Windows.System.Pslist --output results.zip
```

### 7. Launch fleet-wide hunt (GUI workflow)
In GUI: **Hunt Manager** > **New Hunt** > select artifact (e.g. `Windows.Detection.Powershell` or custom one) and parameters > **Launch**. hunt fans out to every matching client; results stream into hunt's results table and can be exported as CSV/JSON. Equivalent server-side VQL:
```sql
-- Create a hunt programmatically via a server VQL notebook
SELECT hunt(
    description="Suspicious PowerShell fleet sweep",
    artifacts="Windows.Detection.Powershell"
) FROM scope()
```

### 8. Build custom artifact
Custom artifacts are YAML documents containing parameters and VQL `sources`. Save in GUI's Artifact editor or import via `artifacts`:
```yaml
name: Custom.Hunt.SuspiciousPowershell
description: Find encoded / download-cradle PowerShell across the fleet.
parameters:
  - name: regex
    default: "(?i)(-enc|frombase64string|downloadstring|-w hidden|iex)"
sources:
  - query: |
      SELECT Pid, Name, CommandLine, timestamp(epoch=now()) AS Collected
      FROM pslist()
      WHERE Name =~ "powershell" AND CommandLine =~ regex
```

### 9. Generate offline collector
For unmanaged/air-gapped hosts, build standalone collector from GUI ("Server Artifacts" > `Server.Utils.CreateCollector`) or via VQL; it produces single executable that collects chosen artifacts into ZIP for later import.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Velociraptor releases | Official binaries | https://github.com/Velocidex/velociraptor/releases |
| Documentation | Deployment, VQL, artifacts | https://docs.velociraptor.app/ |
| VQL reference | Plugin/function reference | https://docs.velociraptor.app/vql_reference/ |
| Artifact Exchange | Community artifacts | https://docs.velociraptor.app/exchange/ |
| Source | GitHub repository | https://github.com/Velocidex/velociraptor |

## Key Commands

| Command | Purpose |
|---------|---------|
| `config generate [-i]` | Create server config (interactive optional) |
| `config client` | Derive client config from server config |
| `user add <name> --role administrator` | Add GUI admin |
| `frontend -v` | Start server frontend (client comms + GUI) |
| `gui` | All-in-one local lab instance |
| `client -v` | Run as endpoint agent |
| `service install` | Install agent as service |
| `query "<VQL>"` | Run VQL ad hoc |
| `artifacts list` | List available artifacts |
| `artifacts collect <name> --output <zip>` | Collect artifact locally |

## Validation Criteria

- [ ] Server config generated and GUI admin created
- [ ] Frontend running and GUI reachable over TLS
- [ ] Client config generated and at least one agent enrolled
- [ ] VQL query validated locally with `query`
- [ ] Built-in artifact collected successfully
- [ ] Fleet-wide hunt launched and results aggregated
- [ ] Custom VQL artifact authored and tested
- [ ] Offline collector produced for unmanaged hosts where needed

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/fleet-hunting-with-velociraptor
