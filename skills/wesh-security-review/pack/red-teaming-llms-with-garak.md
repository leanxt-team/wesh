---
name: red-teaming-llms-with-garak
description: Runs NVIDIA garak probe suites (jailbreak, prompt injection, data leakage, toxicity, and more) against an LLM endpoint - Hugging Face models, OpenAI-compatible APIs, or Bedrock - then interprets the resulting hit-rate report for triage.
subdomain: ai-security
facing: config
upstream: red-teaming-llms-with-garak@54a7988 Apache-2.0, modified by wesh
---
> Authorized use only: written scope / rules of engagement first. Refuse targets outside scope.

## Prerequisites

- Python 3.10+ (3.12 recommended) and virtual environment.
- Install garak from PyPI:
  ```bash
  python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
  python -m pip install -U garak
  garak --version
  ```
- For bleeding-edge version:
  ```bash
  python -m pip install -U git+https://github.com/NVIDIA/garak.git@main
  ```
- API key for target if probing hosted model (e.g. `export OPENAI_API_KEY="sk-..."`).
- Written authorization to test target, and awareness of token cost (probes generate thousands of calls).

## MITRE ATT&CK Mapping

This skill uses MITRE ATLAS (adversarial-ML companion to ATT&CK) technique IDs.

| ID | Tactic | Official Name | Relevance |
|----|--------|---------------|-----------|
| AML.T0051 | ML Attack Staging / Impact | LLM Prompt Injection | garak's `promptinject` and `latentinjection` probes craft malicious prompts that subvert intended model behavior. |
| AML.T0054 | Privilege Escalation / Defense Evasion | LLM Jailbreak | garak's `dan` and related probes attempt to bypass safety guardrails so model produces restricted content. |

## Workflow

### Phase 1: Enumerate Probes and Detectors
1. List every probe garak ships so you can scope run:
   ```bash
   garak --list_probes
   ```
2. List detectors (modules that score whether probe succeeded) and generators (target connectors):
   ```bash
   garak --list_detectors
   garak --list_generators
   ```
3. Read probe taxonomy. Key families:
   - `promptinject` — PromptInject-framework direct injection.
   - `latentinjection` — instructions hidden in documents/encoded text (indirect injection).
   - `dan` — "Do Anything Now" and related jailbreaks (e.g. `dan.Dan_11_0`).
   - `leakreplay` — coax model into reproducing memorized/training or hidden-prompt text.
   - `encoding` — base64/ROT13/etc. injection bypasses.
   - `xss` — emit cross-site-scripting payloads (markdown/HTML exfil).
   - `malwaregen` — request AV-evading or malicious code.

### Phase 2: Probe Local Hugging Face Model
1. Run single jailbreak probe against local model to validate setup:
   ```bash
   python -m garak --target_type huggingface --target_name gpt2 --probes dan.Dan_11_0
   ```
2. Run fuller suite against chat model:
   ```bash
   python -m garak \
     --target_type huggingface \
     --target_name meta-llama/Llama-3.2-1B-Instruct \
     --probes promptinject,dan,leakreplay \
     --report_prefix llama32_baseline
   ```

### Phase 3: Probe OpenAI-Compatible API
1. Export key and run injection + leakage probes:
   ```bash
   export OPENAI_API_KEY="sk-..."
   python -m garak \
     --target_type openai \
     --target_name gpt-4o-mini \
     --probes promptinject,latentinjection,leakreplay \
     --generations 5 \
     --parallel_attempts 8 \
     --report_prefix gpt4omini_injection
   ```
   - `--generations` controls how many completions per prompt (more = more statistical confidence, more cost).
   - `--parallel_attempts` raises throughput for remote APIs.

### Phase 4: Probe Arbitrary REST Endpoint
1. garak can target any HTTP API via JSON generator spec. Create `rest.json`:
   ```json
   {
     "rest": {
       "RestGenerator": {
         "name": "my-llm-gateway",
         "uri": "https://llm.internal.example/v1/chat",
         "method": "post",
         "headers": { "Authorization": "Bearer $ENV_TOKEN", "Content-Type": "application/json" },
         "req_template_json_object": { "model": "internal-bot", "prompt": "$INPUT" },
         "response_json": true,
         "response_json_field": "$.output"
       }
     }
   }
   ```
2. Run garak against it:
   ```bash
   export ENV_TOKEN="..."
   python -m garak \
     --target_type rest \
     -G rest.json \
     --probes promptinject,dan \
     --report_prefix internal_gateway
   ```

### Phase 5: Run Curated Config and Full Sweep
1. For repeatable assessments, pin everything in YAML/JSON config and pass `--config`:
   ```bash
   python -m garak --config assessment.yaml
   ```
   ```yaml
   # assessment.yaml
   plugins:
     model_type: openai
     model_name: gpt-4o-mini
     probe_spec: promptinject,latentinjection,dan,leakreplay,xss,malwaregen
   run:
     generations: 5
     parallel_attempts: 8
   reporting:
     report_prefix: quarterly_llm_assessment
   ```
2. For exhaustive sweep (slow, expensive) run all probes by omitting `--probes` entirely.

### Phase 6: Interpret Hit-Rate Report
1. Read terminal summary. Each row is `probe.Class  detector: PASS|FAIL  ok on N/M`. A FAIL with low `ok` fraction means model frequently produced unsafe behavior — high-severity finding.
2. Open machine-readable report and aggregate failures:
   ```bash
   # Every attempt with detector verdicts is one JSON line
   jq -r 'select(.entry_type=="eval") | "\(.probe)\t\(.detector)\t\(.passed)/\(.total)"' \
     garak.<timestamp>.report.jsonl | sort
   ```
3. Open generated `.report.html` in browser for formatted scorecard and per-probe breakdown.
4. Pull actual successful attack strings from hit log to use as proof-of-concept evidence.

### Phase 7: Mitigate and Re-Test
1. Apply control (tighten system prompt, add input/output guardrail e.g. Llama Guard or LLM Guard, or change model).
2. Re-run identical probe set with new `--report_prefix`.
3. Compare hit rates between runs to quantify risk reduction for report.

## Tools and Resources

| Resource | Purpose | Link |
|----------|---------|------|
| NVIDIA/garak | Source, probe list, issues | https://github.com/NVIDIA/garak |
| garak documentation | CLI reference, generator configs | https://docs.garak.ai/ and https://reference.garak.ai/ |
| garak paper (arXiv:2406.11036) | Methodology and design | https://arxiv.org/abs/2406.11036 |
| OWASP Top 10 for LLM Applications | Risk taxonomy probes map to | https://genai.owasp.org/ |
| MITRE ATLAS | AML technique definitions | https://atlas.mitre.org/ |

## Probe Family Reference

| Probe family | Targets | OWASP LLM mapping |
|--------------|---------|-------------------|
| `promptinject` | Direct prompt injection | LLM01 |
| `latentinjection` | Indirect / hidden-context injection | LLM01 |
| `dan` | Jailbreak / guardrail bypass | LLM01 / safety |
| `leakreplay` | Training-data & prompt leakage | LLM02 / LLM07 |
| `encoding` | Encoding-based filter bypass | LLM01 |
| `xss` | Markdown/HTML exfiltration payloads | LLM02 |
| `malwaregen` | Malicious code generation | misuse |

## Validation Criteria

- [ ] garak installed and `garak --version` succeeds.
- [ ] Probes and detectors enumerated with `--list_probes` / `--list_detectors`.
- [ ] At least one probe run completed against target with a `--report_prefix` set.
- [ ] `.report.jsonl`, `.report.html`, and `garak.log` produced and located.
- [ ] Per-probe hit rates extracted and ranked by severity.
- [ ] Successful attack strings captured from hit log as evidence.
- [ ] A mitigation applied and comparison re-run completed showing changed hit rates.
- [ ] Findings documented against OWASP LLM Top 10 and MITRE ATLAS for risk assessment.

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/red-teaming-llms-with-garak
