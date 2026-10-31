---
name: detecting-model-extraction-attacks
description: Detect MITRE ATLAS AML.T0024 attacks (model stealing, inversion, membership inference) performed via inference-API abuse, by monitoring per-principal query volume/distribution, rate-limiting and perturbing outputs, and red-teaming your model's extractability.
subdomain: ai-security
facing: config
upstream: detecting-model-extraction-attacks@54a7988 Apache-2.0, modified by wesh
---
> **Authorized Use Only:** extraction, inversion, and membership-inference techniques described here are intended for defenders testing their own models and for red teams operating under written authorization. Querying third-party model to clone it, reconstruct its training data, or infer membership without permission may violate terms of service, copyright, and privacy law.

## Prerequisites

- Python 3.9+ environment.
- Access to inference-API access logs (per-API-key/per-principal query counts, timestamps, input features or hashes, returned confidence vectors).
- For self-assessment red-teaming, install Adversarial Robustness Toolbox (ART), reference framework for extraction/inference attacks and defenses:
  ```bash
  pip install adversarial-robustness-toolbox scikit-learn numpy
  ```
- Optional: access to target model object (white/grey-box) or only its API (black-box).
- Authorization to test target model.

## MITRE ATT&CK Mapping

| ID | Name (MITRE ATLAS) | Tactic |
|----|--------------------|--------|
| AML.T0024 | Exfiltration via AI Inference API | Exfiltration |
| AML.T0024.000 | Infer Training Data Membership | Exfiltration |
| AML.T0024.001 | Invert AI Model | Exfiltration |
| AML.T0024.002 | Extract ML Model | Exfiltration |

## Workflow

### 1. Instrument inference API for detection signals
Capture fields detector needs. Per request, log principal (API key / IP / account), timestamp, input fingerprint, and whether caller requested probabilities/logits.

```python
import hashlib, json, time
def log_inference(principal, features, returned_probs):
    record = {
        "ts": time.time(),
        "principal": principal,
        # hash inputs so logs don't store raw sensitive data
        "input_hash": hashlib.sha256(json.dumps(features, sort_keys=True).encode()).hexdigest(),
        "wants_probs": returned_probs,
        "n_features": len(features),
    }
    with open("inference_audit.jsonl", "a") as f:
        f.write(json.dumps(record) + "\n")
```

### 2. Detect extraction-like query patterns
Score each principal on three signals that distinguish extraction from normal use: high query volume in window, high *unique-input* ratio (attackers rarely repeat), and high rate of full-probability requests.

```python
import collections, json
def score_principals(audit_path="inference_audit.jsonl", window_qps_threshold=100):
    by_principal = collections.defaultdict(lambda: {"q": 0, "uniq": set(), "probs": 0})
    for line in open(audit_path):
        r = json.loads(line)
        p = by_principal[r["principal"]]
        p["q"] += 1
        p["uniq"].add(r["input_hash"])
        p["probs"] += int(r["wants_probs"])
    findings = []
    for principal, p in by_principal.items():
        uniq_ratio = len(p["uniq"]) / max(p["q"], 1)
        prob_ratio = p["probs"] / max(p["q"], 1)
        suspicious = p["q"] > window_qps_threshold and uniq_ratio > 0.9 and prob_ratio > 0.8
        findings.append({"principal": principal, "queries": p["q"],
                         "unique_ratio": round(uniq_ratio, 3),
                         "prob_request_ratio": round(prob_ratio, 3),
                         "suspected_extraction": suspicious})
    return sorted(findings, key=lambda x: -x["queries"])
```

### 3. Measure your model's extractability with ART (self red-team)
Use ART's `CopycatCNN` (or `KnockoffNets`) to train surrogate from black-box queries and report fidelity at given query budget. Low query budget + high agreement = high risk.

```python
import numpy as np
from art.estimators.classification import SklearnClassifier
from art.attacks.extraction import KnockoffNets
from sklearn.ensemble import RandomForestClassifier
# victim is your already-trained model wrapped for ART
victim = SklearnClassifier(model=trained_model)            # your production model
thief_model = RandomForestClassifier(n_estimators=100)
thief = SklearnClassifier(model=thief_model)
attack = KnockoffNets(classifier=victim, batch_size_fit=64,
                      batch_size_query=64, nb_epochs=10, nb_stolen=2000)
stolen = attack.extract(x=x_pool, thief_classifier=thief)   # 2000-query budget
agreement = np.mean(stolen.predict(x_test).argmax(1) == victim.predict(x_test).argmax(1))
print(f"Surrogate fidelity (agreement with victim): {agreement:.2%} at 2000 queries")
```

### 4. Quantify training-data leakage with membership inference
Run ART's black-box membership-inference attack. accuracy meaningfully above 50% indicates model leaks membership (AML.T0024.000).

```python
from art.attacks.inference.membership_inference import MembershipInferenceBlackBox
mia = MembershipInferenceBlackBox(victim, attack_model_type="rf")
# fit the attack on a labeled split of known members / non-members
mia.fit(x_train[:500], y_train[:500], x_test[:500], y_test[:500])
member_pred = mia.infer(x_train[500:1000], y_train[500:1000])
nonmember_pred = mia.infer(x_test[500:1000], y_test[500:1000])
acc = (member_pred.mean() + (1 - nonmember_pred.mean())) / 2
print(f"Membership-inference accuracy: {acc:.2%} (0.50 = no leakage)")
```

### 5. Apply and validate defenses
Reduce information returned and query economics. Re-run steps 3 and 4 after each control to confirm extractability drops.

```python
# (a) Label-only responses: never return full probability vectors to untrusted callers.
def respond(probs, trusted):
    return int(probs.argmax()) if not trusted else probs.tolist()
# (b) Confidence rounding / output perturbation (raises queries needed for inversion):
def perturb(probs, decimals=2, noise=0.01):
    p = np.round(probs, decimals) + np.random.normal(0, noise, probs.shape)
    p = np.clip(p, 0, None)
    return p / p.sum()
```
Defense in depth combines these with strict **per-principal rate limiting**, anomaly alerting from step 2, ART's `ReverseSigmoid` / prediction-poisoning postprocessor, and watermarking so extracted surrogate remains attributable.

### 6. Alert and respond
Wire step-2 findings into your SIEM. On confirmed extraction pattern: throttle or revoke API key, switch principal to label-only responses, preserve audit log as evidence, and assess membership-inference exposure for any sensitive training data.

## Tools and Resources

| Resource | Link |
|----------|------|
| MITRE ATLAS AML.T0024 — Exfiltration via AI Inference API | https://atlas.mitre.org/techniques/AML.T0024 |
| Adversarial Robustness Toolbox (ART) | https://github.com/Trusted-AI/adversarial-robustness-toolbox |
| ART extraction attacks (CopycatCNN, KnockoffNets) | https://adversarial-robustness-toolbox.readthedocs.io/ |
| MITRE ATLAS Matrix | https://atlas.mitre.org/matrices/ATLAS |
| NIST AI RMF (MEASURE function) | https://www.nist.gov/itl/ai-risk-management-framework |

## Detection Signal Reference

| Signal | Normal use | Extraction behavior |
|--------|-----------|---------------------|
| Query volume per principal | Bounded, bursty | high, sustained |
| Unique-input ratio | Repeats common inputs | Near-1.0 (rarely repeats) |
| Confidence-vector requests | Mostly top label | Demands full probs/logits |
| Input distribution | In-distribution | Near-boundary / synthetic / grid |
| Inter-query timing | Human-paced | Automated, regular |

## Validation Criteria

- [ ] Inference API logs per-principal query volume, input fingerprint, and confidence-exposure.
- [ ] Detector scores principals and flags high-volume, high-unique-ratio, full-vector callers.
- [ ] ART extraction attack run against own model; surrogate fidelity vs. query budget reported.
- [ ] Membership-inference accuracy measured and compared against 50% baseline.
- [ ] Label-only / confidence-perturbation defenses applied and re-tested.
- [ ] Per-principal rate limiting enforced and validated.
- [ ] Alerts routed to SIEM with response playbook (throttle, revoke, preserve evidence).

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/detecting-model-extraction-attacks
