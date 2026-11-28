<div align="center">

# 🛡️ SentinelOps
### Secure AI Control Plane for LLM Agents

**Reference Implementation of Project Design Report v2.2** · `v1.0.0`

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/Pytest-43%20Passed-2ea44f?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![Policy](https://img.shields.io/badge/Policy-v2.2%20Validated-6366f1?style=flat-square)](policy.yaml)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20%26%20API%20Top%2010-dc2626?style=flat-square)](docs/threat_model.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

<p align="center">
  <em>A 5-checkpoint FastAPI security gateway that wraps a deliberately vulnerable LLM copilot, attacks it with an automated 49-case red-team suite, and proves measurable Attack Success Rate (ASR) reduction with zero unverified claims.</em>
</p>

[Quick Start](#-quick-start) •
[Architecture](#-architecture) •
[Verified Results](#-verified-evaluation-results) •
[Guardrail Policy](#-guardrail-policy--checkpoints) •
[API & Web UI](#-api--web-ui) •
[Repository Layout](#-repository-layout)

</div>

---

<!-- KPI Summary Strip -->
<table align="center">
  <tr>
    <td align="center" width="200">
      <h3>0.0%</h3>
      <sub><b>Defended ASR</b><br/>Down from 70.8% (dev)</sub>
    </td>
    <td align="center" width="200">
      <h3>0.0%</h3>
      <sub><b>False Positive Rate</b><br/>Across 76 benign queries</sub>
    </td>
    <td align="center" width="200">
      <h3>23.8 ms</h3>
      <sub><b>Mean Latency</b><br/>Target &lt; 300 ms</sub>
    </td>
    <td align="center" width="200">
      <h3>0.0158</h3>
      <sub><b>Classifier ECE</b><br/>Isotonic 5-fold CV</sub>
    </td>
  </tr>
</table>

---

## 📖 Overview

**SentinelOps** is a policy-driven **AI Security Control Plane** built to defend tool-using LLM agents and their backing REST APIs against **OWASP LLM Top 10** and **OWASP API Top 10** threats—without ever trusting raw model output.

It pairs a deliberately vulnerable target with a hardened gateway and an automated red-team suite to make security measurable:

| Mode / Stage | Purpose | Key Behavior |
|---|---|---|
| 🔓 **Baseline**<br/>`SENTINEL_MODE=baseline` | Deliberately vulnerable AI Ops Copilot *(synthetic waste-logistics domain)* | Weak auth, blended RAG prompts, string-built SQL, unrestricted tools, unfiltered output. |
| 🛡️ **Defended**<br/>`SENTINEL_MODE=defended` | Hardened 5-checkpoint FastAPI security gateway | Schema-validated [`policy.yaml`](policy.yaml), JWT/RBAC, rate limits, PII masking, HITL approvals, fail-closed timeouts. |
| 🎯 **Red-Team Proof** | Automated adversarial & regression harness | 49 OWASP-aligned attacks (`dev`, `held-out`, `adaptive`) + 76 benign queries (English, Hinglish, Hindi). |

> [!NOTE]
> All data is 100% synthetic — no real personal data, third-party services, or production systems are involved.

---

## ✨ Key Capabilities

- **5-Checkpoint Security Gateway**: Driven by a single schema-validated [`policy.yaml`](policy.yaml) ([`policy.schema.json`](policy.schema.json)) enforcing JWT/RBAC, token-bucket rate limiting, input/context/output gates, PII masking (regex + optional Presidio), and egress allowlists.
- **Hardened Tool Execution**: Enforces single-`SELECT` SQL gates, table allowlists, tenant-scoped DB filtering, dispatch caps, and a **Human-in-the-Loop (HITL) approval queue** (`/approvals`) for high-risk actions (`send_email`, `dispatch_vehicle`).
- **Audit Logging & Incident Investigation**: Emits structured JSONL logs ([`logging_utils.py`](src/sentinelops/logging_utils.py)) tagged with `request_id`, `policy_version`, and registered reason codes to power `/reports/timeline`, `/reports/vulnerability`, and `/reports/residual`.
- **Fail-Closed Self-Protection**: Bounded input normalisation (encodings, split words, length caps), timeout fail-closed (`GUARD_TIMEOUT`), and a CI policy-diff gate that blocks PRs attempting to loosen controls.

---

## 🎯 Threat-to-Control Matrix

| OWASP / PDR Threat | SentinelOps Control | Implementation |
|---|---|---|
| **Prompt Injection & Jailbreaks** `LLM01` | Input + context gates, calibrated classifier, canary & similarity checks | [`gates.py`](src/sentinelops/guardrails/gates.py), [`classifier.py`](src/sentinelops/guardrails/classifier.py) |
| **Excessive Agency** `LLM06` | Tool allowlist, param schemas, risk tiers, dispatch caps, HITL queue | [`ToolGate`](src/sentinelops/guardrails/gates.py), [`approval.py`](src/sentinelops/approval.py) |
| **Sensitive Data Exposure** `LLM02` `LLM07` | Tenant scoping, PII masking (regex/Presidio), egress domain allowlist | [`pii.py`](src/sentinelops/pii.py), [`OutputGate`](src/sentinelops/guardrails/gates.py) |
| **API Weaknesses** `API1–API4` | JWT auth, RBAC, BOLA/IDOR checks, parameterised SQL, rate limiting | [`auth.py`](src/sentinelops/auth.py), [`rate_limit.py`](src/sentinelops/rate_limit.py) |
| **Guardrail Bypass & Drift** | Schema-validated `policy.yaml`, CI policy diff gate, bounded normalisation | [`policy.py`](src/sentinelops/guardrails/policy.py), [`normalise.py`](src/sentinelops/guardrails/normalise.py) |

---

## 🚀 Quick Start

### 1. Install

**Windows (PowerShell)**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e . --no-deps --no-build-isolation
