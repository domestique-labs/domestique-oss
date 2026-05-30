# LLMGuard

An enterprise-grade LLM firewall that prevents sensitive data leakage to
external AI providers. Intercepts traffic to ChatGPT, Claude, Gemini, Copilot,
and 15+ other LLM services. Deploys company-wide with zero per-app
configuration.

## Design Principles

- **Near-zero latency** - parallel async detection; regex fast-path skips NLP
  when content is clean.
- **Modular** - detectors, policy, and transport are independent packages with
  protocol-based contracts.
- **Fail-safe** - configurable fail-open/closed; never silently drops requests.
- **Cross-platform** - runs on macOS (native app), Windows, and Linux.

## Quick Start

### Prerequisites

- **Python 3.11+** - [python.org/downloads](https://www.python.org/downloads/)
- **Ollama** (optional, for LLM classifier) - [ollama.com/download](https://ollama.com/download)

### Install

The installer detects your hardware (RAM/GPU/VRAM), recommends a detection
preset that fits, and downloads only what you confirm.

**macOS:**
```bash
git clone https://github.com/majercakdavid/llmguard.git
cd llmguard
./scripts/install.sh                    # creates .venv, installs deps, builds .app
open dist/LLMGuard.app                  # launches native app + dashboard
```

**Windows:**
```powershell
git clone https://github.com/majercakdavid/llmguard.git
cd llmguard
install.bat                             # or: .\install.ps1 -Yes -Preset balanced
run.bat                                 # opens dashboard at http://127.0.0.1:9876
```

**Linux:**
```bash
git clone https://github.com/majercakdavid/llmguard.git
cd llmguard
python3 scripts/install.py              # interactive: picks features + preset
python3 -m app                          # opens dashboard at http://127.0.0.1:9876
```

**Non-interactive (CI / headless):**
```bash
python scripts/install.py --yes --features all --preset balanced
```

Re-run the installer any time to add features or change presets.

### What gets installed

| Component | Install extra | Size | Description |
|---|---|---|---|
| Regex scanner | (always on) | 0 | API keys, JWTs, SSNs, credit cards, emails, phones |
| GLiNER PII | `[ner]` | ~300 MB | Zero-shot NER for names, addresses, DOBs |
| Presidio PII | `[pii]` | ~500 MB | spaCy-based PII with en_core_web_lg model |
| Browser proxy | `[browser-proxy]` | ~50 MB | MITM interception for 20+ LLM domains |
| LLM classifier | Ollama + model | 1-4 GB | Nuanced classification via local LLM |

### Detection presets (Tier 3 LLM classifier)

| Preset | Stack | VRAM | Latency | F1 | Notes |
|---|---|---|---|---|---|
| `minimal` | Regex only | 0 | <1ms | 14% | Pattern matching, no LLM |
| `balanced` | Regex + Qwen3 1.7B | 1.8 GB | ~164ms | 92% | Recommended - fits 16GB laptops |
| `maximum` | Regex + GLiNER + Qwen3 | 1.8 GB | ~209ms | 91% recall | Highest recall, more false positives |

Gemma 4 E2B is available as a manual toggle in the dashboard for 32GB+ machines.

### Dashboard

Once running, the dashboard is at **http://127.0.0.1:9876/** with:
- Real-time request log (blocked / allowed / redacted)
- Detection preset selector (Minimal / Balanced / Quality / Max Recall)
- Per-detector toggles (Regex, GLiNER, Gemma 4 E2B, Qwen3)
- GLiNER entity label and confidence configuration
- Benchmark runner (70-sample test suite)
- Policy rules and domain management

### Server / proxy mode (Docker)

```bash
cp .env.example .env          # add your LLM provider keys
docker compose up              # proxy on :8000, TLS on :443
curl localhost:8000/health     # check health
```

## How Transparent Interception Works

```
User / App  -->  System Proxy (PAC)  -->  LLMGuard (mitmproxy)  -->  LLM API
                 Routes only LLM          Inspect + Decide           OpenAI,
                 domains through           (<5ms p99 regex)          Claude, etc.
                 the firewall
```

1. PAC file routes LLM domains (chatgpt.com, api.openai.com, etc.) through the local proxy.
2. mitmproxy terminates TLS with a locally-trusted CA certificate.
3. Firewall scans request content in parallel (regex + GLiNER + LLM classifier).
4. Clean requests forward immediately; violations block or redact.

The CA certificate is auto-generated and trusted on first launch (no admin password needed on macOS).

## Project Layout

```
llmguard/
  detectors/          # Pluggable detection modules
    secrets.py        # Regex patterns (API keys, SSNs, emails)
    pii.py            # Presidio PII detector
    registry.py       # Detector registry + pipeline
    local_llm.py      # Ollama LLM classifier (Gemma 4 / Qwen3)
  policy/
    __init__.py       # Rule evaluation engine
    rules.yaml        # Declarative block/redact/allow rules
  config.py           # Settings model (env-driven)

app/
  services/
    mitm_addon.py     # mitmproxy addon (browser interception)
    proxy.py          # Proxy process manager
    pipeline_config.py # Shared pipeline config builder
  server/
    api.py            # Dashboard API server
  assets/
    dashboard.html    # Single-page dashboard UI
  config/
    schema.py         # App config schema (presets, detection stack)

scripts/
  install.py          # Cross-platform hardware-aware installer
  install.sh          # macOS install + py2app build
install.bat           # Windows installer wrapper
install.ps1           # Windows PowerShell installer
```

## License

MIT
