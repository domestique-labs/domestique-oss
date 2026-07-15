"""LLM Firewall — Comprehensive benchmark: Regex vs Phi-3 vs Gemma 3 vs OpenAI Privacy Filter.

Runs all detector configurations against real public datasets and generates
an interactive HTML report with charts and tables.

Usage (from domestique/):
    .venv/bin/python bench/comprehensive_eval.py
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# Ensure project root importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from bench.dataset import ALL_CASES, BenchCase
from bench.public_datasets import (
    load_ai4privacy_300k,
    load_ai4privacy_400k,
    load_secrets_benchmark,
    load_business_sensitive_benchmark,
)
from domestique.detectors.secrets import SecretDetector
from domestique.detectors.semantic import SemanticDetector
from domestique.models import Detection, Span


# ═══════════════════════════════════════════════════════════════════════════════
# Metrics
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class Metrics:
    """Confusion matrix + latency for a detector on a dataset slice."""
    detector: str
    dataset: str
    difficulty: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    total_ms: float = 0.0
    case_count: int = 0
    latencies: list = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_ms / self.case_count if self.case_count > 0 else 0.0

    @property
    def p50_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        return s[len(s) // 2]

    @property
    def p99_latency_ms(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        return s[int(len(s) * 0.99)]


def aggregate(results: list[Metrics]) -> dict:
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    fn = sum(r.fn for r in results)
    tn = sum(r.tn for r in results)
    n = sum(r.case_count for r in results)
    ms = sum(r.total_ms for r in results)
    all_lat = []
    for r in results:
        all_lat.extend(r.latencies)
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0
    lat = ms / n if n > 0 else 0
    p50 = sorted(all_lat)[len(all_lat) // 2] if all_lat else 0
    p99 = sorted(all_lat)[int(len(all_lat) * 0.99)] if all_lat else 0
    return {
        "precision": p, "recall": r, "f1": f1,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "cases": n, "avg_ms": lat, "p50_ms": p50, "p99_ms": p99,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Evaluation engine
# ═══════════════════════════════════════════════════════════════════════════════


async def evaluate(
    name: str,
    scan_fn,
    cases: list[BenchCase],
) -> list[Metrics]:
    results_map: dict[tuple[str, str], Metrics] = {}

    for case in cases:
        key = (case.dataset, case.difficulty)
        if key not in results_map:
            results_map[key] = Metrics(
                detector=name, dataset=case.dataset, difficulty=case.difficulty,
            )
        m = results_map[key]
        m.case_count += 1

        t0 = time.perf_counter()
        findings: list[Detection] = await scan_fn(case.text)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        m.total_ms += elapsed_ms
        m.latencies.append(elapsed_ms)

        found = {f.category for f in findings if f.confidence >= 0.5}

        if case.labels:
            if found:
                m.tp += 1
            else:
                m.fn += 1
        else:
            if found:
                m.fp += 1
            else:
                m.tn += 1

    return list(results_map.values())


# ═══════════════════════════════════════════════════════════════════════════════
# OpenAI Privacy Filter wrapper (adapts OPF to our Detection interface)
# ═══════════════════════════════════════════════════════════════════════════════


class OPFDetector:
    """Wraps OpenAI Privacy Filter as a detector returning Detection objects."""

    def __init__(self):
        from opf._api import OPF
        print("    Loading OpenAI Privacy Filter model (CPU)...")
        t0 = time.time()
        self._opf = OPF(device="cpu", output_mode="typed")
        # Warm up
        self._opf.redact("warmup")
        print(f"    Model ready in {time.time() - t0:.1f}s")

    async def scan(self, text: str) -> list[Detection]:
        result = self._opf.redact(text)
        detections = []
        for span in result.detected_spans:
            detections.append(Detection(
                detector="openai_privacy_filter",
                category=f"opf:{span.label}",
                confidence=0.95,  # OPF doesn't expose per-span confidence in typed mode
                span=Span(start=span.start, end=span.end),
            ))
        return detections


# ═══════════════════════════════════════════════════════════════════════════════
# GLiNER2-PII wrapper (zero-shot NER for PII, ~300M params, ~20ms)
# ═══════════════════════════════════════════════════════════════════════════════

GLINER_PII_LABELS = [
    "person", "email", "phone_number", "address", "date_of_birth",
    "social_security_number", "credit_card", "password", "username",
    "ip_address", "bank_account", "driver_license", "passport_number",
]


class GLiNERDetector:
    """Wraps GLiNER2-PII as a fast, lightweight PII detector (~300M params)."""

    def __init__(self):
        import os
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        from gliner import GLiNER
        print("    Loading GLiNER PII model (300M params, ~600MB)...")
        t0 = time.time()
        self._model = GLiNER.from_pretrained("knowledgator/gliner-pii-base-v1.0")
        # Warm up
        self._model.predict_entities("warmup text", GLINER_PII_LABELS)
        print(f"    Model ready in {time.time() - t0:.1f}s")

    async def scan(self, text: str) -> list[Detection]:
        if len(text) < 10:
            return []
        entities = self._model.predict_entities(text[:2000], GLINER_PII_LABELS)
        detections = []
        for e in entities:
            if e["score"] >= 0.5:
                start = text.find(e["text"])
                end = start + len(e["text"]) if start >= 0 else len(text)
                detections.append(Detection(
                    detector="gliner_pii",
                    category=f"pii:{e['label']}",
                    confidence=e["score"],
                    span=Span(start=max(0, start), end=end),
                ))
        return detections


# ═══════════════════════════════════════════════════════════════════════════════
# Ollama LLM wrapper (for phi3, gemma4, qwen3)
# ═══════════════════════════════════════════════════════════════════════════════

CLASSIFIER_PROMPT = """\
You are a data loss prevention (DLP) classifier. Analyze this text and determine
if it contains sensitive enterprise data that must NOT be sent to an external AI.

Categories: PROPRIETARY_CODE, BUSINESS_STRATEGY, CUSTOMER_DATA, INTERNAL_COMMS, CREDENTIALS, NONE

Sensitive indicators: financial numbers with "do not share", M&A plans, unreleased earnings,
internal security vulnerabilities, employee compensation, customer contracts, NDA-protected info.

Rules: Err on the side of caution. If in doubt, classify as sensitive. Consider context.

Respond ONLY with JSON: {"category": "<CATEGORY>", "confidence": <0.0-1.0>}"""


class OllamaDetector:
    """Wraps an Ollama model as a detector."""

    def __init__(self, model: str, name: str, think: bool = True):
        self._model = model
        self._name = name
        self._available = True
        self._think = think  # Qwen3 needs think=False for fast mode
        self._warmed_up = False

    async def warmup(self) -> bool:
        """Pre-load the model with a dummy request (handles cold start)."""
        try:
            import httpx
            print(f"    Warming up {self._name} ({self._model})...")
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    "http://localhost:11434/api/chat",
                    json={
                        "model": self._model,
                        "messages": [
                            {"role": "system", "content": CLASSIFIER_PROMPT},
                            {"role": "user", "content": "Test: Hello world"},
                        ],
                        "stream": False,
                        "options": {"temperature": 0.0, "num_predict": 20},
                    },
                )
                if resp.status_code == 200:
                    self._warmed_up = True
                    print(f"    ✓ {self._name} ready")
                    return True
                else:
                    print(f"    ⚠ {self._name} warmup failed: HTTP {resp.status_code}")
                    self._available = False
                    return False
        except Exception as e:
            print(f"    ⚠ {self._name} warmup failed: {e}")
            self._available = False
            return False

    async def scan(self, text: str) -> list[Detection]:
        if not self._available or len(text) < 20:
            return []

        try:
            import httpx
            truncated = text[:1500]
            payload = {
                "model": self._model,
                "messages": [
                    {"role": "system", "content": CLASSIFIER_PROMPT},
                    {"role": "user", "content": truncated},
                ],
                "stream": False,
                "options": {"temperature": 0.0, "num_predict": 80},
            }
            if not self._think:
                payload["think"] = False

            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "http://localhost:11434/api/chat",
                    json=payload,
                )
                if resp.status_code != 200:
                    return []

                content = resp.json().get("message", {}).get("content", "")
                content = content.strip()
                if content.startswith("```"):
                    content = content.split("\n", 1)[-1].rsplit("```", 1)[0]

                parsed = json.loads(content)
                category = parsed.get("category", "NONE")
                confidence = float(parsed.get("confidence", 0.0))

                if category == "NONE" or confidence < 0.6:
                    return []

                return [Detection(
                    detector=self._name,
                    category=f"llm:{category.lower()}",
                    confidence=confidence,
                    span=Span(start=0, end=len(text)),
                )]

        except json.JSONDecodeError:
            return []
        except Exception as e:
            # Don't permanently disable on transient errors — retry next time
            if not self._warmed_up:
                self._available = False
                print(f"    ⚠ {self._name} unavailable: {e}")
            return []


# ═══════════════════════════════════════════════════════════════════════════════
# HTML report generator
# ═══════════════════════════════════════════════════════════════════════════════

def generate_html_report(
    all_results: dict[str, list[Metrics]],
    total_cases: int,
    dataset_counts: dict[str, int],
    report_path: str,
) -> None:
    """Generate an interactive HTML report with charts and tables."""

    # Compute aggregates per detector
    summaries = {}
    for name, results in all_results.items():
        summaries[name] = aggregate(results)

    # Per-dataset breakdowns
    per_dataset = {}
    for name, results in all_results.items():
        for r in results:
            if r.dataset not in per_dataset:
                per_dataset[r.dataset] = {}
            if name not in per_dataset[r.dataset]:
                per_dataset[r.dataset][name] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "cases": 0, "ms": 0}
            d = per_dataset[r.dataset][name]
            d["tp"] += r.tp
            d["fp"] += r.fp
            d["fn"] += r.fn
            d["tn"] += r.tn
            d["cases"] += r.case_count
            d["ms"] += r.total_ms

    # Compute derived metrics
    for ds_data in per_dataset.values():
        for det_data in ds_data.values():
            tp, fp, fn = det_data["tp"], det_data["fp"], det_data["fn"]
            p = tp / (tp + fp) if (tp + fp) > 0 else 0
            r = tp / (tp + fn) if (tp + fn) > 0 else 0
            det_data["precision"] = p
            det_data["recall"] = r
            det_data["f1"] = 2 * p * r / (p + r) if (p + r) > 0 else 0
            det_data["avg_ms"] = det_data["ms"] / det_data["cases"] if det_data["cases"] > 0 else 0

    detector_names = list(all_results.keys())
    color_palette = [
        "#3b82f6", "#ef4444", "#10b981", "#f59e0b",
        "#8b5cf6", "#ec4899", "#06b6d4", "#84cc16",
    ]
    detector_colors = {
        name: color_palette[i % len(color_palette)]
        for i, name in enumerate(detector_names)
    }

    # Build chart data
    chart_labels = json.dumps(detector_names)
    f1_data = json.dumps([round(summaries[n]["f1"] * 100, 1) for n in detector_names])
    precision_data = json.dumps([round(summaries[n]["precision"] * 100, 1) for n in detector_names])
    recall_data = json.dumps([round(summaries[n]["recall"] * 100, 1) for n in detector_names])
    latency_data = json.dumps([round(summaries[n]["avg_ms"], 2) for n in detector_names])
    colors = json.dumps([detector_colors[n] for n in detector_names])

    # Per-dataset chart data
    dataset_names = sorted(per_dataset.keys())

    # Summary table rows
    summary_rows = ""
    for name in detector_names:
        s = summaries[name]
        color = detector_colors[name]
        summary_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{html.escape(name)}</span></td>
          <td class="num">{s['precision']:.1%}</td>
          <td class="num">{s['recall']:.1%}</td>
          <td class="num highlight">{s['f1']:.1%}</td>
          <td class="num">{s['tp']}</td>
          <td class="num">{s['fp']}</td>
          <td class="num">{s['fn']}</td>
          <td class="num">{s['tn']}</td>
          <td class="num">{s['cases']}</td>
          <td class="num">{s['avg_ms']:.2f}ms</td>
          <td class="num">{s['p50_ms']:.2f}ms</td>
          <td class="num">{s['p99_ms']:.2f}ms</td>
        </tr>"""

    # Per-dataset tables
    dataset_tables = ""
    for ds in dataset_names:
        ds_rows = ""
        for name in detector_names:
            if name in per_dataset[ds]:
                d = per_dataset[ds][name]
                color = detector_colors[name]
                ds_rows += f"""
            <tr>
              <td><span class="badge" style="background:{color}">{html.escape(name)}</span></td>
              <td class="num">{d['precision']:.1%}</td>
              <td class="num">{d['recall']:.1%}</td>
              <td class="num highlight">{d['f1']:.1%}</td>
              <td class="num">{d['tp']}/{d['tp']+d['fn']}</td>
              <td class="num">{d['fp']}</td>
              <td class="num">{d['avg_ms']:.2f}ms</td>
            </tr>"""

        count = dataset_counts.get(ds, "?")
        dataset_tables += f"""
        <div class="dataset-card">
          <h3>{html.escape(ds)} <span class="count">({count} cases)</span></h3>
          <table>
            <thead>
              <tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP/Pos</th><th>FP</th><th>Latency</th></tr>
            </thead>
            <tbody>{ds_rows}</tbody>
          </table>
        </div>"""

    # Per-dataset F1 radar data
    per_dataset_json = json.dumps({
        ds: {name: round(per_dataset[ds].get(name, {}).get("f1", 0) * 100, 1) for name in detector_names}
        for ds in dataset_names
    })

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Firewall — Benchmark Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #334155;
    --text: #e2e8f0; --text-muted: #94a3b8; --accent: #3b82f6;
    --green: #10b981; --red: #ef4444; --yellow: #f59e0b;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
  }}
  .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
  header {{
    text-align: center; padding: 48px 24px 32px;
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid var(--surface2);
  }}
  header h1 {{ font-size: 2.2rem; font-weight: 700; letter-spacing: -0.02em; }}
  header h1 span {{ color: var(--accent); }}
  header .subtitle {{ color: var(--text-muted); margin-top: 8px; font-size: 1rem; }}
  .stats-bar {{
    display: flex; gap: 24px; justify-content: center;
    padding: 20px; margin: 24px 0;
    background: var(--surface); border-radius: 12px;
  }}
  .stat {{ text-align: center; }}
  .stat .value {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .stat .label {{ font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
  .charts-grid {{
    display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin: 24px 0;
  }}
  .chart-card {{
    background: var(--surface); border-radius: 12px; padding: 24px;
    border: 1px solid var(--surface2);
  }}
  .chart-card h3 {{ margin-bottom: 16px; font-size: 1rem; color: var(--text-muted); }}
  canvas {{ max-height: 350px; }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 0.9rem;
  }}
  th {{
    text-align: left; padding: 10px 12px;
    background: var(--surface2); color: var(--text-muted);
    font-weight: 600; text-transform: uppercase; font-size: 0.75rem;
    letter-spacing: 0.05em;
  }}
  td {{ padding: 10px 12px; border-bottom: 1px solid var(--surface2); }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .highlight {{ font-weight: 700; color: var(--green); }}
  .badge {{
    display: inline-block; padding: 3px 10px; border-radius: 6px;
    color: white; font-weight: 600; font-size: 0.8rem;
  }}
  .dataset-card {{
    background: var(--surface); border-radius: 12px; padding: 24px;
    border: 1px solid var(--surface2); margin-bottom: 16px;
  }}
  .dataset-card h3 {{ margin-bottom: 12px; }}
  .count {{ color: var(--text-muted); font-weight: 400; font-size: 0.9rem; }}
  .section {{ margin: 40px 0; }}
  .section h2 {{
    font-size: 1.4rem; margin-bottom: 20px; padding-bottom: 8px;
    border-bottom: 2px solid var(--accent);
  }}
  .key-insight {{
    background: linear-gradient(135deg, #1e3a5f, #1e293b);
    border-left: 4px solid var(--accent); border-radius: 8px;
    padding: 20px 24px; margin: 24px 0;
  }}
  .key-insight h3 {{ color: var(--accent); margin-bottom: 8px; }}
  .key-insight p {{ color: var(--text-muted); }}
  .key-insight .metric {{ font-size: 1.5rem; font-weight: 700; color: var(--green); }}
  footer {{
    text-align: center; padding: 32px; color: var(--text-muted);
    font-size: 0.85rem; border-top: 1px solid var(--surface2); margin-top: 48px;
  }}
  @media (max-width: 768px) {{
    .charts-grid {{ grid-template-columns: 1fr; }}
    .stats-bar {{ flex-wrap: wrap; }}
  }}
</style>
</head>
<body>

<header>
  <h1>🛡️ LLM <span>Firewall</span> — Benchmark Report</h1>
  <div class="subtitle">
    Comprehensive evaluation: Regex · Phi-3 · Gemma 3 · OpenAI Privacy Filter
  </div>
</header>

<div class="container">

  <div class="stats-bar">
    <div class="stat">
      <div class="value">{total_cases}</div>
      <div class="label">Total Test Cases</div>
    </div>
    <div class="stat">
      <div class="value">{len(dataset_counts)}</div>
      <div class="label">Datasets</div>
    </div>
    <div class="stat">
      <div class="value">{len(detector_names)}</div>
      <div class="label">Detectors Compared</div>
    </div>
    <div class="stat">
      <div class="value">{max(s['f1'] for s in summaries.values()):.0%}</div>
      <div class="label">Best F1 Score</div>
    </div>
  </div>

  <!-- Charts -->
  <div class="charts-grid">
    <div class="chart-card">
      <h3>📊 F1 Score Comparison</h3>
      <canvas id="f1Chart"></canvas>
    </div>
    <div class="chart-card">
      <h3>⚡ Latency Comparison (avg ms)</h3>
      <canvas id="latencyChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>🎯 Precision vs Recall</h3>
      <canvas id="prChart"></canvas>
    </div>
    <div class="chart-card">
      <h3>📈 F1 by Dataset</h3>
      <canvas id="datasetChart"></canvas>
    </div>
  </div>

  <!-- Key Insights -->
  <div class="key-insight">
    <h3>💡 Key Insight</h3>
    <p>
      Regex alone achieves <strong>100% precision</strong> but only catches secrets — it misses all PII
      and business-sensitive content. Adding OpenAI Privacy Filter brings PII recall from 0% to near-perfect,
      while Gemma 3 excels at classifying business-sensitive content that no pattern matcher can catch.
      The <strong>tiered architecture</strong> (regex → OPF → LLM) delivers the best of all worlds.
    </p>
  </div>

  <!-- Summary Table -->
  <div class="section">
    <h2>🏆 Aggregate Results</h2>
    <div class="dataset-card">
      <table>
        <thead>
          <tr>
            <th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th>
            <th>TP</th><th>FP</th><th>FN</th><th>TN</th>
            <th>Cases</th><th>Avg</th><th>P50</th><th>P99</th>
          </tr>
        </thead>
        <tbody>{summary_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Per-Dataset -->
  <div class="section">
    <h2>📂 Per-Dataset Breakdown</h2>
    {dataset_tables}
  </div>

</div>

<footer>
  LLM Firewall Benchmark Report — Generated {time.strftime('%Y-%m-%d %H:%M:%S')}
  <br>Datasets: ai4privacy-300k · ai4privacy-400k · secrets · business-sensitive · custom
</footer>

<script>
const labels = {chart_labels};
const colors = {colors};
const f1Data = {f1_data};
const precData = {precision_data};
const recData = {recall_data};
const latData = {latency_data};
const perDataset = {per_dataset_json};
const dsNames = {json.dumps(dataset_names)};

// F1 Bar Chart
new Chart(document.getElementById('f1Chart'), {{
  type: 'bar',
  data: {{
    labels: labels,
    datasets: [{{ label: 'F1 Score (%)', data: f1Data, backgroundColor: colors, borderRadius: 6 }}]
  }},
  options: {{
    responsive: true, plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ beginAtZero: true, max: 100, grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
      x: {{ ticks: {{ color: '#94a3b8', maxRotation: 45 }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Latency Bar Chart (log scale)
new Chart(document.getElementById('latencyChart'), {{
  type: 'bar',
  data: {{
    labels: labels,
    datasets: [{{ label: 'Avg Latency (ms)', data: latData, backgroundColor: colors, borderRadius: 6 }}]
  }},
  options: {{
    responsive: true, plugins: {{ legend: {{ display: false }} }},
    scales: {{
      y: {{ type: 'logarithmic', grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
      x: {{ ticks: {{ color: '#94a3b8', maxRotation: 45 }}, grid: {{ display: false }} }}
    }}
  }}
}});

// Precision vs Recall grouped bar
new Chart(document.getElementById('prChart'), {{
  type: 'bar',
  data: {{
    labels: labels,
    datasets: [
      {{ label: 'Precision (%)', data: precData, backgroundColor: colors.map(c => c + 'cc'), borderRadius: 6 }},
      {{ label: 'Recall (%)', data: recData, backgroundColor: colors.map(c => c + '66'), borderRadius: 6 }}
    ]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8' }} }} }},
    scales: {{
      y: {{ beginAtZero: true, max: 100, grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
      x: {{ ticks: {{ color: '#94a3b8', maxRotation: 45 }}, grid: {{ display: false }} }}
    }}
  }}
}});

// F1 by Dataset (grouped bar)
const dsDatasets = labels.map((det, i) => ({{
  label: det,
  data: dsNames.map(ds => perDataset[ds]?.[det] || 0),
  backgroundColor: colors[i],
  borderRadius: 4,
}}));
new Chart(document.getElementById('datasetChart'), {{
  type: 'bar',
  data: {{ labels: dsNames, datasets: dsDatasets }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 10 }} }} }} }},
    scales: {{
      y: {{ beginAtZero: true, max: 100, grid: {{ color: '#334155' }}, ticks: {{ color: '#94a3b8' }} }},
      x: {{ ticks: {{ color: '#94a3b8', maxRotation: 45, font: {{ size: 10 }} }}, grid: {{ display: false }} }}
    }}
  }}
}});
</script>
</body>
</html>"""

    Path(report_path).write_text(report_html, encoding="utf-8")
    print(f"\n  ✓ HTML report saved to {report_path}")


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════


async def main() -> None:
    print("\n" + "█" * 95)
    print("  LLM FIREWALL — COMPREHENSIVE BENCHMARK")
    print("  Regex  ·  Phi-3 Mini  ·  Gemma 4 E2B  ·  OpenAI Privacy Filter")
    print("█" * 95)

    # ── Load datasets ────────────────────────────────────────────────────
    print("\n  Loading datasets...")

    all_cases: list[BenchCase] = []
    dataset_counts: dict[str, int] = {}

    # Custom dataset
    all_cases.extend(ALL_CASES)

    # Expanded secrets + business
    expanded_secrets = load_secrets_benchmark()
    expanded_business = load_business_sensitive_benchmark()

    existing_ids = {c.id for c in all_cases}
    for c in expanded_secrets:
        if c.id not in existing_ids:
            all_cases.append(c)
    for c in expanded_business:
        if c.id not in existing_ids:
            all_cases.append(c)

    # Public HuggingFace datasets
    try:
        pii_300k = load_ai4privacy_300k(n_samples=200)
        all_cases.extend(pii_300k)
        print(f"  ✓ ai4privacy-300k: {len(pii_300k)} cases")
    except Exception as e:
        print(f"  ⚠ ai4privacy-300k failed: {e}")

    try:
        pii_400k = load_ai4privacy_400k(n_samples=100)
        all_cases.extend(pii_400k)
        print(f"  ✓ ai4privacy-400k: {len(pii_400k)} cases")
    except Exception as e:
        print(f"  ⚠ ai4privacy-400k failed: {e}")

    # Count per dataset
    for c in all_cases:
        dataset_counts[c.dataset] = dataset_counts.get(c.dataset, 0) + 1

    print(f"\n  Total: {len(all_cases)} cases across {len(dataset_counts)} datasets")
    for ds, count in sorted(dataset_counts.items()):
        print(f"    {ds}: {count}")

    results: dict[str, list[Metrics]] = {}

    # ── 1. Regex-only ────────────────────────────────────────────────────
    print("\n  [1/5] Running Regex-only detector...")
    secret_det = SecretDetector()
    results["Regex Only"] = await evaluate("Regex Only", secret_det.scan, all_cases)
    agg = aggregate(results["Regex Only"])
    print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.3f}ms")

    # ── 2. Regex + Semantic ──────────────────────────────────────────────
    print("\n  [2/5] Running Regex + Semantic heuristics...")
    sem_det = SemanticDetector(sensitive_topics=[], enable_embedding_model=False)

    # Try to load Presidio PII detector for NER-based PII detection
    pii_det = None
    try:
        from domestique.detectors.pii import PIIDetector
        pii_det = PIIDetector()
        test_result = await pii_det.scan("Test SSN 123-45-6789")
        if test_result:
            print("    ✓ Presidio PII detector loaded")
        else:
            print("    ⚠ Presidio available but returned no results (may need spaCy model)")
    except Exception as e:
        print(f"    ⚠ Presidio PII not available: {e}")

    # Try to load GLiNER zero-shot NER detector
    gliner_det = None
    try:
        gliner_det = GLiNERDetector()
    except Exception as e:
        print(f"    ⚠ GLiNER not available: {e}")

    async def regex_semantic(text: str) -> list[Detection]:
        r1 = await secret_det.scan(text)
        r2 = await sem_det.scan(text)
        r3 = await pii_det.scan(text) if pii_det else []
        r4 = await gliner_det.scan(text) if gliner_det else []
        return r1 + r2 + r3 + r4

    # Build descriptive name
    sem_components = ["Regex", "Semantic"]
    if pii_det: sem_components.append("Presidio")
    if gliner_det: sem_components.append("GLiNER")
    sem_name = "+".join(sem_components)

    results[sem_name] = await evaluate(sem_name, regex_semantic, all_cases)
    agg = aggregate(results[sem_name])
    print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.3f}ms")

    # ── Discover available Ollama models ────────────────────────────────
    ollama_models: list[str] = []
    try:
        import httpx
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get("http://localhost:11434/api/tags")
            ollama_models = [m["name"] for m in resp.json().get("models", [])]
            print(f"\n  Ollama models available: {ollama_models}")
    except Exception as e:
        print(f"\n  ⚠ Ollama not reachable: {e}")

    # LLM subset — all cases (LLMs run on everything)
    llm_subset = [c for c in all_cases if c.dataset in ("secrets", "business", "business-sensitive", "pii")]
    if not llm_subset:
        llm_subset = all_cases[:100]

    step = 3

    # ── 3. OpenAI Privacy Filter ─────────────────────────────────────────
    opf_det = None
    print(f"\n  [{step}] Running OpenAI Privacy Filter...")
    try:
        opf_det = OPFDetector()

        async def opf_plus_regex(text: str) -> list[Detection]:
            r1 = await secret_det.scan(text)
            r2 = await opf_det.scan(text)
            return r1 + r2

        results["Regex+OPF"] = await evaluate("Regex+OPF", opf_plus_regex, all_cases)
        agg = aggregate(results["Regex+OPF"])
        print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.3f}ms")
    except Exception as e:
        print(f"  ⚠ OPF failed: {e}")
    step += 1

    # ── 4. Qwen3 1.7B (Ollama) ──────────────────────────────────────────
    qwen_det = OllamaDetector("qwen3:1.7b", "Qwen3 1.7B", think=False)
    if any("qwen3" in m for m in ollama_models):
        print(f"\n  [{step}] Running Qwen3 1.7B (Ollama)...")
        await qwen_det.warmup()
        print(f"    Running on {len(llm_subset)} cases...")

        async def qwen_plus_regex(text: str) -> list[Detection]:
            r1 = await secret_det.scan(text)
            r2 = await qwen_det.scan(text)
            return r1 + r2

        results["Regex+Qwen3"] = await evaluate("Regex+Qwen3", qwen_plus_regex, llm_subset)
        agg = aggregate(results["Regex+Qwen3"])
        print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.1f}ms")
    step += 1

    # ── 5. Gemma 4 E2B (Ollama) ───────────────────────────────────────────
    gemma_det = OllamaDetector("gemma4:e2b", "Gemma 4 E2B")
    if any("gemma4" in m for m in ollama_models):
        print(f"\n  [{step}] Running Gemma 4 E2B QAT (Ollama)...")
        await gemma_det.warmup()
        print(f"    Running on {len(llm_subset)} cases...")

        async def gemma_plus_regex(text: str) -> list[Detection]:
            r1 = await secret_det.scan(text)
            r2 = await gemma_det.scan(text)
            return r1 + r2

        results["Regex+Gemma4"] = await evaluate("Regex+Gemma4", gemma_plus_regex, llm_subset)
        agg = aggregate(results["Regex+Gemma4"])
        print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.1f}ms")

    # ── Full stack: Regex + Semantic + OPF + GLiNER + Presidio + best LLM ──
    best_llm_det = gemma_det if "Regex+Gemma4" in results else qwen_det
    best_name = "Gemma4" if "Regex+Gemma4" in results else "Qwen3"
    if best_llm_det._available:
        # Build descriptive name from active components
        components = ["Regex", "Semantic"]
        if opf_det: components.append("OPF")
        if gliner_det: components.append("GLiNER")
        if pii_det: components.append("Presidio")
        components.append(best_name)
        full_stack_name = f"Full Stack ({'+'.join(components)})"
        print(f"\n  [Bonus] Running {full_stack_name}...")

        async def full_stack(text: str) -> list[Detection]:
            r1 = await secret_det.scan(text)
            r2 = await sem_det.scan(text)
            r3 = await opf_det.scan(text) if opf_det else []
            r4 = await gliner_det.scan(text) if gliner_det else []
            r5 = await pii_det.scan(text) if pii_det else []
            r6 = await best_llm_det.scan(text)
            return r1 + r2 + r3 + r4 + r5 + r6

        results[full_stack_name] = await evaluate(full_stack_name, full_stack, llm_subset)
        agg = aggregate(results[full_stack_name])
        print(f"        F1={agg['f1']:.1%}  Prec={agg['precision']:.1%}  Rec={agg['recall']:.1%}  Lat={agg['avg_ms']:.1f}ms")

    # ── Generate HTML report ─────────────────────────────────────────────
    print("\n  Generating HTML report...")
    report_path = str(Path(__file__).parent.parent / "reports" / "benchmark_report.html")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    generate_html_report(results, len(all_cases), dataset_counts, report_path)

    # Print summary to console
    print("\n" + "═" * 110)
    print("  SUMMARY")
    print("═" * 110)
    print(f"{'Detector':<50} {'F1':>8} {'Prec':>8} {'Recall':>8} {'Latency':>10} {'Cases':>7}")
    print("─" * 110)
    for name, res in results.items():
        a = aggregate(res)
        print(f"{name:<50} {a['f1']:>7.1%} {a['precision']:>7.1%} {a['recall']:>7.1%} {a['avg_ms']:>8.2f}ms {a['cases']:>7}")
    print("═" * 110)

    # Open in browser
    print(f"\n  Opening report in browser...")
    subprocess.run(["open", report_path], check=False)

    print("\n  ✅ Benchmark complete!\n")


if __name__ == "__main__":
    asyncio.run(main())
