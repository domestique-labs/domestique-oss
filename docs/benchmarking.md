# Domestique — Benchmarking & Quality Analysis

## Benchmarks for Evaluating Our Solution

### 1. Quality Benchmarks (Detection Accuracy)

| Benchmark | What It Tests | Dataset Size | Metrics | Link |
|-----------|--------------|--------------|---------|------|
| **GuardBench** (EMNLP 2024) | Full guardrail evaluation — PII, toxicity, topic filtering | 40+ datasets | Precision, Recall, F1, MCC, FPR, FNR | [GitHub](https://github.com/AmenRa/guardbench) |
| **PII-Scope** | PII extraction/leakage under adversarial conditions | Multi-model | Extraction rate, adversarial robustness | [arXiv](https://arxiv.org/abs/2410.06704) |
| **PINT** (Lakera) | Prompt injection detection | 4,314+ prompts | TPR, FPR, latency | [GitHub](https://github.com/lakeraai/pint-benchmark) |
| **CyberSecEval** (Meta Purple Llama) | Security — injection, leakage, override | 1,000+ attacks | LLM-judge verdicts | [Promptfoo](https://www.promptfoo.dev/docs/red-team/plugins/cyberseceval/) |
| **Basak et al.** (ESEM 2023) | Secret detection tool comparison | Real repos | Precision, Recall per tool | [arXiv](https://arxiv.org/abs/2307.00714) |
| **Open-Prompt-Injection** | Agent-level prompt injection | 5,000+ | ASR, MR, Precision | [EmergentMind](https://www.emergentmind.com/topics/open-prompt-injection-benchmark) |

### 2. Latency Benchmarks

| What to Measure | Target | Tool |
|----------------|--------|------|
| Regex secret scanning (our current) | < 0.5 ms p99 | `pytest-benchmark` / `timeit` |
| Presidio PII detection | < 10 ms p99 | `pytest-benchmark` |
| Embedding similarity (MiniLM-L6) | < 15 ms p99 (GPU), < 50 ms (CPU) | Custom harness |
| Local LLM classification (1-3B) | < 20 ms (GPU), < 100 ms (CPU) | `llama.cpp` benchmarks |
| End-to-end proxy overhead | < 20 ms p99 (without local LLM) | `wrk` / `k6` load testing |

---

## Published Figures for the Underlying Techniques

> **These are third-party published figures for the general techniques, measured
> by other people on other corpora. They are not domestique measurements and say
> nothing about how domestique scores.** Domestique's own detection quality is
> whatever the harnesses in `benchmarks/` report on the corpora in this
> repository; no other number in this document describes it.

| Detector Layer | Approach | Published F1 (third-party) | Catches | Misses |
|----------------|----------|-----------------|---------|--------|
| **Secret scanner** (regex) | Compiled regex patterns | ~46% precision, ~88% recall* | Known patterns: AWS keys, GH tokens, JWTs | Obfuscated, encoded, split secrets |
| **PII detector** (Presidio) | spaCy NER + regex | ~85-92% F1 | Structured PII: emails, SSNs, phones | Contextual PII: "her manager Sarah" |
| **Semantic detector** (embeddings) | Sentence-transformers | ~75-85% F1 (topic matching) | Topic similarity, encoded blobs | Novel/paraphrased sensitive content |

*Based on Basak et al. ESEM 2023 comparative study of secret detection tools.

---

## Can Local LLMs Improve Quality? The Literature Says Yes.

### The published evidence

> Again: third-party figures for the general techniques, not domestique
> measurements. Whether domestique realises any of this is an open question that
> only the eval harness can answer.

| Approach | Published F1 (third-party) |
|----------|----------|
| Presidio (regex + spaCy) | 85-92% |
| LLM-based NER (fine-tuned 1-3B) | 94-98% |
| LLM classifier (phi-3/llama3 3B) | 93-97% |

### What Local LLMs Catch That Regex/NER Cannot

1. **Paraphrased proprietary info**: "The thing we discussed in last week's board meeting about acquiring company X"
2. **Contextual PII**: "Tell the nurse I spoke with yesterday about my condition"
3. **Obfuscated secrets**: Base64-encoded credentials, secrets split across messages
4. **Business-sensitive context**: M&A strategy, unreleased financials discussed casually
5. **Intent detection**: "Summarize all the customer data in this database and format it for export"

---

## The Tradeoff: Quality vs. Latency

### Latency budget per strategy

Latency figures below are design *targets* for choosing an architecture, not
measured results. The quality-gain column that used to sit here has been
removed: it projected F1 improvements for domestique's own stack that nothing
in this repository measures.

| Strategy | Latency Added (target) | When to Use |
|----------|--------------|-------------|
| Regex only | ~0.1 ms | Always (first pass) |
| + Presidio NER | ~5-10 ms | Always (parallel with regex) |
| + Embeddings (MiniLM) | ~5-15 ms (GPU) | When topics configured |
| + Local LLM (1B) | ~10-50 ms (GPU) | **Second-pass only** |
| + Local LLM (3B) | ~20-100 ms (GPU) | **Second-pass only** |
| + Local LLM (3B, CPU) | ~100-300 ms | Dev/test environments |

### Recommended Architecture: Tiered Detection

```
Request arrives
     │
     ▼
┌─────────────────────────────┐
│ TIER 1: Fast Path (< 1 ms)  │  ← Regex secrets, pattern matching
│ Runs on EVERY request        │     Known credential patterns
└──────────────┬──────────────┘
               │ Clean? → Forward immediately (zero added latency)
               │ Suspicious? ↓
┌──────────────▼──────────────┐
│ TIER 2: NLP Pass (< 15 ms)  │  ← Presidio NER + embeddings
│ Runs on flagged OR all reqs  │     Catches contextual PII + topics
└──────────────┬──────────────┘
               │ Ambiguous (0.4 < confidence < 0.8)? ↓
┌──────────────▼──────────────┐
│ TIER 3: LLM Pass (< 100 ms) │  ← Local 1-3B model classification
│ Runs ONLY on ambiguous cases │     Catches paraphrased/obfuscated content
└──────────────┬──────────────┘
               │
               ▼
         Final Decision
```

### The assumption this architecture rests on

The tiering only pays off if the overwhelming majority of traffic clears Tier 1.
The traffic mix below is the **design assumption**, not a measurement — no
traffic study in this repository establishes it, and it is worth testing before
relying on it.

- Most requests clean → Tier 1 only → sub-millisecond overhead
- A small fraction have regex hits → decided immediately
- A smaller fraction need NLP → Tier 2
- A rare remainder is ambiguous → Tier 3, the expensive path

Report latency as a distribution rather than a single number: p50 is dominated
by Tier 1, while p99 is whatever the classifier costs on the tail.

---

## Benchmarking Plan

### What exists today

```bash
# detection-quality eval + PR scorecard (the gate CI enforces per PR)
python -m benchmarks.eval run \
  --corpus benchmarks/eval/data/corpus.jsonl --out /tmp/results.json

# attachment scanning against its own labeled corpus (needs OCR installed --
# see benchmarks/file_scanning/RESULTS.md)
python -m benchmarks.file_scanning.run_benchmark

python benchmarks/redaction_bench.py   # redaction-engine latency (M6-M9)
```

`benchmarks.eval` is the prompt-detection gate CI enforces per PR;
`benchmarks.file_scanning` covers attachments. Those two are what measure
domestique's own detection quality.

### What does not exist yet

Everything below is **planned, not implemented**. This section previously listed
these as runnable commands (`bench/eval_secrets.py`, `bench/eval_pii.py`,
`bench/tier_sweep.py`, `tests/bench/`, `bench/load_test.js`); none of those
paths were ever in the repository.

- Scoring against the external datasets listed at the top of this document
- Per-tier sweeps, so each detection preset can be scored separately
- End-to-end load profiling

The corpus is also far too small to support strong claims. Growing it —
weighted toward benign-but-trigger-dense text, where guardrails are known to
collapse — is the prerequisite for publishing any detection number at all.

---

## Key Takeaways

1. **The literature suggests local LLMs improve detection quality.** Whether
   they improve *ours* is unmeasured; treat it as a hypothesis to test, not a
   result to cite.
2. **The latency cost looks affordable** — tens of milliseconds on GPU, and only
   on the cases the cheaper tiers could not settle.
3. **Tiering is a cost strategy, not a quality strategy.** It makes the
   expensive detector affordable; it does not make it more accurate.
4. **Latency has headroom.** LLM API round-trips run hundreds to thousands of
   milliseconds, so a tail-path classifier is unlikely to be what a user
   notices.
5. **Precision is the number that matters.** Recall is the easy metric every
   competitor claims. Precision on benign, trigger-word-dense developer traffic
   is the defensible one — and the one to publish, once the corpus can support
   it.

> Nothing in this document is a measurement of domestique. The reproducible
> figures come from the harnesses in `benchmarks/` — `benchmarks.eval` for
> prompt detection and `benchmarks.file_scanning` for attachments.
