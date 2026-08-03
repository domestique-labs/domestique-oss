# Prompt Engineering Competition - Hints & Tips

## The Challenge
Write a **classifier** system prompt that maximizes accuracy on the 70-sample
workshop dataset while keeping latency low and prompt length short. Your prompt
must return one label per sample as a single JSON object:
`{"c":"<CATEGORY>","v":<0.0-1.0>}`.

Dataset: `workshop/prompt_competition/dataset.json` (70 samples)

> **This is a workshop exercise, not a measurement of the shipped product.**
> Domestique's production prompt
> (`domestique.detectors.local_llm.default_system_prompt`) is a span
> *extractor*: it returns a JSON array of `{"t","c","v"}` objects naming
> extracted substrings and canonical taxonomy categories (`us_ssn`, `person`).
> It does not emit these six labels and cannot be scored by this runner — point
> `--prompt` at it and every sample comes back `PARSE_ERROR`. The six-label
> vocabulary below belongs to `dataset.json`; it appears nowhere in
> `domestique/`.

## Scoring
| Metric | Points |
|--------|--------|
| Correct sensitive classification | +2 per sample |
| Correct NONE classification | +1 per sample |
| Wrong category (sensitive -> different sensitive) | -1 |
| False positive (NONE flagged as sensitive) | -0.5 |
| False negative (sensitive classified as NONE) | -2 |
| Unparseable response on a sensitive sample | -2 (counts as a miss) |
| Avg latency < 200ms | +5 bonus |
| Avg latency < 300ms | +3 bonus |
| Prompt < 300 words | +5 bonus |
| Prompt < 500 words | +3 bonus |

**Max possible: 117 points** (37 sensitive x2 + 33 NONE x1 + 5 latency + 5 prompt).
The runner derives this from whichever samples you actually ran, so `--limit`
and `--difficulty` shrink it accordingly.

---

## Hint Level 1: Structure (Easy)

- **Be explicit about output format** - the model must return valid JSON
- **Use compact JSON** - `{"c":"CAT","v":0.9}` is faster than `{"category":"...","confidence":...,"reason":"..."}`
- **Add `stop=["}"]`** in Ollama options - halts generation right after JSON closes
- **List all categories clearly** - ambiguity causes wrong classifications  
- **Use "exactly one" phrasing** - prevents multi-category responses

```
JSON only, no markdown: {"c":"CATEGORY","v":confidence}
```

---

## 💡 Hint Level 2: Category Definitions (Medium)

The default prompt lists categories but doesn't define boundaries well.
Consider:

- **What makes PROPRIETARY_CODE vs NONE?** → Is open-source code NONE? Yes!
  Key signal: internal architecture, production infra, patents, trade secrets
  
- **INTERNAL_COMMS vs BUSINESS_STRATEGY** → Both can appear in emails.
  Key signal: INTERNAL_COMMS = process/people info. BUSINESS_STRATEGY = financial/market decisions.

- **CREDENTIALS vs everything else** → Not just `sk-xxx` patterns!
  Key signal: anything that grants access — encoded, split, rotated, or obfuscated

- **CUSTOMER_DATA specifics** → PII, PHI (medical), financial records, support tickets
  Key signal: data ABOUT identifiable individuals (customers, patients, users)

---

## Hint Level 3: Edge Cases (Hard)

The dataset includes adversarial samples designed to cause false positives:

1. **Public code vs proprietary code** - quicksort = NONE, internal fraud detection model = PROPRIETARY
   -> Key: "Does this reveal INTERNAL implementation that provides competitive advantage?"

2. **Discussing credentials vs leaking them** - "How does bcrypt work?" = NONE, "password is Hunter2" = CREDENTIALS
   -> Key: Is REAL sensitive data present, or is the user discussing the CONCEPT?

3. **Test/dummy data** - "Generate fake users with faker.ssn()" = NONE
   -> Key: Explicitly fake/test data should not be flagged

4. **Public financial info** - "Apple's revenue was $78B per 10-K" = NONE, "Our Q4 revenue was $45M" = BUSINESS_STRATEGY
   -> Key: Public vs unreleased

5. **Encoded secrets** - Base64-encoded API keys, split credentials
   -> Instruct: "detect encoded/obfuscated forms of secrets"

6. **Name + location** - "My name is John and I live in New York" = CUSTOMER_DATA
   -> Key: PII is person name COMBINED with contact/location/medical details

**Winning insight: Put NONE rules FIRST.** Small models follow ordered rules -
checking "is this safe?" before "is this dangerous?" cuts false positives. (The
before/after percentages that used to sit here came from the same unreproducible
ablation flagged at the bottom of this file, so they are gone; the effect is
cheap to confirm for yourself — reorder your own rules and re-run the scorer.)

---

## Hint Level 4: Advanced Techniques (Expert)

### NONE-first decision rules (highest impact technique)
Put safe-content rules before sensitive-content rules, and tell the model to
apply the first match:
```
Decision rules (apply first match):
1. Public/open-source code, generic algorithms -> NONE
2. Placeholder credentials (sk_live_XXXX, dummy, test) -> NONE
3. Educational/documentation content -> NONE
4. SQL/code with REAL company data -> PROPRIETARY_CODE
5. Contains real email/phone/SSN -> CUSTOMER_DATA
...
```

### Inference speed tricks
- `top_k=1, top_p=0.1` - greedy decoding, no sampling overhead
- `think=False` - disable chain-of-thought (Qwen3 uses tokens on reasoning)
- `num_ctx=8192` - smaller context window = less VRAM
- `stop=["}"]` - stop generating the moment JSON closes (~100ms savings)

---

## Hint Level 5: Prompt Architecture (Master)

A structure worth starting from:

```
[Role: "You are an enterprise DLP scanner"]
[Task: "Detect REAL sensitive data being leaked"]
[Categories: precise, with NONE explicitly listing safe content types]
[Decision rules: NONE-first ordering, "apply first match"]
[Output format: compact JSON]
```

### Key insight: NONE-first ordering beats everything else
Listing the safe-content rules first, before the sensitive-content rules,
substantially raised accuracy and cut the false-positive rate — same model,
same categories, just reordered rules. Worth trying first.

(The specific before/after percentages that used to appear here came from an
ablation whose prompt revisions are not in this repository, so the comparison
could not be re-run and the figures have been removed. The effect itself is
cheap to confirm: reorder the rules in your own prompt and re-run the scorer.)

### Key insight: Specificity beats length
A 150-word prompt with precise decision rules outperforms a 400-word prompt
with vague descriptions. The model knows what code looks like - you just
need to tell it WHICH code matters and WHICH is safe.

---

## Competition Strategy

1. **Start with the default prompt** - run the baseline over all 70 samples
2. **Analyze failure patterns** - which categories does it confuse? Check FP vs FN
3. **Put NONE rules first** - this is the single highest-impact change
4. **Add targeted fixes** - address specific failure modes you observe
5. **Trim ruthlessly** - every token costs latency
6. **Measure precision AND recall** - accuracy alone hides problems, and check
   the Unparseable count: a prompt that stopped returning JSON is not a prompt
   that got better

---

## Benchmarks to Beat

Run the built-in baseline yourself, then beat what *you* measured:

```bash
uv run python workshop/prompt_competition/run_competition.py
```

With no `--prompt`, this scores the **naive baseline classifier prompt defined
inside the runner itself** (not the production detector — see the note at the
top) against `dataset.json`, and reports accuracy, precision, recall, F1 and
average latency. It needs Ollama running; the default model is `qwen3:1.7b`.

One measured data point, so you have somewhere to start from:

| | baseline prompt, `qwen3:1.7b`, 70/70 samples |
|---|---|
| Score | 40.5 / 117 |
| Accuracy | 67.1% (47/70) |
| Precision / Recall / F1 | 81.5% / 59.5% / 68.8% |
| False positives / negatives | 5 / 15 |
| Unparseable | 0 |
| Avg latency | 184 ms |

That is a single run on one machine (Apple Silicon, local Ollama), taken with
the command above. Re-run it before comparing anything to it: scores move with
the model, and latency is entirely hardware-dependent.

Caveats on numbers you may see quoted elsewhere in this file's history:

- **Any ~90% figure attributed to the production prompt is not measurable with
  this script.** The production prompt is an extractor; feeding it to this
  runner yields `PARSE_ERROR` on every sample. Verified: 0.0% accuracy, 6/6
  unparseable.
- Until this pass, the scorer counted `PARSE_ERROR` as a detection, because the
  binary metrics tested `predicted != "NONE"`. The extractor-prompt run above
  therefore used to print **F1 90.9% alongside 0.0% accuracy**. If you have an
  old score sheet with a high F1 and a low accuracy, that is what it was.
- The runner only ever loads `dataset.json`. `dataset_combined.json` (262
  samples) ships alongside it but there is no `--dataset` flag, so any score
  attributed to the combined set cannot currently be reproduced with this
  script.
- The V0-vs-V6 rule-ordering ablation is not reproducible either: those prompt
  revisions are not in the repository, only the conclusion drawn from them.

---

## Running the Competition

Prefix with `uv run` as shown, or drop it if the project venv is already
activated.

```bash
# Run with default prompt (baseline)
uv run python workshop/prompt_competition/run_competition.py

# Run with your custom prompt
uv run python workshop/prompt_competition/run_competition.py --prompt my_prompt.txt

# Quick test (first 10 samples)
uv run python workshop/prompt_competition/run_competition.py --limit 10

# Test only hard samples
uv run python workshop/prompt_competition/run_competition.py --difficulty hard

# Use a different model
uv run python workshop/prompt_competition/run_competition.py --model gemma4:e2b
```
