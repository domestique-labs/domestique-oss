# Prompt Engineering Competition - Hints & Tips

## The Challenge
Customize the LLM classifier's system prompt to maximize accuracy on the
70-sample workshop dataset while keeping latency low and prompt length short.

Dataset: `workshop/prompt_competition/dataset.json` (70 samples)

## Scoring
| Metric | Points |
|--------|--------|
| Correct sensitive classification | +2 per sample |
| Correct NONE classification | +1 per sample |
| Wrong category (sensitive -> different sensitive) | -1 |
| False positive (NONE flagged as sensitive) | -0.5 |
| False negative (sensitive classified as NONE) | -2 |
| Avg latency < 200ms | +5 bonus |
| Avg latency < 300ms | +3 bonus |
| Prompt < 300 words | +5 bonus |
| Prompt < 500 words | +3 bonus |

**Max possible: ~113 points**

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
checking "is this safe?" before "is this dangerous?" dramatically reduces
false positives (from 21% FP to 3% FP in our benchmarks).

---

## Hint Level 4: Advanced Techniques (Expert)

### NONE-first decision rules (highest impact technique)
The current production prompt achieves 93% accuracy by putting safe-content
rules before sensitive-content rules:
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

The production prompt (93% accuracy, 97% precision on 262 samples) follows this structure:

```
[Role: "You are an enterprise DLP scanner"]
[Task: "Detect REAL sensitive data being leaked"]
[Categories: precise, with NONE explicitly listing safe content types]
[Decision rules: NONE-first ordering, "apply first match"]
[Output format: compact JSON]
```

### Key insight: NONE-first ordering beats everything else
Our ablation study showed:
- Prompt V0 (sensitive-first rules): 73% accuracy, 21% FP rate
- Prompt V6 (NONE-first rules): 86% accuracy, 3% FP rate
Same model, same categories, just reordered rules.

### Key insight: Specificity beats length
A 150-word prompt with precise decision rules outperforms a 400-word prompt
with vague descriptions. The model knows what code looks like - you just
need to tell it WHICH code matters and WHICH is safe.

---

## Competition Strategy

1. **Start with the default prompt** - run baseline on the Tiny Benchmark (70 samples)
2. **Analyze failure patterns** - which categories does it confuse? Check FP vs FN
3. **Put NONE rules first** - this is the single highest-impact change
4. **Add targeted fixes** - address specific failure modes you observe
5. **Test on Combined dataset** (262 samples) - that's where scores differentiate
6. **Trim ruthlessly** - every token costs latency
7. **Measure precision AND recall** - accuracy alone hides problems

---

## Benchmarks to Beat

Current production prompt on Qwen3 1.7B (70-sample dataset):
- **Accuracy**: 90%
- **Precision**: 92%
- **Recall**: 89%
- **F1**: 90%
- **Latency**: ~164ms average

---

## Running the Competition

```bash
# Run with default prompt (baseline)
python workshop/prompt_competition/run_competition.py

# Run with your custom prompt
python workshop/prompt_competition/run_competition.py --prompt my_prompt.txt

# Quick test (first 10 samples)
python workshop/prompt_competition/run_competition.py --limit 10

# Test only hard samples
python workshop/prompt_competition/run_competition.py --difficulty hard

# Use a different model
python workshop/prompt_competition/run_competition.py --model gemma4:e2b
```
