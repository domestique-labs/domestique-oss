#!/usr/bin/env python3
"""Domestique Prompt Engineering Competition Runner.

Evaluates a custom classifier prompt against the labeled dataset.
Scores based on classification accuracy, latency, and prompt efficiency.

Usage:
    python run_competition.py                    # Uses default prompt
    python run_competition.py --prompt my_prompt.txt  # Uses custom prompt file
    python run_competition.py --interactive      # Enter prompt interactively
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def load_dataset() -> dict:
    """Load the competition dataset."""
    dataset_path = Path(__file__).parent / "dataset.json"
    with open(dataset_path) as f:
        return json.load(f)


def classify_with_prompt(text: str, system_prompt: str, ollama_url: str, model: str) -> dict:
    """Run classification using Ollama with the given prompt."""
    import urllib.request

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text},
        ],
        "stream": False,
        "think": False,
        "options": {"temperature": 0.0, "num_predict": 40, "top_k": 1, "top_p": 0.1, "num_ctx": 8192},
        "stop": ["}"],
    }).encode()

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(
        f"{ollama_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    start = time.perf_counter()
    try:
        resp = opener.open(req, timeout=30)
        data = json.loads(resp.read())
        latency = (time.perf_counter() - start) * 1000

        content = data.get("message", {}).get("content", "").strip()
        # Handle stop="}" truncation
        if not content.endswith("}"):
            content += "}"
        # Handle markdown code blocks
        if "```" in content:
            content = content.replace("```json", "").replace("```", "").strip()
            if not content.endswith("}"):
                content += "}"
        try:
            result = json.loads(content)
            # Support both compact {"c":"CAT","v":0.9} and full {"category":"CAT","confidence":0.9}
            category = result.get("c", result.get("category", "UNKNOWN"))
            confidence = float(result.get("v", result.get("confidence", 0.0)))
            return {
                "category": category,
                "confidence": confidence,
                "latency_ms": round(latency, 1),
                "raw": content,
            }
        except (json.JSONDecodeError, IndexError):
            # Try to extract category from free-text response
            categories = ["PROPRIETARY_CODE", "BUSINESS_STRATEGY", "CUSTOMER_DATA",
                         "INTERNAL_COMMS", "CREDENTIALS", "NONE"]
            for cat in categories:
                if cat in content.upper():
                    return {"category": cat, "confidence": 0.5,
                            "latency_ms": round(latency, 1), "raw": content}
            return {"category": "PARSE_ERROR", "confidence": 0.0,
                    "latency_ms": round(latency, 1), "raw": content}
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return {"category": "ERROR", "confidence": 0.0,
                "latency_ms": round(latency, 1), "raw": str(e)}


def score_results(results: list[dict], metadata: dict) -> dict:
    """Calculate competition score from results."""
    total_score = 0
    correct = 0
    wrong = 0
    false_positives = 0
    false_negatives = 0
    latencies = []

    for r in results:
        predicted = r["predicted"]
        expected = r["expected"]
        latencies.append(r["latency_ms"])

        if predicted == expected:
            correct += 1
            total_score += 2 if expected != "NONE" else 1
        elif predicted == "NONE" and expected != "NONE":
            # False negative (missed sensitive content)
            false_negatives += 1
            total_score -= 2
        elif predicted != "NONE" and expected == "NONE":
            # False positive (flagged clean content)
            false_positives += 1
            total_score -= 0.5
        else:
            # Wrong category
            wrong += 1
            total_score -= 1

    avg_latency = sum(latencies) / len(latencies) if latencies else 999
    if avg_latency < 200:
        total_score += 5
    elif avg_latency < 300:
        total_score += 3

    # Precision / Recall (binary: sensitive vs NONE)
    tp = sum(1 for r in results if r["expected"] != "NONE" and r["predicted"] != "NONE")
    fp = sum(1 for r in results if r["expected"] == "NONE" and r["predicted"] != "NONE")
    fn = sum(1 for r in results if r["expected"] != "NONE" and r["predicted"] == "NONE")
    tn = sum(1 for r in results if r["expected"] == "NONE" and r["predicted"] == "NONE")
    precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
    recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
    f1 = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) > 0 else 0

    return {
        "total_score": round(total_score, 1),
        "accuracy": round(correct / len(results) * 100, 1),
        "correct": correct,
        "wrong_category": wrong,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "avg_latency_ms": round(avg_latency, 1),
        "latency_bonus": 5 if avg_latency < 200 else (3 if avg_latency < 300 else 0),
        "total_samples": len(results),
    }


def print_results_table(results: list[dict]) -> None:
    """Print a colorful results table."""
    print(f"\n{'─' * 90}")
    print(f"{'#':>3} {'Expected':<18} {'Predicted':<18} {'Conf':>5} {'ms':>6} {'Result':<8} {'Difficulty'}")
    print(f"{'─' * 90}")

    for r in results:
        match = r["predicted"] == r["expected"]
        symbol = "✅" if match else "❌"
        color = "\033[92m" if match else "\033[91m"
        reset = "\033[0m"
        print(f"{r['id']:>3} {r['expected']:<18} {color}{r['predicted']:<18}{reset} "
              f"{r['confidence']:>4.1f} {r['latency_ms']:>5.0f}ms {symbol:<8} {r['difficulty']}")

    print(f"{'─' * 90}")


def main():
    parser = argparse.ArgumentParser(description="Domestique Prompt Engineering Competition")
    parser.add_argument("--prompt", type=str, help="Path to custom prompt file")
    parser.add_argument("--interactive", action="store_true", help="Enter prompt interactively")
    parser.add_argument("--model", default="qwen3:1.7b", help="Ollama model (default: qwen3:1.7b)")
    parser.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama URL")
    parser.add_argument("--limit", type=int, help="Limit to N samples (for quick testing)")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard"], help="Filter by difficulty")
    args = parser.parse_args()

    # Load prompt
    if args.interactive:
        print("Enter your custom system prompt (end with Ctrl+D or empty line):")
        lines = []
        try:
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
        except EOFError:
            pass
        system_prompt = "\n".join(lines)
    elif args.prompt:
        system_prompt = Path(args.prompt).read_text()
    else:
        # Naive baseline prompt (~60-70% accuracy). Participants should improve it.
        # The production prompt in domestique/detectors/local_llm.py scores ~90%.
        system_prompt = """\
You are a DLP classifier. Classify if text contains sensitive enterprise data.

Categories (pick one):
- PROPRIETARY_CODE: source code, algorithms, internal tooling
- BUSINESS_STRATEGY: M&A plans, financials, competitive intelligence
- CUSTOMER_DATA: PII - emails, phones, SSNs, addresses, medical records
- INTERNAL_COMMS: forwarded emails, Slack messages, meeting notes
- CREDENTIALS: passwords, API keys, tokens, connection strings
- NONE: safe content, public knowledge, generic questions

Respond with JSON: {"c":"<CATEGORY>","v":<0.0-1.0>}"""

    # Load dataset
    dataset = load_dataset()
    samples = dataset["samples"]

    if args.difficulty:
        samples = [s for s in samples if s["difficulty"] == args.difficulty]
    if args.limit:
        samples = samples[:args.limit]

    prompt_tokens = len(system_prompt.split())
    print(f"\n🏆 Domestique Prompt Engineering Competition")
    print(f"{'═' * 50}")
    print(f"Model: {args.model}")
    print(f"Prompt length: {prompt_tokens} words / {len(system_prompt)} chars")
    print(f"Samples: {len(samples)}")
    print(f"{'═' * 50}\n")

    # Prompt length bonus
    prompt_bonus = 0
    if prompt_tokens < 300:
        prompt_bonus = 5
    elif prompt_tokens < 500:
        prompt_bonus = 3

    # Run classification
    results = []
    for i, sample in enumerate(samples):
        sys.stdout.write(f"\r  Classifying {i+1}/{len(samples)}...")
        sys.stdout.flush()

        result = classify_with_prompt(sample["text"], system_prompt, args.ollama_url, args.model)
        results.append({
            "id": sample["id"],
            "expected": sample["expected"],
            "predicted": result["category"],
            "confidence": result.get("confidence", 0),
            "latency_ms": result["latency_ms"],
            "difficulty": sample["difficulty"],
            "reason": result.get("reason", ""),
        })

    print("\r" + " " * 40 + "\r", end="")

    # Display results
    print_results_table(results)

    # Score
    scores = score_results(results, dataset["metadata"])
    scores["prompt_length_bonus"] = prompt_bonus
    scores["total_score"] += prompt_bonus

    print(f"\n🏆 FINAL SCORE: {scores['total_score']}")
    print(f"{'─' * 50}")
    print(f"  Accuracy:          {scores['accuracy']}% ({scores['correct']}/{scores['total_samples']})")
    print(f"  Precision:         {scores['precision']}% (TP={scores['tp']}, FP={scores['fp']})")
    print(f"  Recall:            {scores['recall']}% (TP={scores['tp']}, FN={scores['fn']})")
    print(f"  F1 Score:          {scores['f1']}%")
    print(f"  Wrong category:    {scores['wrong_category']}")
    print(f"  False positives:   {scores['false_positives']} (flagged clean as sensitive)")
    print(f"  False negatives:   {scores['false_negatives']} (missed sensitive content)")
    print(f"  Avg latency:       {scores['avg_latency_ms']}ms (bonus: +{scores['latency_bonus']})")
    print(f"  Prompt efficiency: {prompt_tokens} words (bonus: +{prompt_bonus})")
    print(f"{'─' * 50}")
    print(f"  MAX POSSIBLE:      ~153 (37 sensitive×2 + 33 NONE×1 + latency 5 + prompt 5)")
    print()


if __name__ == "__main__":
    main()
