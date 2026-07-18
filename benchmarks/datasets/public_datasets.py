"""LLM Firewall — Public benchmark dataset loaders.

Loads samples from real, published datasets for rigorous evaluation:

1. ai4privacy/pii-masking-300k  — 300K labeled PII samples (HuggingFace)
2. ai4privacy/pii-masking-400k  — 400K multilingual PII samples (HuggingFace)
3. Custom secrets corpus         — Real-world secret patterns from Basak et al.
4. Business-sensitive corpus     — Enterprise content classification

Each loader returns a list of BenchCase objects compatible with evaluate.py.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from typing import Iterator

from benchmarks.datasets.dataset import BenchCase


# ═══════════════════════════════════════════════════════════════════════════════
# PII label mapping — maps dataset labels to our detection categories.
# ═══════════════════════════════════════════════════════════════════════════════

# Labels that constitute high-sensitivity PII (must be caught)
HIGH_SENSITIVITY_PII = {
    "EMAIL", "SOCIALNUMBER", "IDCARD", "CREDITCARDNUMBER",
    "PASS", "DATEOFBIRTH", "TELEPHONENUM",
}

# Labels that are moderate sensitivity (contextual PII)
MODERATE_SENSITIVITY_PII = {
    "USERNAME", "LASTNAME1", "LASTNAME2", "STREET",
    "BUILDING", "BUILDINGNUM", "POSTCODE", "ZIPCODE",
}

# Labels that are low sensitivity (often public information)
LOW_SENSITIVITY_PII = {
    "CITY", "STATE", "COUNTRY", "DATE", "TIME",
}


def _classify_pii_difficulty(labels: set[str]) -> str:
    """Classify difficulty based on which PII types are present."""
    if labels & HIGH_SENSITIVITY_PII:
        return "easy"  # High-sensitivity PII should be easy to catch
    elif labels & MODERATE_SENSITIVITY_PII:
        return "medium"
    else:
        return "hard"


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset 1: ai4privacy/pii-masking-300k
# ═══════════════════════════════════════════════════════════════════════════════

def load_ai4privacy_300k(n_samples: int = 200, seed: int = 42) -> list[BenchCase]:
    """Load samples from ai4privacy/pii-masking-300k.

    Returns a balanced mix of PII-bearing and clean samples.
    Uses streaming to avoid downloading the full 300K dataset.
    """
    from datasets import load_dataset

    ds = load_dataset("ai4privacy/pii-masking-300k", split="train", streaming=True)

    # Collect samples with diverse PII types
    cases: list[BenchCase] = []
    seen_labels: dict[str, int] = {}
    n_positive = int(n_samples * 0.7)  # 70% positive, 30% negative
    n_negative = n_samples - n_positive

    for i, sample in enumerate(itertools.islice(ds, n_samples * 3)):
        if len(cases) >= n_positive:
            break

        text = sample["source_text"]
        masks = sample.get("privacy_mask", [])

        if not masks or len(text) < 50:
            continue

        # Get unique PII labels in this sample
        pii_labels = {m["label"] for m in masks}
        difficulty = _classify_pii_difficulty(pii_labels)

        # Map to our detection categories
        detection_labels = []
        if pii_labels & (HIGH_SENSITIVITY_PII | MODERATE_SENSITIVITY_PII):
            detection_labels.append("pii")

        cases.append(BenchCase(
            id=f"ai4p-300k-{sample.get('id', i)}",
            text=text[:1500],  # Truncate very long texts
            labels=detection_labels,
            difficulty=difficulty,
            dataset="ai4privacy-300k",
        ))

    # Generate negative cases from the masked (clean) versions
    ds2 = load_dataset("ai4privacy/pii-masking-300k", split="train", streaming=True)
    neg_count = 0
    for sample in itertools.islice(ds2, n_samples * 2):
        if neg_count >= n_negative:
            break
        # target_text has PII replaced with masks — should NOT trigger
        clean_text = sample.get("target_text", "")
        if len(clean_text) > 100 and "[" not in clean_text[:50]:
            cases.append(BenchCase(
                id=f"ai4p-300k-neg-{neg_count}",
                text=clean_text[:1500],
                labels=[],  # Clean — should not be flagged
                difficulty="easy",
                dataset="ai4privacy-300k",
            ))
            neg_count += 1

    return cases


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset 2: ai4privacy/pii-masking-400k (multilingual, different PII types)
# ═══════════════════════════════════════════════════════════════════════════════

def load_ai4privacy_400k(n_samples: int = 100, seed: int = 42) -> list[BenchCase]:
    """Load samples from ai4privacy/pii-masking-400k.

    Focuses on English samples with credit cards, phone numbers, DOB.
    """
    from datasets import load_dataset

    ds = load_dataset("ai4privacy/pii-masking-400k", split="train", streaming=True)

    cases: list[BenchCase] = []
    n_positive = int(n_samples * 0.7)

    for i, sample in enumerate(itertools.islice(ds, n_samples * 5)):
        if len(cases) >= n_positive:
            break

        # Filter to English
        if sample.get("language", "").lower() != "english":
            continue

        text = sample.get("source_text", "")
        masks = sample.get("privacy_mask", [])

        if not masks or len(text) < 50:
            continue

        pii_labels = {m["label"] for m in masks}
        difficulty = _classify_pii_difficulty(pii_labels)

        detection_labels = []
        if pii_labels & (HIGH_SENSITIVITY_PII | MODERATE_SENSITIVITY_PII):
            detection_labels.append("pii")

        cases.append(BenchCase(
            id=f"ai4p-400k-{sample.get('uid', i)}",
            text=text[:1500],
            labels=detection_labels,
            difficulty=difficulty,
            dataset="ai4privacy-400k",
        ))

    # Add negatives from masked text
    ds2 = load_dataset("ai4privacy/pii-masking-400k", split="train", streaming=True)
    n_negative = n_samples - len(cases)
    neg_count = 0
    for sample in itertools.islice(ds2, n_samples * 3):
        if neg_count >= n_negative:
            break
        clean_text = sample.get("masked_text", "")
        if clean_text and len(clean_text) > 80:
            cases.append(BenchCase(
                id=f"ai4p-400k-neg-{neg_count}",
                text=clean_text[:1500],
                labels=[],
                difficulty="easy",
                dataset="ai4privacy-400k",
            ))
            neg_count += 1

    return cases


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset 3: Secrets benchmark (expanded from Basak et al. ESEM 2023 patterns)
# Real credential formats that appear in code/config/chat.
# ═══════════════════════════════════════════════════════════════════════════════

def load_secrets_benchmark() -> list[BenchCase]:
    """Expanded secrets benchmark with real-world credential patterns.

    Covers: AWS, GitHub, OpenAI, Anthropic, GCP, Slack, Stripe,
    JWTs, database URIs, SSH keys, and obfuscated variants.
    """
    cases: list[BenchCase] = []

    # Easy: plaintext credentials (regex should catch these)
    easy_secrets = [
        ("AWS access key in config", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"),
        ("AWS secret key", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("GitHub PAT", "export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"),
        ("OpenAI key in code", 'openai.api_key = "sk-proj-ABCDefgh1234567890abcdefghijklmnopqrstuvwxyz1234567890AB"'),
        ("Anthropic key", 'ANTHROPIC_API_KEY=sk-ant-api03-ABCDefghIJKLmnopQRSTuvwxYZ0123456789abcdefghijklmnopqrstuv-ABCDE'),
        ("Slack token", "xoxb-123456789012-1234567890123-ABCDEfghIJKLmnopQRSTuvwx"),
        ("Stripe key", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"),
        ("JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("Connection string", "postgresql://admin:s3cr3t_pass@db.internal.corp:5432/production"),
        ("GCP service account", '{"type": "service_account", "private_key_id": "key123", "private_key": "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpA..."}'),
        ("SSH private key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...\n-----END OPENSSH PRIVATE KEY-----"),
        ("Password in URL", "https://admin:P@ssw0rd123!@api.internal.company.com/v2/deploy"),
        ("Azure connection", "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz==;"),
        ("Sendgrid API key", "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ01"),
        ("Twilio auth token", 'TWILIO_AUTH_TOKEN="a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"'),
    ]

    for title, text in easy_secrets:
        cases.append(BenchCase(
            id=f"secrets-easy-{len(cases)}",
            text=text,
            labels=["secret"],
            difficulty="easy",
            dataset="secrets",
        ))

    # Medium: secrets embedded in larger context
    medium_secrets = [
        (
            "Key in chat message",
            "Hey, can you check the deployment? The API key for the staging env is "
            "sk-proj-Abc123Def456Ghi789Jkl012Mno345Pqr678Stu901Vwx234Yz567890ABCDEF "
            "— let me know if it works."
        ),
        (
            "Credentials in meeting notes",
            "Meeting Notes - Sprint 47\n\nDB Migration:\n- New connection: "
            "mongodb+srv://appuser:M0ng0P@ss2024!@cluster0.abc123.mongodb.net/prod\n"
            "- Backfill starts Friday\n- Need to update terraform state"
        ),
        (
            "Key in error log",
            "2024-03-15 14:23:01 ERROR AuthService: Failed to authenticate with "
            "provider. Token: ghp_Xyz123Abc456Def789Ghi012Jkl345Mno678. Retrying..."
        ),
        (
            "Env file pasted in chat",
            "Here's my .env for reference:\nDATABASE_URL=postgres://root:admin123@localhost/myapp\n"
            "REDIS_URL=redis://:secretpass@cache.internal:6379\n"
            "OPENAI_API_KEY=sk-svcacct-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        ),
        (
            "AWS creds in terraform",
            'resource "aws_instance" "web" {\n  # TODO: move to vault\n  '
            'provisioner "remote-exec" {\n    environment = {\n      '
            'AWS_ACCESS_KEY_ID = "AKIAI44QH8DHBEXAMPLE"\n      '
            'AWS_SECRET_ACCESS_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"\n    }\n  }\n}'
        ),
    ]

    for title, text in medium_secrets:
        cases.append(BenchCase(
            id=f"secrets-med-{len(cases)}",
            text=text,
            labels=["secret"],
            difficulty="medium",
            dataset="secrets",
        ))

    # Hard: obfuscated, split, encoded secrets (need LLM to catch)
    hard_secrets = [
        (
            "Base64 encoded key",
            "Config backup: key=" + "c2stcHJvai1BYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=",
        ),
        (
            "Split across variables",
            'prefix = "sk-ant-api03"\nmiddle = "ABCDefghIJKLmnop"\nsuffix = "QRSTuvwxYZ012345"\n'
            "full_key = f'{prefix}-{middle}{suffix}'"
        ),
        (
            "ROT13 obfuscated",
            "# Credential (rot13): fx-cebw-NopQrsTuvWxyZabcDefGhiJklMnoPqrStUvWxYz0123456789"
        ),
        (
            "Hex encoded password",
            "# DB pass (hex): 50404073737730726421"  # P@@ssw0rd!
        ),
        (
            "Key in reversed string",
            "# For recovery: '21fedcba_tpg_pohtig=NEKOT_BUH'"  # reversed github token hint
        ),
        (
            "Partial key with hint",
            "The production API key starts with 'sk-proj-' and ends with 'X9f2kL'. "
            "Full key is in 1Password under 'Production OpenAI'."
        ),
        (
            "Key split across messages",
            "Part 1 of the deploy key: AKIA\nPart 2: IOSF\nPart 3: ODNN7EXAMPLE\n"
            "Combine them for the access key."
        ),
    ]

    for title, text in hard_secrets:
        cases.append(BenchCase(
            id=f"secrets-hard-{len(cases)}",
            text=text,
            labels=["secret"],
            difficulty="hard",
            dataset="secrets",
        ))

    # True negatives (should NOT be flagged)
    negatives = [
        "Can you help me write a Python function to sort a list?",
        "The meeting is scheduled for 3pm tomorrow in conference room B.",
        "I'm getting a 404 error when I try to access the /users endpoint.",
        "Let's discuss the new feature requirements for the Q2 sprint.",
        "The CI pipeline is taking too long — can we parallelize the test suite?",
        "Here's a sample API response: {\"status\": \"ok\", \"data\": [1, 2, 3]}",
        "What's the best way to implement pagination in a REST API?",
        "The load balancer is showing 99.9% uptime over the last 30 days.",
        "Can you review my pull request? It adds input validation to the form.",
        "We should upgrade to Python 3.12 for the performance improvements.",
    ]

    for i, text in enumerate(negatives):
        cases.append(BenchCase(
            id=f"secrets-neg-{i}",
            text=text,
            labels=[],
            difficulty="easy",
            dataset="secrets",
        ))

    return cases


# ═══════════════════════════════════════════════════════════════════════════════
# Dataset 4: Business-sensitive content (enterprise DLP scenarios)
# ═══════════════════════════════════════════════════════════════════════════════

def load_business_sensitive_benchmark() -> list[BenchCase]:
    """Business-sensitive content that should be blocked from external LLMs.

    These are the hardest cases — no regex can catch them. Requires
    semantic understanding or LLM classification.
    """
    cases: list[BenchCase] = []

    sensitive_texts = [
        (
            "M&A discussion",
            "Following up on our call with Goldman — the Acme Corp acquisition "
            "is priced at $4.2B with a 30% premium over market. Board approval "
            "expected by March 15. Keep this strictly confidential until 8-K filing."
        ),
        (
            "Unreleased financials",
            "Q3 preview (INTERNAL ONLY): Revenue $847M (+12% YoY), but EBITDA margin "
            "compressed to 18.3% due to the datacenter expansion. Guidance cut likely "
            "when we report on Nov 4. Do NOT discuss externally."
        ),
        (
            "Security vulnerability",
            "CRITICAL - CVE pending: Our auth service has a BOLA vulnerability in "
            "/api/v2/users/{id}/settings. Any authenticated user can access other "
            "users' settings by changing the ID. Affects all customers on v2.3+. "
            "Patch in progress, ETA 48 hours. DO NOT DISCLOSE."
        ),
        (
            "Competitive intelligence",
            "Intel from ex-Competitor employee: They're planning to undercut our "
            "enterprise tier by 40% starting Q1. Their new pricing: $15/seat vs our "
            "$25/seat. We need to prepare a retention strategy before their announcement."
        ),
        (
            "Employee HR data",
            "Compensation review results (VP+ level):\n"
            "- Sarah Chen (SVP Eng): $485K base + $1.2M RSU\n"
            "- Marcus Rivera (VP Product): $380K + $800K RSU\n"
            "- Jennifer Walsh (VP Sales): $360K + $950K OTE\n"
            "Board approved 15% equity refresh for retention."
        ),
        (
            "Customer contract details",
            "Enterprise deal update: Acme Industries signed 3-year commit at "
            "$2.4M ARR with custom SLA (99.99% uptime, 15-min response). "
            "They get dedicated infrastructure + custom model fine-tuning. "
            "NDA prevents us from using their data for training."
        ),
        (
            "Board meeting minutes",
            "Board Minutes - Emergency Session (CONFIDENTIAL)\n"
            "Discussed potential SEC investigation re: revenue recognition on "
            "multi-year deals. Outside counsel advises restating Q2 numbers. "
            "CFO to prepare restatement scenarios by Friday."
        ),
        (
            "Product roadmap leak",
            "2025 roadmap (NOT for external sharing):\n"
            "- Q1: Launch AI assistant (internal codename 'Phoenix')\n"
            "- Q2: Acquire DataFlow Inc ($180M budget approved)\n"
            "- Q3: Enter healthcare vertical (HIPAA cert in progress)\n"
            "- Q4: IPO preparation begins"
        ),
        (
            "Internal incident report",
            "Incident Report IR-2024-0892 (INTERNAL ONLY)\n"
            "Customer data breach: 12,847 records exposed via misconfigured S3 bucket. "
            "Affected: names, emails, purchase history. No financial data. "
            "Legal team drafting notification letters. Do NOT discuss on any external channel."
        ),
        (
            "Patent application draft",
            "Patent Draft (PRIVILEGED & CONFIDENTIAL)\n"
            "Title: 'Method for Distributed Consensus Using Entropy-Weighted DAG'\n"
            "Claims: 1. A system comprising... [novel approach to solve Byzantine fault "
            "tolerance using probabilistic finality with O(log n) message complexity]\n"
            "Filing deadline: March 1. Prior art search complete."
        ),
    ]

    for i, (title, text) in enumerate(sensitive_texts):
        cases.append(BenchCase(
            id=f"business-{i}",
            text=text,
            labels=["business_sensitive"],
            difficulty="hard",
            dataset="business-sensitive",
        ))

    # Negatives — business-like but NOT sensitive
    negatives = [
        "Our quarterly all-hands is next Thursday at 2pm. Please RSVP.",
        "The new office kitchen policy: please clean up after yourself.",
        "Reminder: mandatory security training due by end of month.",
        "We're hiring for 3 senior engineer positions. Please share the JD.",
        "The team offsite is scheduled for June 15-17 in Austin.",
        "Please review the updated code style guide before your next PR.",
        "The wifi password for the guest network has been updated.",
        "Lunch and learn next week: Introduction to Kubernetes.",
    ]

    for i, text in enumerate(negatives):
        cases.append(BenchCase(
            id=f"business-neg-{i}",
            text=text,
            labels=[],
            difficulty="easy",
            dataset="business-sensitive",
        ))

    return cases


# ═══════════════════════════════════════════════════════════════════════════════
# Master loader
# ═══════════════════════════════════════════════════════════════════════════════

def load_all_public_datasets(
    pii_300k_samples: int = 200,
    pii_400k_samples: int = 100,
) -> dict[str, list[BenchCase]]:
    """Load all available benchmark datasets.

    Returns a dict mapping dataset name → list of BenchCase.
    """
    datasets: dict[str, list[BenchCase]] = {}

    # Always available (no external deps)
    datasets["secrets"] = load_secrets_benchmark()
    datasets["business-sensitive"] = load_business_sensitive_benchmark()

    # HuggingFace datasets (require internet + datasets library)
    try:
        datasets["ai4privacy-300k"] = load_ai4privacy_300k(n_samples=pii_300k_samples)
    except Exception as e:
        print(f"  ⚠ Could not load ai4privacy-300k: {e}")

    try:
        datasets["ai4privacy-400k"] = load_ai4privacy_400k(n_samples=pii_400k_samples)
    except Exception as e:
        print(f"  ⚠ Could not load ai4privacy-400k: {e}")

    return datasets
