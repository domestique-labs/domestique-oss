"""Generate synthetic benchmark dataset for file/image PII & secrets detection.

Creates a labeled dataset of files containing:
- Screenshots/images with embedded PII (OCR required)
- PDF documents with secrets and credentials
- CSV/Excel files with PII columns
- Code snippets with API keys and tokens
- Clean (negative) samples for false positive measurement

Each sample has ground truth annotations:
    {
        "file": "sample_001.png",
        "type": "image",
        "contains_sensitive": true,
        "categories": ["email", "SSN", "phone"],
        "sensitive_values": ["jane@corp.com", "123-45-6789", "555-0100"],
        "description": "Screenshot of a form with PII fields"
    }

Usage:
    python -m benchmarks.file_scanning.generate_benchmark --output benchmarks/file_scanning/dataset
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import string
import sys
from io import BytesIO
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------------------
# Fake data generators (deterministic, no external dependency on Faker)
# ---------------------------------------------------------------------------

_RNG = random.Random(42)

_FIRST_NAMES = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer",
                "Michael", "Linda", "David", "Elizabeth", "Sarah", "Daniel"]
_LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia",
               "Miller", "Davis", "Rodriguez", "Martinez", "Wilson", "Taylor"]
_DOMAINS = ["acme.com", "corp.io", "bigbank.org", "healthco.net", "techfirm.dev"]
_CITIES = ["New York", "San Francisco", "Chicago", "Austin", "Seattle", "Boston"]
_STREETS = ["Main St", "Oak Ave", "Elm Dr", "Pine Rd", "Maple Blvd", "Cedar Ln"]


def _fake_name() -> str:
    return f"{_RNG.choice(_FIRST_NAMES)} {_RNG.choice(_LAST_NAMES)}"


def _fake_email() -> str:
    first = _RNG.choice(_FIRST_NAMES).lower()
    last = _RNG.choice(_LAST_NAMES).lower()
    return f"{first}.{last}@{_RNG.choice(_DOMAINS)}"


def _fake_ssn() -> str:
    return f"{_RNG.randint(100,999)}-{_RNG.randint(10,99)}-{_RNG.randint(1000,9999)}"


def _fake_phone() -> str:
    return f"({_RNG.randint(200,999)}) {_RNG.randint(100,999)}-{_RNG.randint(1000,9999)}"


def _fake_credit_card() -> str:
    prefix = _RNG.choice(["4", "5", "37"])
    remaining = 16 - len(prefix)
    digits = prefix + "".join(str(_RNG.randint(0, 9)) for _ in range(remaining))
    # Format with dashes
    return f"{digits[:4]}-{digits[4:8]}-{digits[8:12]}-{digits[12:]}"


def _fake_address() -> str:
    return f"{_RNG.randint(100,9999)} {_RNG.choice(_STREETS)}, {_RNG.choice(_CITIES)}"


def _fake_api_key() -> str:
    prefix = _RNG.choice(["sk-", "AKIA", "ghp_", "xoxb-", "Bearer ey"])
    chars = string.ascii_letters + string.digits
    return prefix + "".join(_RNG.choice(chars) for _ in range(32))


def _fake_password() -> str:
    return "P@ss" + "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(12))


def _fake_aws_secret() -> str:
    chars = string.ascii_letters + string.digits + "+/"
    return "".join(_RNG.choice(chars) for _ in range(40))


# ---------------------------------------------------------------------------
# Sample generators by type
# ---------------------------------------------------------------------------


def _generate_image_samples(output_dir: Path, start_idx: int) -> list[dict]:
    """Generate PNG images with embedded text containing PII."""
    samples = []
    idx = start_idx

    scenarios = [
        # (description, text_lines_fn, expected_categories)
        (
            "Form screenshot with personal info",
            lambda: [
                "Customer Information Form",
                "",
                f"Full Name: {(n := _fake_name())}",
                f"Email: {(e := _fake_email())}",
                f"Phone: {(p := _fake_phone())}",
                f"SSN: {(s := _fake_ssn())}",
                f"Address: {(a := _fake_address())}",
            ],
            lambda lines: {
                "categories": ["name", "email", "phone", "SSN", "address"],
                "sensitive_values": [
                    lines[2].split(": ", 1)[1],
                    lines[3].split(": ", 1)[1],
                    lines[4].split(": ", 1)[1],
                    lines[5].split(": ", 1)[1],
                    lines[6].split(": ", 1)[1],
                ],
            },
        ),
        (
            "Chat window with email and credit card",
            lambda: [
                "ChatGPT - conversation",
                "",
                "User: Can you help me verify my payment?",
                f"My card number is {(cc := _fake_credit_card())}",
                f"and my email is {(e := _fake_email())}",
                "",
                "Assistant: I cannot process payment info...",
            ],
            lambda lines: {
                "categories": ["credit_card", "email"],
                "sensitive_values": [
                    lines[3].split("is ", 1)[1],
                    lines[4].split("is ", 1)[1],
                ],
            },
        ),
        (
            "Terminal output with API keys",
            lambda: [
                "$ export OPENAI_API_KEY=" + (k := _fake_api_key()),
                f"$ export AWS_SECRET_ACCESS_KEY={(_s := _fake_aws_secret())}",
                "$ curl -H 'Authorization: Bearer sk-proj-abc123def456' ...",
                "",
                "Response: 200 OK",
            ],
            lambda lines: {
                "categories": ["api_key", "credential"],
                "sensitive_values": [
                    lines[0].split("=", 1)[1],
                    lines[1].split("=", 1)[1],
                ],
            },
        ),
        (
            "Spreadsheet screenshot with employee data",
            lambda: [
                "Employee ID | Name          | SSN          | Salary",
                "-" * 55,
                f"EMP-001     | {(n1 := _fake_name()):13s} | {(s1 := _fake_ssn())} | $95,000",
                f"EMP-002     | {(n2 := _fake_name()):13s} | {(s2 := _fake_ssn())} | $102,000",
                f"EMP-003     | {(n3 := _fake_name()):13s} | {(s3 := _fake_ssn())} | $87,500",
            ],
            lambda lines: {
                "categories": ["name", "SSN"],
                "sensitive_values": [s for line in lines[2:] for s in [
                    line.split("|")[1].strip(),
                    line.split("|")[2].strip(),
                ]],
            },
        ),
        (
            "Slack message with credentials",
            lambda: [
                "#engineering-ops",
                "",
                f"@devops-bot: Deploy credentials updated:",
                f"  DB_PASSWORD={(_p := _fake_password())}",
                f"  API_TOKEN={(_t := _fake_api_key())}",
                f"  Contact: {(e := _fake_email())}",
            ],
            lambda lines: {
                "categories": ["credential", "api_key", "email"],
                "sensitive_values": [
                    lines[3].split("=", 1)[1],
                    lines[4].split("=", 1)[1],
                    lines[5].split(": ", 1)[1],
                ],
            },
        ),
    ]

    # Generate multiple variations of each scenario
    for variation in range(3):
        for desc, lines_fn, extract_fn in scenarios:
            lines = lines_fn()
            meta = extract_fn(lines)

            # Render to image
            img = _render_text_image(lines, variation)
            filename = f"img_{idx:03d}.png"
            img.save(output_dir / filename)

            samples.append({
                "file": filename,
                "type": "image",
                "contains_sensitive": True,
                "categories": meta["categories"],
                "sensitive_values": meta["sensitive_values"],
                "description": desc,
            })
            idx += 1

    # Add clean (negative) images
    clean_texts = [
        ["Meeting Notes - Q3 Planning", "", "Attendees: Team Alpha",
         "Topics: roadmap, timelines, budget allocation",
         "Next steps: review by Friday"],
        ["System Status: All services operational", "",
         "Uptime: 99.97%", "Last deploy: 2024-03-15",
         "CPU: 42% | Memory: 68% | Disk: 55%"],
        ["Recipe: Chocolate Chip Cookies", "",
         "Ingredients: flour, sugar, butter, eggs",
         "Preheat oven to 375F", "Bake for 12 minutes"],
    ]
    for clean_lines in clean_texts:
        img = _render_text_image(clean_lines, _RNG.randint(0, 2))
        filename = f"img_{idx:03d}.png"
        img.save(output_dir / filename)
        samples.append({
            "file": filename,
            "type": "image",
            "contains_sensitive": False,
            "categories": [],
            "sensitive_values": [],
            "description": "Clean image without sensitive data",
        })
        idx += 1

    return samples


def _render_text_image(lines: list[str], style: int = 0) -> Image.Image:
    """Render text lines into a PNG image simulating a screen capture."""
    # Different visual styles to test OCR robustness
    configs = [
        {"bg": (255, 255, 255), "fg": (30, 30, 30), "size": (800, 400)},   # White bg
        {"bg": (40, 44, 52), "fg": (220, 220, 220), "size": (900, 450)},   # Dark mode
        {"bg": (245, 245, 220), "fg": (50, 50, 50), "size": (750, 380)},   # Beige
    ]
    cfg = configs[style % len(configs)]

    img = Image.new("RGB", cfg["size"], cfg["bg"])
    draw = ImageDraw.Draw(img)

    # Use default font (monospace-like rendering)
    try:
        font = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 16)
    except (OSError, IOError):
        font = ImageFont.load_default()

    y = 20
    for line in lines:
        draw.text((20, y), line, fill=cfg["fg"], font=font)
        y += 24

    return img


def _generate_pdf_samples(output_dir: Path, start_idx: int) -> list[dict]:
    """Generate PDF-like text files with secrets (simulated PDF content).

    Note: We generate plain text files with .pdf extension for simplicity
    in the benchmark. The scanner should handle both real PDFs and text extraction.
    For a production benchmark, use reportlab to generate real PDFs.
    """
    samples = []
    idx = start_idx

    # PDF with employee records
    content = f"""CONFIDENTIAL - HR Department
Employee Records Export - Q1 2024

Name: {(n1 := _fake_name())}
SSN: {(s1 := _fake_ssn())}
Email: {(e1 := _fake_email())}
Salary: $125,000
Department: Engineering

Name: {(n2 := _fake_name())}
SSN: {(s2 := _fake_ssn())}
Email: {(e2 := _fake_email())}
Salary: $98,000
Department: Marketing

---
Generated by HRIS v4.2 | Internal Use Only
"""
    filename = f"doc_{idx:03d}.txt"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "document",
        "contains_sensitive": True,
        "categories": ["name", "SSN", "email"],
        "sensitive_values": [n1, s1, e1, n2, s2, e2],
        "description": "HR employee records with PII",
    })
    idx += 1

    # Config file with secrets
    content = f"""# Production Configuration - DO NOT COMMIT
[database]
host = prod-db.internal.corp.io
port = 5432
username = admin
password = {(p1 := _fake_password())}

[api]
openai_key = {(k1 := _fake_api_key())}
stripe_secret = sk_live_{"".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(24))}

[aws]
access_key_id = AKIA{"".join(_RNG.choice(string.ascii_uppercase + string.digits) for _ in range(16))}
secret_access_key = {(aws := _fake_aws_secret())}
region = us-east-1
"""
    filename = f"doc_{idx:03d}.txt"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "document",
        "contains_sensitive": True,
        "categories": ["credential", "api_key"],
        "sensitive_values": [p1, k1, aws],
        "description": "Configuration file with API keys and passwords",
    })
    idx += 1

    # Legal document with PII
    content = f"""SETTLEMENT AGREEMENT

Between:
{(n1 := _fake_name())} (SSN: {(s1 := _fake_ssn())})
residing at {(a1 := _fake_address())}
Phone: {(ph := _fake_phone())}
Email: {(e1 := _fake_email())}

And:
BigCorp International LLC

The parties agree to the following terms...
Payment of $250,000 to be wired to account ending in 4521.
Credit card on file: {(cc := _fake_credit_card())}
"""
    filename = f"doc_{idx:03d}.txt"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "document",
        "contains_sensitive": True,
        "categories": ["name", "SSN", "address", "phone", "email", "credit_card"],
        "sensitive_values": [n1, s1, a1, ph, e1, cc],
        "description": "Legal settlement with full PII",
    })
    idx += 1

    # Clean documents
    clean_docs = [
        ("Technical specification for API v2", """
API Specification v2.0

Endpoints:
  GET /api/users - List all users
  POST /api/users - Create user
  DELETE /api/users/:id - Remove user

Rate limits: 100 req/min per client
Authentication: OAuth 2.0 bearer tokens
Response format: JSON with pagination
"""),
        ("Meeting minutes without PII", """
Engineering All-Hands - March 2024

Agenda:
1. Q1 retrospective
2. Infrastructure migration update
3. New hire onboarding process
4. Team social planning

Action items:
- Review deployment pipeline by next Friday
- Schedule cross-team sync for mobile launch
- Update documentation for new API endpoints
"""),
    ]
    for desc, text in clean_docs:
        filename = f"doc_{idx:03d}.txt"
        (output_dir / filename).write_text(text)
        samples.append({
            "file": filename,
            "type": "document",
            "contains_sensitive": False,
            "categories": [],
            "sensitive_values": [],
            "description": desc,
        })
        idx += 1

    return samples


def _generate_csv_samples(output_dir: Path, start_idx: int) -> list[dict]:
    """Generate CSV files with PII data."""
    samples = []
    idx = start_idx

    # Customer database export
    filename = f"data_{idx:03d}.csv"
    rows = [["id", "name", "email", "phone", "ssn", "address"]]
    sensitive_vals = []
    for i in range(10):
        name = _fake_name()
        email = _fake_email()
        phone = _fake_phone()
        ssn = _fake_ssn()
        addr = _fake_address()
        rows.append([str(i + 1), name, email, phone, ssn, addr])
        sensitive_vals.extend([email, ssn])

    with open(output_dir / filename, "w", newline="") as f:
        csv.writer(f).writerows(rows)

    samples.append({
        "file": filename,
        "type": "spreadsheet",
        "contains_sensitive": True,
        "categories": ["name", "email", "phone", "SSN", "address"],
        "sensitive_values": sensitive_vals[:6],  # Keep manageable
        "description": "Customer database export with full PII",
    })
    idx += 1

    # Financial data with credit cards
    filename = f"data_{idx:03d}.csv"
    rows = [["transaction_id", "customer", "card_number", "amount", "date"]]
    cc_vals = []
    for i in range(5):
        cc = _fake_credit_card()
        rows.append([f"TXN-{i+1:04d}", _fake_name(), cc,
                     f"${_RNG.randint(10,5000):.2f}", "2024-03-15"])
        cc_vals.append(cc)

    with open(output_dir / filename, "w", newline="") as f:
        csv.writer(f).writerows(rows)

    samples.append({
        "file": filename,
        "type": "spreadsheet",
        "contains_sensitive": True,
        "categories": ["name", "credit_card"],
        "sensitive_values": cc_vals[:3],
        "description": "Transaction log with credit card numbers",
    })
    idx += 1

    # Clean CSV
    filename = f"data_{idx:03d}.csv"
    rows = [["date", "metric", "value", "change"]]
    for i in range(7):
        rows.append([f"2024-03-{i+1:02d}", "page_views",
                     str(_RNG.randint(1000, 50000)), f"{_RNG.uniform(-5, 5):.1f}%"])
    with open(output_dir / filename, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    samples.append({
        "file": filename,
        "type": "spreadsheet",
        "contains_sensitive": False,
        "categories": [],
        "sensitive_values": [],
        "description": "Analytics metrics without PII",
    })
    idx += 1

    return samples


def _generate_code_samples(output_dir: Path, start_idx: int) -> list[dict]:
    """Generate code files with embedded secrets."""
    samples = []
    idx = start_idx

    # Python file with hardcoded credentials
    key = _fake_api_key()
    pwd = _fake_password()
    content = f'''"""Database connection module."""
import psycopg2

DB_HOST = "prod-postgres.internal.corp.io"
DB_USER = "app_service"
DB_PASSWORD = "{pwd}"

OPENAI_API_KEY = "{key}"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, dbname="production"
    )
'''
    filename = f"code_{idx:03d}.py"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "code",
        "contains_sensitive": True,
        "categories": ["credential", "api_key"],
        "sensitive_values": [pwd, key],
        "description": "Python file with hardcoded database password and API key",
    })
    idx += 1

    # .env file
    aws_key = _fake_aws_secret()
    stripe = "sk_live_" + "".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(24))
    content = f"""# Production environment
DATABASE_URL=postgres://admin:{_fake_password()}@db.internal:5432/prod
REDIS_URL=redis://default:{_fake_password()}@cache.internal:6379
AWS_SECRET_ACCESS_KEY={aws_key}
STRIPE_SECRET_KEY={stripe}
SENDGRID_API_KEY=SG.{"".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(32))}
JWT_SECRET={"".join(_RNG.choice(string.ascii_letters + string.digits) for _ in range(48))}
"""
    filename = f"code_{idx:03d}.env"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "code",
        "contains_sensitive": True,
        "categories": ["credential", "api_key"],
        "sensitive_values": [aws_key, stripe],
        "description": ".env file with multiple secrets",
    })
    idx += 1

    # Clean code file
    content = '''"""Utility functions for string manipulation."""


def slugify(text: str) -> str:
    """Convert text to URL-friendly slug."""
    return text.lower().replace(" ", "-").strip("-")


def truncate(text: str, max_length: int = 100) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def word_count(text: str) -> int:
    """Count words in text."""
    return len(text.split())
'''
    filename = f"code_{idx:03d}.py"
    (output_dir / filename).write_text(content)
    samples.append({
        "file": filename,
        "type": "code",
        "contains_sensitive": False,
        "categories": [],
        "sensitive_values": [],
        "description": "Clean utility code without secrets",
    })
    idx += 1

    return samples


def generate_dataset(output_dir: Path) -> list[dict]:
    """Generate the complete benchmark dataset.

    Returns:
        List of sample metadata dicts with ground truth annotations.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    all_samples = []
    idx = 0

    # Generate each category
    img_samples = _generate_image_samples(output_dir, idx)
    all_samples.extend(img_samples)
    idx += len(img_samples)

    doc_samples = _generate_pdf_samples(output_dir, idx)
    all_samples.extend(doc_samples)
    idx += len(doc_samples)

    csv_samples = _generate_csv_samples(output_dir, idx)
    all_samples.extend(csv_samples)
    idx += len(csv_samples)

    code_samples = _generate_code_samples(output_dir, idx)
    all_samples.extend(code_samples)
    idx += len(code_samples)

    # Write manifest
    manifest_path = output_dir / "manifest.json"
    manifest = {
        "name": "Domestique File Scanning Benchmark v1.0",
        "total_samples": len(all_samples),
        "positive_samples": sum(1 for s in all_samples if s["contains_sensitive"]),
        "negative_samples": sum(1 for s in all_samples if not s["contains_sensitive"]),
        "categories": sorted(set(
            cat for s in all_samples for cat in s["categories"]
        )),
        "file_types": sorted(set(s["type"] for s in all_samples)),
        "samples": all_samples,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))

    return all_samples


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate file scanning benchmark")
    parser.add_argument("--output", type=Path,
                        default=Path("benchmarks/file_scanning/dataset"))
    args = parser.parse_args()

    samples = generate_dataset(args.output)
    pos = sum(1 for s in samples if s["contains_sensitive"])
    neg = len(samples) - pos

    print(f"Generated {len(samples)} samples ({pos} positive, {neg} negative)")
    print(f"Output: {args.output}")
    print(f"File types: {sorted(set(s['type'] for s in samples))}")
    print(f"Categories: {sorted(set(c for s in samples for c in s['categories']))}")


if __name__ == "__main__":
    main()
