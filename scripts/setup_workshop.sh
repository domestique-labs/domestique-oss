#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Domestique Workshop Setup — run ONCE before the workshop to pre-download
# all models and dependencies. After this, everything runs fully offline.
#
# Usage:
#   cd domestique
#   bash scripts/setup_workshop.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "══════════════════════════════════════════════════════════════"
echo "  Domestique Workshop Setup"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Python venv ─────────────────────────────────────────────────
echo "▶ [1/5] Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate

# Fix SSL cert verification on macOS (Homebrew Python doesn't use system certs)
export SSL_CERT_FILE="$(python -c 'import certifi; print(certifi.where())' 2>/dev/null || echo '')"
export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"

# ── 2. Install all dependencies ────────────────────────────────────
echo "▶ [2/5] Installing all dependencies..."
pip install -e ".[workshop]" --quiet

# ── 3. Download spaCy model (Presidio needs this) ─────────────────
echo "▶ [3/5] Downloading spaCy language model..."
python -m spacy download en_core_web_lg --quiet 2>/dev/null || \
    pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl --quiet 2>/dev/null || \
    echo "  ⚠ spaCy model download failed — Presidio PII will be unavailable"

# ── 4. Pre-download ML models ─────────────────────────────────────
echo "▶ [4/5] Pre-downloading ML models (runs offline after this)..."
python -c "
import warnings
warnings.filterwarnings('ignore')

print('  Downloading GLiNER PII model...')
try:
    from gliner import GLiNER
    m = GLiNER.from_pretrained('knowledgator/gliner-pii-base-v1.0')
    m.predict_entities('warmup', ['person'])  # trigger full load
    print('  ✓ GLiNER ready')
except Exception as e:
    print(f'  ⚠ GLiNER failed: {e}')

print('  Downloading SentenceTransformers model...')
try:
    from sentence_transformers import SentenceTransformer
    m = SentenceTransformer('all-MiniLM-L6-v2')
    m.encode(['warmup'])
    print('  ✓ SentenceTransformers ready')
except Exception as e:
    print(f'  ⚠ SentenceTransformers failed: {e}')

print('  Verifying Presidio...')
try:
    from presidio_analyzer import AnalyzerEngine
    a = AnalyzerEngine()
    r = a.analyze(text='Test 123-45-6789', language='en')
    print(f'  ✓ Presidio ready ({len(r)} entities in test)')
except Exception as e:
    print(f'  ⚠ Presidio failed: {e}')
"

# ── 5. Ollama models ──────────────────────────────────────────────
echo "▶ [5/5] Pulling Ollama models..."
if command -v ollama &>/dev/null; then
    for model in qwen3:1.7b gemma4:e2b; do
        echo "  Pulling $model..."
        ollama pull "$model" 2>/dev/null || echo "  ⚠ Failed to pull $model"
    done
    echo "  ✓ Ollama models ready"
else
    echo "  ⚠ Ollama not installed — install from https://ollama.com"
    echo "    Then run: ollama pull qwen3:1.7b && ollama pull gemma4:e2b && ollama pull"
fi

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✅ Setup complete! Run the app:"
echo "     .venv/bin/python -c 'from domestique_app.main import launch; launch()'"
echo ""
echo "  Run the benchmark:"
echo "     .venv/bin/python bench/comprehensive_eval.py"
echo "══════════════════════════════════════════════════════════════"
