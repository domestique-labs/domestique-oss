#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# LLMGuard Install — sets up everything needed to run the app.
#
# Usage:
#   cd llmguard
#   bash scripts/install.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

echo "══════════════════════════════════════════════════════════════"
echo "  LLMGuard Installer"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── 1. Python venv ─────────────────────────────────────────────────
echo "▶ [1/5] Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "  Created .venv"
fi
source .venv/bin/activate

# Fix SSL for Homebrew Python
export SSL_CERT_FILE="$(python -c 'import certifi; print(certifi.where())' 2>/dev/null || echo '')"
export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"

# ── 2. Install package + all extras ───────────────────────────────
echo "▶ [2/5] Installing LLMGuard + dependencies..."
pip install -e ".[all]" --quiet
pip install py2app --quiet

# ── 3. Download models ────────────────────────────────────────────
echo "▶ [3/5] Downloading ML models..."
export HF_HUB_OFFLINE=0  # Allow downloads during install
python -c "
import warnings; warnings.filterwarnings('ignore')
print('  GLiNER PII model...')
try:
    from gliner import GLiNER
    GLiNER.from_pretrained('knowledgator/gliner-pii-base-v1.0')
    print('  ✓ GLiNER ready')
except Exception as e: print(f'  ⚠ GLiNER: {e}')
"
export HF_HUB_OFFLINE=1

# ── 4. Ollama models ──────────────────────────────────────────────
echo "▶ [4/5] Pulling Ollama models..."
if command -v ollama &>/dev/null; then
    ollama pull qwen3:1.7b 2>/dev/null && echo "  ✓ qwen3:1.7b" || echo "  ⚠ qwen3:1.7b failed"
    ollama pull gemma4:e2b 2>/dev/null && echo "  gemma4:e2b" || echo "  gemma4:e2b failed"
else
    echo "  ⚠ Ollama not installed — install from https://ollama.com"
fi

# ── 5. Build .app bundle ─────────────────────────────────────────
echo "▶ [5/5] Building LLMGuard.app..."
python setup.py py2app --alias 2>/dev/null

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✅ Installation complete!"
echo ""
echo "  Launch:  open dist/LLMGuard.app"
echo "  Dashboard: http://127.0.0.1:9876/"
echo ""
echo "  Default preset: Balanced (Regex + GLiNER + Qwen3 1.7B)"
echo "══════════════════════════════════════════════════════════════"
