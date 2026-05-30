#!/bin/bash
# Launch LLMGuard in the best mode for this OS
set -e
cd "$(dirname "$0")"
if [ -x ".venv/bin/python" ]; then
  exec .venv/bin/python -m app "$@"
fi
exec python -m app "$@"
