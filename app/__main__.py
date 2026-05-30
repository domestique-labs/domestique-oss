"""Entry point for the LLMGuard desktop application.

Usage:
    python -m app
    python -m app --mode portable
    python -m app --no-browser
    ./run.sh
"""

from app.main import main

if __name__ == "__main__":
    main()
