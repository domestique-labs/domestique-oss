"""Entry point for the Domestique desktop application.

Usage:
    python -m domestique_app
    python -m domestique_app --mode portable
    python -m domestique_app --no-browser
    ./run.sh
"""

from domestique_app.main import main

if __name__ == "__main__":
    main()
