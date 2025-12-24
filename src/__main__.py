"""
Entry point for running redact-verify as a module.

Usage:
    python -m src [options] file.pdf
"""

from src.cli import main

if __name__ == "__main__":
    main()

