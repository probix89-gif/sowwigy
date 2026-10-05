"""Railway entrypoint — Railpack auto-runs root main.py.

Delegates to the swiggy-hunter CLI (default command: run).
"""
from swiggy_hunter.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
