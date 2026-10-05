"""Railway entrypoint — Railpack auto-runs root main.py.

Adds src/ to sys.path so the swiggy_hunter package resolves without
a pip install of the project itself, then delegates to the CLI
(default command: run).
"""
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from swiggy_hunter.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
