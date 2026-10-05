#!/usr/bin/env bash
set -euo pipefail

echo "[*] swiggy-hunter v2 setup"

if ! command -v python3.11 >/dev/null 2>&1; then
  echo "[-] python3.11 required" >&2
  exit 1
fi

python3.11 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"

if ! python -c "import curl_cffi" 2>/dev/null; then
  echo "[!] curl_cffi not installed — install with: pip install curl-cffi"
fi

if ! python -c "import playwright" 2>/dev/null; then
  echo "[!] playwright not installed — install with: pip install playwright && playwright install chromium"
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[*] wrote .env — fill GLM_API_KEY and TELEGRAM_*"
fi

mkdir -p data logs data/workspace data/evidence data/exploits data/browser_profile

echo "[+] done. run: source .venv/bin/activate && swiggy-hunter run"
