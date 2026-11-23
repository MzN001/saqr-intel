#!/bin/bash
cd "$(dirname "$0")"
echo "=== SAQR-INTEL: first run takes a few minutes ==="
command -v node >/dev/null || { echo "Node.js not found. Install the LTS version from https://nodejs.org"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m playwright install chromium
python -m uvicorn main:app --host 0.0.0.0 --port 8000 &
BACKEND=$!
trap 'kill $BACKEND' EXIT
cd frontend
[ -d node_modules ] || npm install
(sleep 6 && open http://localhost:3000/citizen) &
npm run dev -- -H 0.0.0.0
