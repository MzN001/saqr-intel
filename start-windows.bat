@echo off
cd /d "%~dp0"
echo === SAQR-INTEL: first run takes a few minutes ===
where python >nul 2>nul || (echo Python not found. Reinstall Python and tick "Add python.exe to PATH". & pause & exit /b)
where node >nul 2>nul || (echo Node.js not found. Install the LTS version from https://nodejs.org then run this again. & pause & exit /b)
if not exist .venv python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
python -m playwright install chromium
echo === Starting backend (port 8000) in a new window ===
start "SAQR-INTEL backend" cmd /k "cd /d "%~dp0" && .venv\Scripts\python -m uvicorn main:app --host 0.0.0.0 --port 8000"
cd frontend
if not exist node_modules call npm install
echo === Starting citizen app (port 3000) ===
start "" http://localhost:3000/citizen
call npm run dev -- -H 0.0.0.0
pause
