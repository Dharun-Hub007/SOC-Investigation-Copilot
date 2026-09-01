@echo off

cd /d C:\Users\narut\SOC-Investigation-Copilot

call venv\Scripts\activate.bat

start "SOC Flask Dashboard" cmd /k "python -m web.app"

timeout /t 5 /nobreak >nul

start "Wazuh Auto Ingestion" cmd /k "python auto_ingest.py"

timeout /t 5 /nobreak >nul

start "" http://127.0.0.1:5000

exit