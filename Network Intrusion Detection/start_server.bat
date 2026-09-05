@echo off
echo ================================================
echo   NIDS Agent - Network Intrusion Detection
echo ================================================
echo.
echo Starting Flask server on http://localhost:5000
echo Press Ctrl+C to stop the server.
echo.

cd /d "%~dp0"
python run.py

pause
