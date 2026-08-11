@echo off
echo Starting IronDome.ai...
echo.

start "IronDome - Frontend + Backend" cmd /k npm run dev

timeout /t 3 /nobreak >nul

start "IronDome - Victim Agent (Healthcare Node)" cmd /k "cd systemapp && venv\Scripts\python.exe monitor_server.py"

echo.
echo Two windows just opened - leave them running.
echo Give everything about 15-20 seconds to fully boot, then open:
echo.
echo     http://localhost:5173
echo.
pause
