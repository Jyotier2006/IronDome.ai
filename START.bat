@echo off
echo Starting IronDome.ai (SIH PS 26145) ...
echo.

start "IronDome - Passive Sensor" cmd /k "cd backend\sensor-service && ..\..\venv\Scripts\python.exe sensor_service.py"

timeout /t 3 /nobreak >nul

start "IronDome - Dashboard" cmd /k "cd frontend && npm run dev"

echo.
echo Two windows just opened - leave them running.
echo The sensor loads 5 minutes of estate history, then streams live detections.
echo Give it about 15 seconds, then open:
echo.
echo     http://localhost:5173
echo.
echo Flow collector (receive-only):  UDP 2055   (NetFlow v5 / JSON flow records)
echo Replay a capture:   venv\Scripts\python.exe scripts\replay_capture.py captures\kill_chain.jsonl.gz
echo.
pause
