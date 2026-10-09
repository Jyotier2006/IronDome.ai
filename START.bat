@echo off
setlocal
cd /d "%~dp0"
echo Starting IronDome.ai (SIH PS 26145) ...
echo.

rem -- 1. Python: the venv from setup.bat if it exists, otherwise python / py on PATH.
rem    (PY is run from backend\sensor-service, hence the relative venv path.)
set "PY="
if exist "venv\Scripts\python.exe" (
    set "PY=..\..\venv\Scripts\python.exe"
    set "PY_CHECK=venv\Scripts\python.exe"
) else (
    where python >nul 2>nul && (set "PY=python" & set "PY_CHECK=python")
)
if not defined PY (
    where py >nul 2>nul && (set "PY=py -3" & set "PY_CHECK=py -3")
)
if not defined PY (
    echo [ERROR] Python was not found. Install Python 3.11+ ^(tick "Add to PATH"^) and run setup.bat once.
    goto :fail
)
%PY_CHECK% -c "import fastapi, socketio, uvicorn, sklearn, joblib, numpy" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] The sensor's Python packages are not installed for: %PY_CHECK%
    echo         Run setup.bat once, or:
    echo         %PY_CHECK% -m pip install -r backend\sensor-service\requirements.txt
    goto :fail
)

rem -- 2. Dashboard packages.
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js / npm was not found. Install Node.js 18+ and run setup.bat once.
    goto :fail
)
if not exist "frontend\node_modules\vite" (
    echo [ERROR] The dashboard packages are not installed. Run setup.bat once ^(or: cd frontend, then npm install^).
    goto :fail
)

rem -- 3. Only now, with everything in place, stop a copy that is still running (a second
rem    sensor cannot bind its ports), then launch. The window titles let STOP.bat find
rem    exactly these two windows again.
call "%~dp0STOP.bat" /quiet
ping -n 2 127.0.0.1 >nul
start "IronDome.ai sensor" cmd /k "title IronDome.ai sensor && cd backend\sensor-service && %PY% sensor_service.py"
start "IronDome.ai dashboard" cmd /k "title IronDome.ai dashboard && cd frontend && npm run dev"

rem -- 4. Wait for the sensor's warm start so a failure is reported here, not as an empty dashboard.
set "SENSOR_PORT=%PORT%"
if not defined SENSOR_PORT set "SENSOR_PORT=3001"
where curl >nul 2>nul || goto :started
echo Waiting for the sensor to load its models and 5 minutes of estate history ...
set /a tries=0
:wait_sensor
curl -sf -o nul -m 2 http://127.0.0.1:%SENSOR_PORT%/health && goto :started
set /a tries+=1
if %tries% geq 45 (
    echo.
    echo [WARNING] The sensor has not answered after 90 seconds.
    echo           Look at the "IronDome.ai sensor" window for the error message.
    goto :done
)
ping -n 3 127.0.0.1 >nul
goto :wait_sensor

:started
echo.
echo Sensor and dashboard are running in their own windows - leave them open.
echo Open the dashboard:   http://localhost:5173
echo.
echo Attacks happen only when you inject one: click the flask tab on the right edge of the
echo dashboard (Traffic lab). The built-in lab only generates normal background traffic.
echo   Random demo attacks every ~2 min instead:  set IRONDOME_AUTO_SCENARIOS=on  then START.bat
echo   Stop everything:                           STOP.bat
echo   Replay a capture:  python scripts\replay_capture.py captures\kill_chain.jsonl.gz
echo   Flow collector (receive-only):  UDP 2055 (NetFlow v5/v9, IPFIX, sFlow, JSON)
:done
echo.
pause
exit /b 0

:fail
echo.
pause
exit /b 1
