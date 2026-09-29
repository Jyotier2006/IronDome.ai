@echo off
echo ============================================
echo   IronDome.ai - first-time setup
echo   Installs all dependencies.
echo   Only needs to be run ONCE per machine.
echo ============================================
echo.

echo [1/4] Installing root workspace tools (concurrently) and dashboard dependencies...
call npm install
if errorlevel 1 goto :error

echo.
echo [2/4] Creating the Python environment (venv)...
python -m venv venv
if errorlevel 1 goto :error

echo.
echo [3/4] Installing sensor + training dependencies...
call venv\Scripts\pip install -r backend\sensor-service\requirements.txt -r model_microservice\requirements.txt
if errorlevel 1 goto :error

echo.
echo [4/4] Checking the trained models and running the unit tests...
if not exist model_microservice\models\ddos.joblib (
    echo Models not found - training them now, about 1 minute...
    cd model_microservice
    call ..\venv\Scripts\python.exe model_training_pipeline.py
    if errorlevel 1 goto :error
    cd ..
)
call venv\Scripts\python.exe -m unittest discover -s tests
if errorlevel 1 goto :error

echo.
echo ============================================
echo   Setup complete!
echo   Run START.bat to launch the sensor and dashboard.
echo ============================================
pause
exit /b 0

:error
echo.
echo ============================================
echo   Setup FAILED. Scroll up to see which step
echo   failed and the error message above it.
echo   Common fix: make sure "python" (3.11+) and
echo   "node" (18+) are installed and on your PATH.
echo ============================================
pause
exit /b 1
