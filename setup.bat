@echo off
echo ============================================
echo   IronDome.ai - First-time setup
echo   This installs all dependencies fresh.
echo   Only needs to be run ONCE per machine.
echo ============================================
echo.

echo [1/9] Installing root workspace tools (concurrently)...
call npm install
if errorlevel 1 goto :error

echo.
echo [2/9] Installing frontend dependencies...
cd frontend
call npm install
if errorlevel 1 goto :error
cd ..

echo.
echo [3/9] Setting up ingest-service...
cd backend\ingest-service
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..\..

echo.
echo [4/9] Setting up api-gateway...
cd backend\api-gateway
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..\..

echo.
echo [5/9] Setting up detection-engine...
cd backend\detection-engine
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..\..

echo.
echo [6/9] Setting up alert-manager...
cd backend\alert-manager
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..\..

echo.
echo [7/9] Setting up response-engine...
cd backend\response-engine
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..\..

echo.
echo [8/9] Setting up model microservice (this one takes a while - installs PyTorch)...
cd model_microservice
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..

echo.
echo [9/9] Setting up victim agent (systemapp)...
cd systemapp
python -m venv venv
call venv\Scripts\pip install -r requirements.txt
if errorlevel 1 goto :error
cd ..

echo.
echo ============================================
echo   Setup complete!
echo   Run START.bat to launch everything.
echo ============================================
pause
exit /b 0

:error
echo.
echo ============================================
echo   Setup FAILED. Scroll up to see which step
echo   failed and the error message above it.
echo   Common fix: make sure "python" and "node"
echo   are installed and on your PATH.
echo ============================================
pause
exit /b 1
