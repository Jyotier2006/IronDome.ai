@echo off
rem Stops IronDome.ai: the sensor and dashboard windows opened by START.bat, plus any
rem sensor (python ... sensor_service.py) or dashboard (vite in this project's frontend)
rem started some other way. Nothing else is touched - no blanket taskkill of python/node.
setlocal
set "IRONDOME_ROOT=%~dp0"
if /i not "%~1"=="/quiet" echo Stopping IronDome.ai ...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$front = (Join-Path $env:IRONDOME_ROOT 'frontend').ToLower();" ^
  "$all = @(Get-CimInstance Win32_Process);" ^
  "$windows = $all | Where-Object { $_.Name -eq 'cmd.exe' -and ($_.CommandLine -like '*title IronDome.ai sensor*' -or $_.CommandLine -like '*title IronDome.ai dashboard*') };" ^
  "foreach ($w in $windows) { & taskkill.exe /PID $w.ProcessId /T /F *> $null };" ^
  "$strays = $all | Where-Object { ($_.Name -like 'python*.exe' -and $_.CommandLine -like '*sensor_service.py*') -or ($_.Name -eq 'node.exe' -and $_.CommandLine -and $_.CommandLine.ToLower().Contains($front) -and $_.CommandLine -like '*vite*') };" ^
  "foreach ($p in $strays) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue };" ^
  "$n = @($windows).Count + @($strays).Count;" ^
  "if ($n) { Write-Host ('  stopped ' + $n + ' IronDome process(es)') } elseif ('%~1' -ne '/quiet') { Write-Host '  nothing was running' }"
endlocal
exit /b 0
