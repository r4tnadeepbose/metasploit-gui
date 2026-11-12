@echo off
setlocal
cd /d "%~dp0"
title Metasploit GUI

where py >nul 2>nul
if %errorlevel%==0 (
  py run.py
) else (
  python run.py
)

if %errorlevel% neq 0 (
  echo.
  echo Failed to start. Make sure Python 3.10+ is installed and on PATH.
  pause
)
endlocal
