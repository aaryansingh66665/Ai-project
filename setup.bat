@echo off
title CyberAgent X - System Setup
echo ===============================================================================
echo                ⚡ CYBERAGENT X - OFFLINE GPU MULTI-AGENT SETUP ⚡
echo ===============================================================================
echo.

echo [1/3] Installing Python Dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Python package installation encountered issues.
)

echo.
echo [2/3] Installing Web Studio Dependencies...
cd web
call npm install
cd ..

echo.
echo [3/3] Running Hardware & Local Model Pre-flight Check...
python main.py --check

echo.
echo ===============================================================================
echo   Setup Complete! To launch the system, run: start.bat
echo ===============================================================================
pause
