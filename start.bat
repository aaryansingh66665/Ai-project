@echo off
title CyberAgent X Launcher
cls
set CUDA_DEVICE_ORDER=PCI_BUS_ID
set CUDA_VISIBLE_DEVICES=0
set OLLAMA_NUM_GPU=99
set NVIDIA_VISIBLE_DEVICES=all
echo ===============================================================================
echo                ⚡ CYBERAGENT X - OFFLINE GPU MULTI-AGENT SYSTEM ⚡
echo                  NVIDIA RTX 3050 (6GB VRAM) • Zero Restrictions
echo ===============================================================================
echo.
echo Select Mode to Launch:
echo   [1] Modern Cyber Studio Web UI (Browser at http://127.0.0.1:8000)
echo   [2] Interactive Terminal CLI Console
echo   [3] Run System Diagnostics & GPU Check
echo   [4] Exit
echo.
set /p choice="Enter Choice (1-4): "

if "%choice%"=="1" (
    echo.
    echo Launching CyberAgent X Web Studio...
    start http://127.0.0.1:8000
    python main.py --web
    goto end
)
if "%choice%"=="2" (
    echo.
    python main.py
    goto end
)
if "%choice%"=="3" (
    echo.
    python main.py --check
    echo.
    pause
    goto end
)
if "%choice%"=="4" (
    exit
)

:end
