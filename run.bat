@echo off
setlocal enabledelayedexpansion
title CyberAgent X

:: ─── GPU environment lock ─────────────────────────────────────────────────
set CUDA_DEVICE_ORDER=PCI_BUS_ID
set CUDA_VISIBLE_DEVICES=0
set OLLAMA_NUM_GPU=99
set NVIDIA_VISIBLE_DEVICES=all

:: ─── Load .env if it exists ───────────────────────────────────────────────
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        set "line=%%A"
        if not "!line:~0,1!"=="#" (
            if not "%%B"=="" set "%%A=%%B"
        )
    )
)

:: ─── Route to run.py ──────────────────────────────────────────────────────
python run.py %*
