@echo off
chcp 65001 >nul
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" src\main.py %*
) else (
    python src\main.py %*
)
