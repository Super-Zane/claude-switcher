@echo off
chcp 65001 >nul
setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%SCRIPT_DIR%ClaudeGuardUI.ps1\"'"
