@echo off
chcp 65001 >nul
setlocal
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ==========================================
echo    Claude 持久化安全锁 · Windows 一键卸载
echo ==========================================
echo.
set "INSTALL_DIR=C:\ProgramData\ClaudeGuard"
if exist "%INSTALL_DIR%\windows\claude-guard.ps1" (
    echo 正在解除系统内核级 Claude 进程锁与永久防火墙规则，并恢复原生网络...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%INSTALL_DIR%\windows\claude-guard.ps1" uninstall-all
)
del /F /Q "%USERPROFILE%\Desktop\Claude安全锁.lnk" 2>nul
rmdir /S /Q "%INSTALL_DIR%" 2>nul
rmdir /S /Q "%USERPROFILE%\.claude-guard" 2>nul
echo.
echo [OK] 已完全卸载，电脑防火墙与网络已恢复原生状态。
pause
