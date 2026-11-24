@echo off
chcp 65001 >nul
setlocal
:: 检查管理员权限，非管理员自动 UAC 提权重启自身
net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "SRC=%~dp0"
if exist "%SRC%windows\claude-guard.ps1" (
    set "WIN_SRC=%SRC%windows"
    set "DATA_SRC=%SRC%data"
) else (
    set "WIN_SRC=%SRC%"
    set "DATA_SRC=%SRC%..\data"
)
set "INSTALL_DIR=C:\ProgramData\ClaudeGuard"
echo ==========================================
echo    Claude 持久化安全锁 · Windows 一键安装
echo ==========================================
echo.
if not exist "%WIN_SRC%\claude-guard.ps1" (
    echo [ERROR] 安装包文件不完整，请先将整个 zip 压缩包右键全部解压缩，再双击运行。
    pause
    exit /b 1
)
if not exist "%DATA_SRC%\overseas-ipv4-ranges.txt" (
    echo [ERROR] 缺少海外 IP 分段数据文件，请先将整个 zip 压缩包完整解压后再安装。
    pause
    exit /b 1
)

if not exist "%INSTALL_DIR%\windows" mkdir "%INSTALL_DIR%\windows"
if not exist "%INSTALL_DIR%\data" mkdir "%INSTALL_DIR%\data"

copy /Y "%WIN_SRC%\claude-guard.ps1" "%INSTALL_DIR%\windows\" >nul
copy /Y "%WIN_SRC%\ClaudeGuardUI.ps1" "%INSTALL_DIR%\windows\" >nul
copy /Y "%WIN_SRC%\env-audit.ps1" "%INSTALL_DIR%\windows\" >nul
copy /Y "%WIN_SRC%\Claude安全锁控制台.bat" "%INSTALL_DIR%\windows\" >nul
copy /Y "%DATA_SRC%\overseas-ipv4-ranges.txt" "%INSTALL_DIR%\data\" >nul
copy /Y "%DATA_SRC%\cn-ipv4.txt" "%INSTALL_DIR%\data\" >nul

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Claude安全锁.lnk'); $sc.TargetPath = '%INSTALL_DIR%\windows\Claude安全锁控制台.bat'; $sc.WorkingDirectory = '%INSTALL_DIR%\windows'; $sc.Save()"

echo [OK] 已安装到: %INSTALL_DIR%
echo [OK] 已在桌面创建快捷方式: Claude安全锁
echo.
echo 正在打开「Claude 双锁安全控制台」...
start "" "%INSTALL_DIR%\windows\Claude安全锁控制台.bat"
pause
