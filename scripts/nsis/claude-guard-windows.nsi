; Claude 持久化安全锁 · Windows 原生单文件安装程序 (NSIS Unicode / MUI2)
; 特点:
;   - 真正的单文件 PE .exe 安装向导，双击自动 UAC 管理员提权
;   - 内嵌全部引擎脚本、WPF 控制台、UTF-16 LE IFEO 拦截弹窗、7,456 条 CN 表与 4,751 条海外区间表
;   - 自动安装至 C:\ProgramData\ClaudeGuard，创建桌面与开始菜单快捷方式，注册 Windows 控制面板标准卸载入口 (Uninstall.exe)
;   - 卸载时自动调用 uninstall-all 完整解除内核 IFEO 进程锁、WFP 防火墙规则与 hosts 黑洞，恢复出厂状态

Unicode true
!include "MUI2.nsh"

!define APP_NAME "Claude安全锁"
!define APP_VERSION "2.1.0"
!define APP_PUBLISHER "ClaudeGuard"
!define INSTALL_DIR "C:\ProgramData\ClaudeGuard"
!define UNINST_REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\ClaudeGuard"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\..\dist\Claude安全锁-Windows安装程序.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!define MUI_ICON "..\..\portable-kit\windows\app.ico"
!define MUI_UNICON "..\..\portable-kit\windows\app.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $\"$INSTDIR\windows\ClaudeGuardUI.ps1$\""
!define MUI_FINISHPAGE_RUN_TEXT "立即打开 Claude安全锁 控制台"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"

Section "主程序与防泄露安全引擎" SecMain
    SetOutPath "$INSTDIR\windows"
    File "..\..\portable-kit\windows\claude-guard.ps1"
    File "..\..\portable-kit\windows\ClaudeGuardUI.ps1"
    File "..\..\portable-kit\windows\env-audit.ps1"
    File "..\..\portable-kit\windows\claude-blocked-alert.vbs"
    File "..\..\portable-kit\windows\Claude安全锁控制台.bat"
    File "..\..\portable-kit\windows\app.ico"

    SetOutPath "$INSTDIR\data"
    File "..\..\portable-kit\data\cn-ipv4.txt"
    File "..\..\portable-kit\data\overseas-ipv4-ranges.txt"

    SetOutPath "$INSTDIR"
    File "/oname=使用说明.md" "..\..\portable-kit\README-交付手册.md"
    File "..\..\portable-kit\templates\断网急救.txt"
    File "..\..\portable-kit\templates\Clash-Verge-防漏覆写模板.yaml"

    ; 生成标准 Windows 卸载器
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; 创建桌面快捷方式 (带高清盾牌锁图标)
    SetOutPath "$INSTDIR\windows"
    CreateShortcut "$DESKTOP\Claude安全锁.lnk" "$INSTDIR\windows\Claude安全锁控制台.bat" "" "$INSTDIR\windows\app.ico" 0

    ; 创建开始菜单快捷方式与卸载入口
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\Claude安全锁.lnk" "$INSTDIR\windows\Claude安全锁控制台.bat" "" "$INSTDIR\windows\app.ico" 0
    CreateShortcut "$SMPROGRAMS\${APP_NAME}\卸载 Claude安全锁.lnk" "$INSTDIR\Uninstall.exe" "" "$INSTDIR\windows\app.ico" 0

    ; 注册 Windows 控制面板「卸载或更改程序」标准条目
    WriteRegStr HKLM "${UNINST_REG_KEY}" "DisplayName" "${APP_NAME} (防直连与遥测泄露)"
    WriteRegStr HKLM "${UNINST_REG_KEY}" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "${UNINST_REG_KEY}" "Publisher" "${APP_PUBLISHER}"
    WriteRegStr HKLM "${UNINST_REG_KEY}" "DisplayIcon" "$INSTDIR\windows\app.ico"
    WriteRegStr HKLM "${UNINST_REG_KEY}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegDWORD HKLM "${UNINST_REG_KEY}" "NoModify" 1
    WriteRegDWORD HKLM "${UNINST_REG_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
    ; 卸载前自动执行 uninstall-all: 解除 IFEO 内核进程锁、WFP 防火墙规则与 hosts 黑洞
    nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\windows\claude-guard.ps1" uninstall-all'

    Delete "$DESKTOP\Claude安全锁.lnk"
    RMDir /r "$SMPROGRAMS\${APP_NAME}"
    DeleteRegKey HKLM "${UNINST_REG_KEY}"

    RMDir /r "$INSTDIR\windows"
    RMDir /r "$INSTDIR\data"
    Delete "$INSTDIR\使用说明.md"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"
SectionEnd
