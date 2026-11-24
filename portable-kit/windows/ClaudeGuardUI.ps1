# Claude 持久化安全锁 · Windows 极简单锁图形控制台 (WPF 零依赖)
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$CORE = Join-Path $PSScriptRoot 'claude-guard.ps1'

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Claude 安全锁控制台 · Windows"
        Width="720" Height="680" MinWidth="600" MinHeight="580"
        WindowStartupLocation="CenterScreen"
        Background="#FF0B1120" Foreground="#FFF4F7FB" FontFamily="Segoe UI">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#FF162238"/>
            <Setter Property="Foreground" Value="#FFE6EDF7"/>
            <Setter Property="BorderBrush" Value="#FF2A3952"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="MinHeight" Value="40"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Padding" Value="12,8"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="9" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="#FF131E31" BorderBrush="#FF2A3952" BorderThickness="1" CornerRadius="12" Padding="16">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                    <TextBlock Text="Claude 持久化安全锁（零泄露 · 永久防呆）" FontSize="17" FontWeight="Bold"/>
                    <TextBlock x:Name="StatusSub" Text="正在读取操作系统防火墙与内核进程锁状态..." FontSize="11" Foreground="#FF9AA9BF" Margin="0,6,0,0" TextWrapping="Wrap"/>
                </StackPanel>
                <Border x:Name="StatusPill" Grid.Column="1" VerticalAlignment="Center" CornerRadius="12" Padding="14,7" Background="#33F59E0B">
                    <TextBlock x:Name="StatusText" Text="检查中" FontSize="12" FontWeight="Bold" Foreground="#FFFBBE24"/>
                </Border>
            </Grid>
        </Border>

        <Border Grid.Row="1" Background="#FF101C30" BorderBrush="#FF24415E" BorderThickness="1" CornerRadius="12" Padding="16" Margin="0,12,0,0">
            <StackPanel>
                <Button x:Name="BtnToggleLock" Content="🔒 开启安全锁（启用防泄露硬锁并解锁 Claude 使用）" MinHeight="48" FontSize="14" Background="#FF166534" BorderBrush="#FF22C55E" Foreground="#FFFFFFFF"/>
                <TextBlock x:Name="LockHint" Text="说明：关闭安全锁切回日常上网时，系统将自动从内核锁死 Claude 进程（点开弹提示）并永久封锁 Claude 与遥测服务器直连，除非卸载本软件。" FontSize="11" Foreground="#FF93C5FD" TextWrapping="Wrap" Margin="0,8,0,0"/>
                <CheckBox x:Name="ChkStrictMode" Content="开启安全锁时使用「全封闭模式」（连国内公网直连与物理裸 DNS 53 也一并封锁；默认放行国内直连）" Foreground="#FFCBD5E1" FontSize="11" Margin="0,8,0,0"/>
            </StackPanel>
        </Border>

        <Border Grid.Row="2" Background="#FF131E31" BorderBrush="#FF2A3952" BorderThickness="1" CornerRadius="12" Padding="12" Margin="0,12,0,0">
            <StackPanel>
                <TextBlock Text="代理第一跳入口 IP / 域名（可选：链式代理第一跳在国内中转机可留空；直连海外 VPS 或全封闭模式请填 IP，多个逗号隔开）" FontSize="11" Foreground="#FF9AA9BF" TextWrapping="Wrap"/>
                <Grid Margin="0,7,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="NodesInput" Background="#FF162238" Foreground="#FFFFFFFF" BorderBrush="#FF334155" BorderThickness="1" Padding="10,6" FontSize="13" VerticalContentAlignment="Center"/>
                    <Button x:Name="BtnSaveNodes" Grid.Column="1" Content="保存入口" MinHeight="34" Margin="10,0,0,0"/>
                </Grid>
            </StackPanel>
        </Border>

        <UniformGrid Grid.Row="3" Columns="4" Margin="0,12,0,0">
            <Button x:Name="BtnInit" Content="🚀 一键初始化环境" Background="#FF1D4ED8" BorderBrush="#FF3B82F6" Foreground="#FFFFFFFF" Margin="0,0,6,0"/>
            <Button x:Name="BtnVerifyFw" Content="🛡️ 验收防火墙与日志" Margin="3,0,3,0"/>
            <Button x:Name="BtnCheck" Content="🔍 14维度深度体检" Margin="3,0,3,0"/>
            <Button x:Name="BtnExport" Content="📄 导出交机报告" Margin="6,0,0,0"/>
        </UniformGrid>

        <Border Grid.Row="4" Background="#FF0F172A" BorderBrush="#FF22304A" BorderThickness="1" CornerRadius="12" Padding="12" Margin="0,12,0,0">
            <TextBox x:Name="OutputBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     Background="Transparent" Foreground="#FFDCE7F7" BorderThickness="0"
                     FontFamily="Consolas" FontSize="12" Text="欢迎使用 Claude 持久化安全锁！&#x0A;&#x0A;1. 首次交付：在 Clash Verge(服务模式+TUN) 或 v2rayN(管理员+启用Tun) 开启「全局 + TUN」，点击「🚀 一键初始化环境」。&#x0A;2. 日常切换：只用上面一把大开关！开启安全锁 = 安心用 Claude（只能走海外 TUN）；关闭安全锁 = 正常日常上网，但 Claude 已被系统内核锁死（永远点不开，点开弹提示）且遥测流量 0 泄露！&#x0A;3. 验收实证：点击「🛡️ 验收防火墙与日志」核查系统防火墙、IFEO 进程锁与 pfirewall.log 真实 DROP 丢包记录。"/>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [Windows.Markup.XamlReader]::Load($reader)

$statusPill    = $win.FindName('StatusPill')
$statusText    = $win.FindName('StatusText')
$statusSub     = $win.FindName('StatusSub')
$btnToggleLock = $win.FindName('BtnToggleLock')
$chkStrictMode = $win.FindName('ChkStrictMode')
$nodesInput    = $win.FindName('NodesInput')
$outputBox     = $win.FindName('OutputBox')
$btnSave       = $win.FindName('BtnSaveNodes')
$btnInit       = $win.FindName('BtnInit')
$btnVerifyFw   = $win.FindName('BtnVerifyFw')
$btnCheck      = $win.FindName('BtnCheck')
$btnExport     = $win.FindName('BtnExport')

$allBtns = @($btnToggleLock, $btnSave, $btnInit, $btnVerifyFw, $btnCheck, $btnExport)
$script:currentLock = 'off'
$script:suppressStrictEvent = $false

function Invoke-GuardAction([string[]]$GuardArgs) {
    return (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CORE @GuardArgs 2>&1 | Out-String).Trim()
}

function Refresh-State {
    $raw = Invoke-GuardAction @('status')
    $map = @{}
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^([^=]+)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
    }
    $lock = $map['LOCK']
    $mode = $map['LOCK_MODE']
    $procLocked = $map['PROC_LOCKED']
    $strict = $map['STRICT_MODE']
    $nodes = $map['ENTRY_NODES']
    $cc = $map['COUNTRY_TARGET']
    $script:currentLock = $lock

    if ($nodes -and $nodes -ne '未配置' -and [string]::IsNullOrWhiteSpace($nodesInput.Text)) { $nodesInput.Text = $nodes }
    $script:suppressStrictEvent = $true
    $chkStrictMode.IsChecked = ($strict -eq '1')
    $script:suppressStrictEvent = $false

    if ($lock -eq 'on') {
        $modeLabel = if ($mode -eq 'strict') { '全封闭模式' } else { '放行国内 · 死锁Claude与海外' }
        $statusText.Text = '🔒 安全锁已开启'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF4ADE80'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#3322C55E'))
        $statusSub.Text = "Claude 已放行且仅能走海外 TUN ($modeLabel) · 退出/重启不失效 | 目标国: $cc"
        $btnToggleLock.Content = '🔓 关闭安全锁（切换日常上网 · 自动从系统锁死 Claude 进程）'
        $btnToggleLock.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF854D0E'))
        $btnToggleLock.BorderBrush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFEAB308'))
    } else {
        $statusText.Text = if ($lock -eq 'standby') { '🟡 日常模式 · Claude已锁死' } else { '⚠️ 尚未初始化' }
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFFACC15'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#33EAB308'))
        $statusSub.Text = "日常上网可用 | Claude 内核进程锁=$procLocked + 永久遥测/ASN 防线在线 | 目标国: $cc"
        $btnToggleLock.Content = '🔒 开启安全锁（启用防泄露硬锁并解锁 Claude 使用）'
        $btnToggleLock.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF166534'))
        $btnToggleLock.BorderBrush = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF22C55E'))
    }
}

function Run-UiOp([string]$Title, [string[]]$GuardArgs) {
    foreach ($b in $allBtns) { $b.IsEnabled = $false }
    $chkStrictMode.IsEnabled = $false
    $outputBox.Text = "正在执行: $Title ..."
    $win.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
    try {
        $outputBox.Text = Invoke-GuardAction $GuardArgs
    } catch {
        $outputBox.Text = "执行失败: $($_.Exception.Message)"
    } finally {
        Refresh-State
        foreach ($b in $allBtns) { $b.IsEnabled = $true }
        $chkStrictMode.IsEnabled = $true
    }
}

$btnToggleLock.Add_Click({
    if ($script:currentLock -eq 'on') {
        Run-UiOp '关闭安全锁 (切回日常模式并从内核锁死 Claude 进程)' @('unlock')
    } else {
        $n = $nodesInput.Text.Trim()
        if ($n) { $null = Invoke-GuardAction @('set-nodes', $n) }
        Run-UiOp '开启安全锁 (刷入持久化防火墙并解锁 Claude)' @('lock')
    }
})

$chkStrictMode.Add_Click({
    if ($script:suppressStrictEvent) { return }
    $val = if ($chkStrictMode.IsChecked) { '1' } else { '0' }
    if ($val -eq '1' -and [string]::IsNullOrWhiteSpace($nodesInput.Text)) {
        $outputBox.Text = '提示：启用全封闭模式前，请先在下方填入第一跳代理入口 IP 或域名！'
        $script:suppressStrictEvent = $true; $chkStrictMode.IsChecked = $false; $script:suppressStrictEvent = $false
        return
    }
    $n = $nodesInput.Text.Trim()
    if ($n) { $null = Invoke-GuardAction @('set-nodes', $n) }
    $null = Invoke-GuardAction @('set-strict', $val)
    if ($script:currentLock -eq 'on') {
        Run-UiOp '应用新开锁策略' @('lock')
    } else {
        $outputBox.Text = if ($val -eq '1') { '已设为：下次开启安全锁时使用全封闭模式。' } else { '已设为：下次开启安全锁时放行国内直连（推荐）。' }
    }
})

$btnSave.Add_Click({
    $n = $nodesInput.Text.Trim()
    $out = Invoke-GuardAction @('set-nodes', $n)
    if ($script:currentLock -eq 'on') {
        $out = $out + "`r`n" + (Invoke-GuardAction @('lock'))
    }
    $outputBox.Text = $out
    Refresh-State
})

$btnInit.Add_Click({ Run-UiOp '一键初始化环境 (锁时区/地区/英文/关IPv6 + 开启安全锁)' @('init', $nodesInput.Text.Trim()) })
$btnVerifyFw.Add_Click({ Run-UiOp '验收系统防火墙、内核进程锁与 DROP 流量日志' @('verify-firewall') })
$btnCheck.Add_Click({ Run-UiOp '14 维度深度本地环境体检' @('check') })
$btnExport.Add_Click({ Run-UiOp '导出脱敏交机体检报告到桌面' @('export-report') })

$win.Add_Loaded({ Refresh-State })
$null = $win.ShowDialog()
