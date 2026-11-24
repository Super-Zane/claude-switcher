# Claude 安全锁 · Windows 极简图形控制台 (WPF 零依赖，双击 Claude安全锁控制台.bat 启动)
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$CORE = Join-Path $PSScriptRoot 'claude-guard.ps1'

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Claude 安全锁 · Windows 控制台"
        Width="660" Height="620" MinWidth="560" MinHeight="520"
        WindowStartupLocation="CenterScreen"
        Background="#FF0B1120" Foreground="#FFF4F7FB" FontFamily="Segoe UI">
    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#FF162238"/>
            <Setter Property="Foreground" Value="#FFE6EDF7"/>
            <Setter Property="BorderBrush" Value="#FF2A3952"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="MinHeight" Value="42"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Padding" Value="14,8"/>
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
    <Grid Margin="22">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="#FF131E31" BorderBrush="#FF2A3952" BorderThickness="1" CornerRadius="12" Padding="18">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel>
                    <TextBlock Text="Claude 安全锁（方案 A · 严格白名单零泄露）" FontSize="17" FontWeight="Bold"/>
                    <TextBlock x:Name="StatusSub" Text="正在读取系统防火墙状态..." FontSize="11" Foreground="#FF9AA9BF" Margin="0,6,0,0" TextWrapping="Wrap"/>
                </StackPanel>
                <Border x:Name="StatusPill" Grid.Column="1" VerticalAlignment="Center" CornerRadius="12" Padding="14,7" Background="#33F59E0B">
                    <TextBlock x:Name="StatusText" Text="检查中" FontSize="12" FontWeight="Bold" Foreground="#FFFBBE24"/>
                </Border>
            </Grid>
        </Border>

        <Border Grid.Row="1" Background="#FF131E31" BorderBrush="#FF2A3952" BorderThickness="1" CornerRadius="12" Padding="16" Margin="0,14,0,0">
            <StackPanel>
                <TextBlock Text="代理入口节点 IP / 域名（链式代理请填第一跳入口，多个用逗号隔开）" FontSize="11" FontWeight="SemiBold" Foreground="#FF9AA9BF"/>
                <Grid Margin="0,8,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="NodesInput" Background="#FF162238" Foreground="#FFFFFFFF" BorderBrush="#FF334155" BorderThickness="1" Padding="10,8" FontSize="13" VerticalContentAlignment="Center"/>
                    <Button x:Name="BtnSaveNodes" Grid.Column="1" Content="保存节点" MinHeight="36" Margin="10,0,0,0"/>
                </Grid>
            </StackPanel>
        </Border>

        <UniformGrid Grid.Row="2" Columns="2" Margin="0,14,0,0">
            <Button x:Name="BtnLock" Content="🟢 开启安全锁（用 Claude 前点这里）" Background="#FF166534" BorderBrush="#FF22C55E" Foreground="#FFFFFFFF" Margin="0,0,8,10"/>
            <Button x:Name="BtnUnlock" Content="🟡 恢复直连模式（不用 Claude 点这里）" Background="#FF713F12" BorderBrush="#FFEAB308" Foreground="#FFFFFFFF" Margin="8,0,0,10"/>
            <Button x:Name="BtnInit" Content="⚙️ 一键初始化环境（锁时区/地区/英文/IPv6）" Background="#FF1D4ED8" BorderBrush="#FF3B82F6" Foreground="#FFFFFFFF" Margin="0,0,8,10"/>
            <Button x:Name="BtnCheck" Content="🔍 14维度深度体检（IP画像/DNS/WebRTC/TLS）" Margin="8,0,0,10"/>
            <Button x:Name="BtnExport" Content="📄 导出交机体检报告到桌面" Margin="0,0,8,0"/>
            <Button x:Name="BtnRefresh" Content="🔄 刷新当前安全锁状态" Margin="8,0,0,0"/>
        </UniformGrid>

        <Border Grid.Row="3" Background="#FF0F172A" BorderBrush="#FF22304A" BorderThickness="1" CornerRadius="12" Padding="12" Margin="0,14,0,0">
            <TextBox x:Name="OutputBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     Background="Transparent" Foreground="#FFDCE7F7" BorderThickness="0"
                     FontFamily="Consolas" FontSize="12" Text="欢迎使用 Claude 安全锁！&#x0A;&#x0A;首次交付：先在 Clash Verge (服务模式+TUN) 或 v2rayN (管理员+启用Tun) 中开启「全局 + TUN」，填入入口节点 IP 后点击「一键初始化环境」。&#x0A;日常使用：用 Claude 前点「开启安全锁」；不用 Claude 想恢复正常上网点「恢复直连模式」。"/>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [Windows.Markup.XamlReader]::Load($reader)

$statusPill = $win.FindName('StatusPill')
$statusText = $win.FindName('StatusText')
$statusSub  = $win.FindName('StatusSub')
$nodesInput = $win.FindName('NodesInput')
$outputBox  = $win.FindName('OutputBox')
$btnSave    = $win.FindName('BtnSaveNodes')
$btnLock    = $win.FindName('BtnLock')
$btnUnlock  = $win.FindName('BtnUnlock')
$btnInit    = $win.FindName('BtnInit')
$btnCheck   = $win.FindName('BtnCheck')
$btnExport  = $win.FindName('BtnExport')
$btnRefresh = $win.FindName('BtnRefresh')

function Invoke-GuardAction([string[]]$GuardArgs) {
    $res = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CORE @GuardArgs 2>&1 | Out-String).Trim()
    return $res
}

function Refresh-State {
    $raw = Invoke-GuardAction @('status')
    $map = @{}
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^([^=]+)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
    }
    $lock = $map['LOCK']
    $nodes = $map['ENTRY_NODES']
    $cc = $map['COUNTRY_TARGET']
    if ($nodes -and $nodes -ne '未配置' -and [string]::IsNullOrWhiteSpace($nodesInput.Text)) {
        $nodesInput.Text = $nodes
    }
    if ($lock -eq 'on') {
        $statusText.Text = '安全锁已开启'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF4ADE80'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#3322C55E'))
        $statusSub.Text = "物理网卡直连/IPv6/WebRTC/裸DNS已全部阻断 | 目标国家: $cc | 入口: $nodes"
    } else {
        $statusText.Text = '直连模式(未加锁)'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFFBBE24'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#33F59E0B'))
        $statusSub.Text = "当前允许直连上网；使用 Claude 前请先点击「开启安全锁」 | 目标国家: $cc"
    }
}

function Run-UiOp([string]$Title, [string[]]$GuardArgs) {
    $btnLock.IsEnabled = $false; $btnUnlock.IsEnabled = $false; $btnInit.IsEnabled = $false; $btnCheck.IsEnabled = $false; $btnSave.IsEnabled = $false; $btnExport.IsEnabled = $false; $btnRefresh.IsEnabled = $false
    $outputBox.Text = "正在执行: $Title ..."
    $win.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
    try {
        $out = Invoke-GuardAction $GuardArgs
        $outputBox.Text = $out
    } catch {
        $outputBox.Text = "执行失败: $($_.Exception.Message)"
    } finally {
        Refresh-State
        $btnLock.IsEnabled = $true; $btnUnlock.IsEnabled = $true; $btnInit.IsEnabled = $true; $btnCheck.IsEnabled = $true; $btnSave.IsEnabled = $true; $btnExport.IsEnabled = $true; $btnRefresh.IsEnabled = $true
    }
}

$btnSave.Add_Click({
    $n = $nodesInput.Text.Trim()
    if (-not $n) { $outputBox.Text = '请先输入代理入口节点 IP 或域名（链式代理填第一跳入口）。'; return }
    Run-UiOp '保存入口节点' @('set-nodes', $n)
})

$btnLock.Add_Click({
    $n = $nodesInput.Text.Trim()
    if ($n) { $null = Invoke-GuardAction @('set-nodes', $n) }
    Run-UiOp '开启安全锁' @('lock')
})

$btnUnlock.Add_Click({
    Run-UiOp '恢复直连模式' @('unlock')
})

$btnInit.Add_Click({
    $n = $nodesInput.Text.Trim()
    if (-not $n) { $outputBox.Text = '请先在上方输入框填入第一跳代理入口节点 IP 或域名，再点一键初始化。'; return }
    Run-UiOp '一键初始化环境并开启安全锁' @('init', $n)
})

$btnCheck.Add_Click({
    Run-UiOp '14 维度深度环境体检' @('check')
})

$btnExport.Add_Click({
    $dest = Join-Path ([Environment]::GetFolderPath('Desktop')) ("claude-env-report-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    Run-UiOp "导出交机体检报告到 $dest" @('export-report', $dest)
})

$btnRefresh.Add_Click({
    Refresh-State
    $outputBox.Text = '状态已刷新。'
})

$win.Add_ContentRendered({ Refresh-State })
$null = $win.ShowDialog()
