# Claude 持久化安全锁 · Windows 双锁图形控制台 (WPF 零依赖)
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$CORE = Join-Path $PSScriptRoot 'claude-guard.ps1'

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Claude 双锁安全控制台 · Windows"
        Width="740" Height="740" MinWidth="620" MinHeight="640"
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
                    <TextBlock Text="Claude 双锁持久化安全控制台（零泄露防线）" FontSize="17" FontWeight="Bold"/>
                    <TextBlock x:Name="StatusSub" Text="正在读取操作系统防火墙持久化状态..." FontSize="11" Foreground="#FF9AA9BF" Margin="0,6,0,0" TextWrapping="Wrap"/>
                </StackPanel>
                <Border x:Name="StatusPill" Grid.Column="1" VerticalAlignment="Center" CornerRadius="12" Padding="14,7" Background="#33F59E0B">
                    <TextBlock x:Name="StatusText" Text="检查中" FontSize="12" FontWeight="Bold" Foreground="#FFFBBE24"/>
                </Border>
            </Grid>
        </Border>

        <Border Grid.Row="1" Background="#FF131E31" BorderBrush="#FF2A3952" BorderThickness="1" CornerRadius="12" Padding="14" Margin="0,12,0,0">
            <StackPanel>
                <TextBlock Text="海外代理第一跳入口 IP / 域名（可选：链式代理若第一跳在国内中转机可留空；直连海外 VPS 请填 IP，多个逗号隔开）" FontSize="11" FontWeight="SemiBold" Foreground="#FF9AA9BF" TextWrapping="Wrap"/>
                <Grid Margin="0,8,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="NodesInput" Background="#FF162238" Foreground="#FFFFFFFF" BorderBrush="#FF334155" BorderThickness="1" Padding="10,7" FontSize="13" VerticalContentAlignment="Center"/>
                    <Button x:Name="BtnSaveNodes" Grid.Column="1" Content="保存白名单" MinHeight="34" Margin="10,0,0,0"/>
                </Grid>
            </StackPanel>
        </Border>

        <Border Grid.Row="2" Background="#FF101C30" BorderBrush="#FF24415E" BorderThickness="1" CornerRadius="12" Padding="14" Margin="0,12,0,0">
            <StackPanel>
                <TextBlock Text="🔒 锁 1：直连切换锁（无论切哪侧，Claude ASN/域名/进程与一切海外均 0ms 死锁，代理退出/软件被杀/重启不失效）" FontSize="11" FontWeight="Bold" Foreground="#FF93C5FD" TextWrapping="Wrap"/>
                <UniformGrid Columns="2" Margin="0,10,0,0">
                    <Button x:Name="BtnLockCn" Content="🟡 放行国内直连（但死锁 Claude 与一切海外 · 推荐）" Background="#FF854D0E" BorderBrush="#FFEAB308" Foreground="#FFFFFFFF" Margin="0,0,6,0"/>
                    <Button x:Name="BtnLockStrict" Content="🔒 全封闭模式（仅走海外 TUN，国内也全封）" Background="#FF166534" BorderBrush="#FF22C55E" Foreground="#FFFFFFFF" Margin="6,0,0,0"/>
                </UniformGrid>
            </StackPanel>
        </Border>

        <Border Grid.Row="3" Background="#FF241217" BorderBrush="#FF7F1D1D" BorderThickness="1" CornerRadius="12" Padding="14" Margin="0,12,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel VerticalAlignment="Center" Margin="0,0,12,0">
                    <TextBlock Text="🔐 锁 2：持久化硬锁总开关（高危解封）" FontSize="12" FontWeight="Bold" Foreground="#FFFCA5A5"/>
                    <TextBlock Text="仅当确定不再使用 Claude 时解开恢复原生网络。解开后千万不要启动任何 Claude 服务！" FontSize="11" Foreground="#FFE5B4B4" TextWrapping="Wrap" Margin="0,3,0,0"/>
                </StackPanel>
                <Button x:Name="BtnUnlockAll" Grid.Column="1" Content="🔓 解开持久化硬锁（恢复出厂）" Background="#FF991B1B" BorderBrush="#FFF87171" Foreground="#FFFFFFFF" MinHeight="38"/>
            </Grid>
        </Border>

        <UniformGrid Grid.Row="4" Columns="4" Margin="0,12,0,0">
            <Button x:Name="BtnInit" Content="⚙️ 一键初始化环境" Background="#FF1D4ED8" BorderBrush="#FF3B82F6" Foreground="#FFFFFFFF" Margin="0,0,6,0"/>
            <Button x:Name="BtnVerifyFw" Content="🛡️ 验收防火墙与日志" Margin="3,0,3,0"/>
            <Button x:Name="BtnCheck" Content="🔍 14维度深度体检" Margin="3,0,3,0"/>
            <Button x:Name="BtnExport" Content="📄 导出交机报告" Margin="6,0,0,0"/>
        </UniformGrid>

        <Border Grid.Row="5" Background="#FF0F172A" BorderBrush="#FF22304A" BorderThickness="1" CornerRadius="12" Padding="12" Margin="0,12,0,0">
            <TextBox x:Name="OutputBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     Background="Transparent" Foreground="#FFDCE7F7" BorderThickness="0"
                     FontFamily="Consolas" FontSize="12" Text="欢迎使用 Claude 双锁持久化安全控制台！&#x0A;&#x0A;1. 首次交付：在 Clash Verge(服务模式+TUN) 或 v2rayN(管理员+启用Tun) 开启「全局 + TUN」，点击「⚙️ 一键初始化环境」。&#x0A;2. 日常使用：锁 1 默认「放行国内直连 + 死锁 Claude 与海外」，即使关掉代理或退掉本软件，误点 Claude 也不会暴露本地 IP。&#x0A;3. 验收实证：点击「🛡️ 验收防火墙与日志」直接核查系统防火墙状态与 pfirewall.log 真实 DROP 拦截日志。"/>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [Windows.Markup.XamlReader]::Load($reader)

$statusPill    = $win.FindName('StatusPill')
$statusText    = $win.FindName('StatusText')
$statusSub     = $win.FindName('StatusSub')
$nodesInput    = $win.FindName('NodesInput')
$outputBox     = $win.FindName('OutputBox')
$btnSave       = $win.FindName('BtnSaveNodes')
$btnLockCn     = $win.FindName('BtnLockCn')
$btnLockStrict = $win.FindName('BtnLockStrict')
$btnUnlockAll  = $win.FindName('BtnUnlockAll')
$btnInit       = $win.FindName('BtnInit')
$btnVerifyFw   = $win.FindName('BtnVerifyFw')
$btnCheck      = $win.FindName('BtnCheck')
$btnExport     = $win.FindName('BtnExport')

$allBtns = @($btnSave, $btnLockCn, $btnLockStrict, $btnUnlockAll, $btnInit, $btnVerifyFw, $btnCheck, $btnExport)

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
    $nodes = $map['ENTRY_NODES']
    $cc = $map['COUNTRY_TARGET']
    if ($nodes -and $nodes -ne '未配置' -and [string]::IsNullOrWhiteSpace($nodesInput.Text)) { $nodesInput.Text = $nodes }
    if ($lock -eq 'on' -and $mode -eq 'strict') {
        $statusText.Text = '🔒 全封闭硬锁已扣死'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FF4ADE80'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#3322C55E'))
        $statusSub.Text = "锁1=全封闭(仅海外TUN) + 锁2=持久化硬锁生效(退出/重启不失效) | 目标国: $cc"
    } elseif ($lock -eq 'on') {
        $statusText.Text = '🟡 国内放行 · 海外/Claude死锁'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFFACC15'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#33EAB308'))
        $statusSub.Text = "锁1=国内直连放行(Claude ASN/域名/进程与一切海外 0ms 死锁) + 锁2=持久化生效 | 目标国: $cc"
    } else {
        $statusText.Text = '🔓 锁2已解开(原生直连)'
        $statusText.Foreground = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#FFF87171'))
        $statusPill.Background = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString('#33F87171'))
        $statusSub.Text = "⚠️ 持久化硬锁未开启！请勿启动任何 Claude 服务 | 目标国: $cc"
    }
}

function Run-UiOp([string]$Title, [string[]]$GuardArgs) {
    foreach ($b in $allBtns) { $b.IsEnabled = $false }
    $outputBox.Text = "正在执行: $Title ..."
    $win.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
    try {
        $outputBox.Text = Invoke-GuardAction $GuardArgs
    } catch {
        $outputBox.Text = "执行失败: $($_.Exception.Message)"
    } finally {
        Refresh-State
        foreach ($b in $allBtns) { $b.IsEnabled = $true }
    }
}

$btnSave.Add_Click({ Run-UiOp '保存海外入口白名单' @('set-nodes', $nodesInput.Text.Trim()) })

$btnLockCn.Add_Click({
    $n = $nodesInput.Text.Trim()
    if ($n) { $null = Invoke-GuardAction @('set-nodes', $n) }
    Run-UiOp '【锁1】切换为国内直连放行 + 死锁 Claude 与一切海外' @('lock-cn')
})

$btnLockStrict.Add_Click({
    $n = $nodesInput.Text.Trim()
    if (-not $n) { $outputBox.Text = '开启全封闭模式前，请先在上方填入第一跳代理入口 IP 或域名！'; return }
    $null = Invoke-GuardAction @('set-nodes', $n)
    Run-UiOp '【锁1】切换为全封闭模式 (仅海外 TUN)' @('lock-strict')
})

$btnUnlockAll.Add_Click({
    $msg = "确定要解开【锁 2：持久化硬锁】并恢复电脑原生直连网络吗？`n`n⚠️ 重要安全警告：`n1. 本软件将先自动关闭正在运行的 Claude 桌面版与 Claude Code CLI；`n2. 解开后电脑将完全恢复到未安装本软件时的直连状态；`n3. 解开后【千万不要】启动 Claude 桌面版、网页版或 Claude Code CLI 的任何服务，否则将立即暴露本地直连 IP！"
    $ans = [System.Windows.MessageBox]::Show($msg, '⚠️ 高危确认：解开持久化硬锁', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
    if ($ans -eq [System.Windows.MessageBoxResult]::Yes) {
        Run-UiOp '【锁2】解开持久化硬锁并恢复出厂网络' @('unlock-all')
    }
})

$btnInit.Add_Click({ Run-UiOp '一键初始化环境并扣死持久化硬锁' @('init', $nodesInput.Text.Trim()) })
$btnVerifyFw.Add_Click({ Run-UiOp '验收操作系统防火墙与 pfirewall.log 流量拦截日志' @('verify-firewall') })
$btnCheck.Add_Click({ Run-UiOp '14 维度深度环境体检' @('check') })
$btnExport.Add_Click({
    $dest = Join-Path ([Environment]::GetFolderPath('Desktop')) ("claude-env-report-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
    Run-UiOp "导出交机体检报告到 $dest" @('export-report', $dest)
})

$win.Add_ContentRendered({ Refresh-State })
$null = $win.ShowDialog()
