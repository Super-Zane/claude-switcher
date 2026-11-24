# Claude 持久化安全锁 · Windows Claude 品牌暖米风格三态防呆亮灯控制台 (v2.2)
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$CORE  = Join-Path $PSScriptRoot 'claude-guard.ps1'
$AUDIT = Join-Path $PSScriptRoot 'env-audit.ps1'
$CFG   = Join-Path $env:USERPROFILE '.claude-guard\config.json'

$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Claude 安全锁"
        Width="880" Height="760" MinWidth="780" MinHeight="660"
        WindowStartupLocation="CenterScreen"
        Background="#FFFAF9F5" Foreground="#FF1F1E1D" FontFamily="Microsoft YaHei UI, Segoe UI">
    <Window.Resources>
        <Style x:Key="SoftBtn" TargetType="Button">
            <Setter Property="Background" Value="#FFFFFFFF"/>
            <Setter Property="Foreground" Value="#FF1F1E1D"/>
            <Setter Property="BorderBrush" Value="#FFE7E2D8"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="MinHeight" Value="34"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="AccentBtn" TargetType="Button" BasedOn="{StaticResource SoftBtn}">
            <Setter Property="Background" Value="#FFD97757"/>
            <Setter Property="Foreground" Value="#FFFFFFFF"/>
            <Setter Property="BorderBrush" Value="#FFC26142"/>
        </Style>
    </Window.Resources>

    <Grid Margin="22,16,22,14">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- 顶部 Claude 品牌 Header -->
        <Grid Grid.Row="0" Margin="0,0,0,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Width="44" Height="44" CornerRadius="12" Background="#FFD97757" Margin="0,0,12,0">
                <TextBlock Text="🛡" FontSize="22" HorizontalAlignment="Center" VerticalAlignment="Center" Foreground="#FFFFFFFF"/>
            </Border>
            <StackPanel Grid.Column="1" VerticalAlignment="Center">
                <StackPanel Orientation="Horizontal">
                    <TextBlock Text="Claude 安全锁" FontSize="19" FontWeight="Bold" Foreground="#FF1F1E1D"/>
                    <Border Background="#1FD97757" CornerRadius="8" Padding="6,2" Margin="8,0,0,0" VerticalAlignment="Center">
                        <TextBlock Text="v2.2" FontSize="10.5" FontWeight="SemiBold" Foreground="#FFD97757"/>
                    </Border>
                </StackPanel>
                <TextBlock x:Name="StatusSub" Text="正在读取操作系统防火墙与全版本进程守卫状态..." FontSize="11.5" Foreground="#FF6B665E" Margin="0,3,0,0" TextTrimming="CharacterEllipsis"/>
            </StackPanel>
            <Border x:Name="StatusPill" Grid.Column="2" VerticalAlignment="Center" CornerRadius="14" Padding="12,6" Background="#FFF1F2F4">
                <StackPanel Orientation="Horizontal">
                    <Ellipse x:Name="StatusDot" Width="9" Height="9" Fill="#FF9CA3AF" VerticalAlignment="Center" Margin="0,0,7,0"/>
                    <TextBlock x:Name="StatusText" Text="检查中" FontSize="12" FontWeight="SemiBold" Foreground="#FF6B665E"/>
                </StackPanel>
            </Border>
        </Grid>

        <!-- 二级放宽锁高危红幅警示条 -->
        <Border x:Name="RelaxWarnBanner" Grid.Row="1" Visibility="Collapsed" Background="#FFFEE2E2" BorderBrush="#FFFCA5A5" BorderThickness="1" CornerRadius="10" Padding="12,8" Margin="0,0,0,10">
            <TextBlock Text="🚨 高危提醒：此时电脑没有全网防护！请不要打开任何与 Claude 相关的服务，包括电子邮件里不要点击 Claude 发来的任何电子邮件和链接！（底层 Claude 全版本进程锁与遥测黑洞仍在保护中）" FontSize="11.5" FontWeight="Bold" Foreground="#FFDC2626" TextWrapping="Wrap"/>
        </Border>

        <!-- 主控卡片: 一级安全锁 + 一键初始化 + 入口IP + 二级放宽锁 -->
        <Border Grid.Row="2" Background="#FFFFFFFF" BorderBrush="#FFE7E2D8" BorderThickness="1" CornerRadius="14" Padding="13">
            <StackPanel>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <Button x:Name="BtnToggleLock" Grid.Column="0" Style="{StaticResource AccentBtn}" MinHeight="52" HorizontalContentAlignment="Left" Padding="16,10">
                        <StackPanel>
                            <TextBlock x:Name="ToggleTitle" Text="🔒 开启一级安全锁（100% 流量强制只走 TUN · 解锁 Claude）" FontSize="13.5" FontWeight="Bold" Foreground="#FFFFFFFF"/>
                            <TextBlock x:Name="ToggleDesc" Text="配合代理全局 + TUN 使用，物理网卡一切国内外公网/裸DNS/IPv6/STUN 全部 0ms 拦截" FontSize="10.5" Foreground="#FFFDF6F3" Margin="0,2,0,0"/>
                        </StackPanel>
                    </Button>
                    <Button x:Name="BtnInit" Grid.Column="1" Style="{StaticResource SoftBtn}" Background="#FFF3EFE6" Width="112" MinHeight="52" Margin="10,0,0,0" Content="✨ 一键初始化"/>
                </Grid>

                <Border Height="1" Background="#FFE7E2D8" Margin="0,11,0,10"/>

                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Grid.Column="0" Text="第一跳入口 IP" FontSize="12" FontWeight="SemiBold" Foreground="#FF1F1E1D" VerticalAlignment="Center" Margin="0,0,8,0"/>
                    <TextBox x:Name="NodesInput" Grid.Column="1" Background="#FFFAF9F5" Foreground="#FF1F1E1D" BorderBrush="#FFE7E2D8" BorderThickness="1" Padding="8,5" FontSize="12" VerticalContentAlignment="Center" ToolTip="留空自动识别当前活跃代理连接 IP；或手动填写第一跳节点 IP（逗号分隔）"/>
                    <Button x:Name="BtnSaveNodes" Grid.Column="2" Style="{StaticResource SoftBtn}" Background="#FFF3EFE6" Content="保存" MinHeight="30" Padding="12,4" Margin="8,0,10,0"/>
                    <Button x:Name="BtnRelaxLock" Grid.Column="3" Style="{StaticResource SoftBtn}" Background="#FFFEE2E2" BorderBrush="#FFFCA5A5" Foreground="#FFDC2626" Content="⚠ 二级放宽锁（防国内误伤）" MinHeight="30" Padding="12,4"/>
                </Grid>

                <Border x:Name="ToastBar" Visibility="Collapsed" Background="#FFF3EFE6" CornerRadius="8" Padding="10,6" Margin="0,10,0,0">
                    <TextBlock x:Name="ToastText" Text="" FontSize="11.5" FontWeight="SemiBold" Foreground="#FF1F1E1D" TextWrapping="Wrap"/>
                </Border>
            </StackPanel>
        </Border>

        <!-- 工具栏 -->
        <Grid Grid.Row="3" Margin="0,12,0,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>
            <StackPanel Grid.Column="0" Orientation="Horizontal">
                <Button x:Name="BtnTabDash" Style="{StaticResource AccentBtn}" Content="亮灯仪表盘" MinHeight="32" Padding="12,4"/>
                <Button x:Name="BtnTabLog" Style="{StaticResource SoftBtn}" Content="防火墙与执行日志" MinHeight="32" Padding="12,4" Margin="6,0,0,0"/>
            </StackPanel>
            <Border x:Name="SummaryBadge" Grid.Column="1" Visibility="Collapsed" Background="#FFF3EFE6" CornerRadius="10" Padding="10,4" Margin="10,0,0,0" VerticalAlignment="Center">
                <TextBlock x:Name="SummaryText" Text="" FontSize="11" FontWeight="SemiBold" Foreground="#FF1F1E1D"/>
            </Border>
            <StackPanel Grid.Column="3" Orientation="Horizontal">
                <Button x:Name="BtnEmergency" Style="{StaticResource SoftBtn}" Content="🚑 急救指南" MinHeight="32" Margin="0,0,6,0"/>
                <Button x:Name="BtnVerifyFw" Style="{StaticResource SoftBtn}" Content="🛡 验收防火墙日志" MinHeight="32" Margin="0,0,6,0"/>
                <Button x:Name="BtnExport" Style="{StaticResource SoftBtn}" Content="📄 导出报告" MinHeight="32" Margin="0,0,6,0"/>
                <Button x:Name="BtnCheck" Style="{StaticResource AccentBtn}" Content="⚡ 一键全面体检" MinHeight="32"/>
            </StackPanel>
        </Grid>

        <!-- 下半区: 14 项亮灯卡片网格 / 日志视图 -->
        <ScrollViewer x:Name="DashScroll" Grid.Row="4" VerticalScrollBarVisibility="Auto">
            <UniformGrid x:Name="LampGrid" Columns="2" VerticalAlignment="Top"/>
        </ScrollViewer>

        <Border x:Name="LogPanel" Grid.Row="4" Visibility="Collapsed" Background="#FFFFFFFF" BorderBrush="#FFE7E2D8" BorderThickness="1" CornerRadius="12" Padding="12">
            <TextBox x:Name="OutputBox" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto"
                     Background="Transparent" Foreground="#FF1F1E1D" BorderThickness="0"
                     FontFamily="Consolas" FontSize="12" Text="欢迎使用 Claude 持久化安全锁 v2.2！&#x0A;&#x0A;• 首次交付：开启 Clash Verge(服务模式+TUN+全局) 或 v2rayN(管理员+启用Tun+全局)，点击「一键初始化」。&#x0A;• 一级安全锁开启：100% 公网流量强制只走 TUN，安心使用 Claude。&#x0A;• 一级安全锁关闭：弹窗确认并自动退出 Claude，切回国内白名单直连网络，持续死锁海外与 Claude 全版本进程。&#x0A;• 二级放宽锁：仅当国内未收录流量被误伤时使用（底层 Claude 全版本进程与 34 个遥测/邮件链接黑洞依然永久锁定）。"/>
        </Border>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$win = [Windows.Markup.XamlReader]::Load($reader)

$statusPill      = $win.FindName('StatusPill')
$statusDot       = $win.FindName('StatusDot')
$statusText      = $win.FindName('StatusText')
$statusSub       = $win.FindName('StatusSub')
$relaxWarnBanner = $win.FindName('RelaxWarnBanner')
$btnToggleLock   = $win.FindName('BtnToggleLock')
$toggleTitle     = $win.FindName('ToggleTitle')
$toggleDesc      = $win.FindName('ToggleDesc')
$btnInit         = $win.FindName('BtnInit')
$nodesInput      = $win.FindName('NodesInput')
$btnSave         = $win.FindName('BtnSaveNodes')
$btnRelaxLock    = $win.FindName('BtnRelaxLock')
$toastBar        = $win.FindName('ToastBar')
$toastText       = $win.FindName('ToastText')
$btnTabDash      = $win.FindName('BtnTabDash')
$btnTabLog       = $win.FindName('BtnTabLog')
$summaryBadge    = $win.FindName('SummaryBadge')
$summaryText     = $win.FindName('SummaryText')
$btnEmergency    = $win.FindName('BtnEmergency')
$btnVerifyFw     = $win.FindName('BtnVerifyFw')
$btnExport       = $win.FindName('BtnExport')
$btnCheck        = $win.FindName('BtnCheck')
$dashScroll      = $win.FindName('DashScroll')
$lampGrid        = $win.FindName('LampGrid')
$logPanel        = $win.FindName('LogPanel')
$outputBox       = $win.FindName('OutputBox')

$allBtns = @($btnToggleLock, $btnInit, $btnSave, $btnRelaxLock, $btnEmergency, $btnVerifyFw, $btnExport, $btnCheck)
$script:currentLock = 'off'

function New-Brush([string]$Hex) {
    return (New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.ColorConverter]::ConvertFromString($Hex)))
}

function Show-Toast([string]$Msg, [bool]$IsError = $false) {
    $toastBar.Visibility = [Windows.Visibility]::Visible
    $toastText.Text = $Msg
    if ($IsError) {
        $toastBar.Background = New-Brush '#FFFEE2E2'; $toastText.Foreground = New-Brush '#FFDC2626'
    } else {
        $toastBar.Background = New-Brush '#FFF3EFE6'; $toastText.Foreground = New-Brush '#FF1F1E1D'
    }
}

function Set-ActiveTab([string]$Tab) {
    if ($Tab -eq 'log') {
        $dashScroll.Visibility = [Windows.Visibility]::Collapsed
        $logPanel.Visibility = [Windows.Visibility]::Visible
        $btnTabLog.Background = New-Brush '#FFD97757'; $btnTabLog.Foreground = New-Brush '#FFFFFFFF'
        $btnTabDash.Background = New-Brush '#FFFFFFFF'; $btnTabDash.Foreground = New-Brush '#FF1F1E1D'
    } else {
        $dashScroll.Visibility = [Windows.Visibility]::Visible
        $logPanel.Visibility = [Windows.Visibility]::Collapsed
        $btnTabDash.Background = New-Brush '#FFD97757'; $btnTabDash.Foreground = New-Brush '#FFFFFFFF'
        $btnTabLog.Background = New-Brush '#FFFFFFFF'; $btnTabLog.Foreground = New-Brush '#FF1F1E1D'
    }
}

function Render-AuditCards($Items) {
    $lampGrid.Children.Clear()
    foreach ($it in $Items) {
        $st = [string]$it.state
        $dotHex = '#FF9CA3AF'; $bgHex = '#FFF1F2F4'; $fgHex = '#FF6B665E'; $label = '待测'; $bdHex = '#FFE7E2D8'
        if ($st -eq 'ok')      { $dotHex = '#FF16A34A'; $bgHex = '#FFDCFCE7'; $fgHex = '#FF16A34A'; $label = '通过' }
        elseif ($st -eq 'warn'){ $dotHex = '#FFD97706'; $bgHex = '#FFFEF3C7'; $fgHex = '#FFD97706'; $label = '警告' }
        elseif ($st -eq 'fail'){ $dotHex = '#FFDC2626'; $bgHex = '#FFFEE2E2'; $fgHex = '#FFDC2626'; $label = '异常'; $bdHex = '#FFFCA5A5' }
        elseif ($st -eq 'unknown') { $label = '未知' }

        $card = New-Object Windows.Controls.Border
        $card.Background = New-Brush '#FFFFFFFF'; $card.BorderBrush = New-Brush $bdHex
        $card.BorderThickness = New-Object Windows.Thickness(1)
        $card.CornerRadius = New-Object Windows.CornerRadius(10)
        $card.Padding = New-Object Windows.Thickness(11, 8, 11, 8)
        $card.Margin = New-Object Windows.Thickness(4)

        $g = New-Object Windows.Controls.Grid
        $c0 = New-Object Windows.Controls.ColumnDefinition; $c0.Width = [Windows.GridLength]::Auto
        $c1 = New-Object Windows.Controls.ColumnDefinition; $c1.Width = New-Object Windows.GridLength(1, [Windows.GridUnitType]::Star)
        $g.ColumnDefinitions.Add($c0); $g.ColumnDefinitions.Add($c1)

        $lampWrap = New-Object Windows.Controls.Border
        $lampWrap.Width = 20; $lampWrap.Height = 20; $lampWrap.CornerRadius = New-Object Windows.CornerRadius(10)
        $lampWrap.Background = New-Brush $bgHex; $lampWrap.VerticalAlignment = 'Top'; $lampWrap.Margin = New-Object Windows.Thickness(0, 1, 9, 0)
        $dot = New-Object Windows.Shapes.Ellipse
        $dot.Width = 10; $dot.Height = 10; $dot.Fill = New-Brush $dotHex
        $lampWrap.Child = $dot
        [Windows.Controls.Grid]::SetColumn($lampWrap, 0); $null = $g.Children.Add($lampWrap)

        $sp = New-Object Windows.Controls.StackPanel
        $hdr = New-Object Windows.Controls.DockPanel
        $badge = New-Object Windows.Controls.Border
        $badge.Background = New-Brush $bgHex; $badge.CornerRadius = New-Object Windows.CornerRadius(7)
        $badge.Padding = New-Object Windows.Thickness(6, 1, 6, 1)
        [Windows.Controls.DockPanel]::SetDock($badge, 'Right')
        $bTxt = New-Object Windows.Controls.TextBlock
        $bTxt.Text = $label; $bTxt.FontSize = 10.5; $bTxt.FontWeight = 'SemiBold'; $bTxt.Foreground = New-Brush $fgHex
        $badge.Child = $bTxt; $null = $hdr.Children.Add($badge)

        $title = New-Object Windows.Controls.TextBlock
        $title.Text = [string]$it.name; $title.FontSize = 12.5; $title.FontWeight = 'SemiBold'; $title.Foreground = New-Brush '#FF1F1E1D'
        $title.TextTrimming = 'CharacterEllipsis'
        $null = $hdr.Children.Add($title); $null = $sp.Children.Add($hdr)

        $det = New-Object Windows.Controls.TextBlock
        $det.Text = [string]$it.detail; $det.FontSize = 11; $det.Foreground = New-Brush '#FF6B665E'
        $det.TextWrapping = 'Wrap'; $det.Margin = New-Object Windows.Thickness(0, 3, 0, 0)
        $null = $sp.Children.Add($det)

        [Windows.Controls.Grid]::SetColumn($sp, 1); $null = $g.Children.Add($sp)
        $card.Child = $g; $null = $lampGrid.Children.Add($card)
    }
}

$defaultItems = @(
    @{ name = '持久化安全锁 (WFP 防火墙)'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '全局 TUN 与默认路由'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '本地与上游 DNS 泄露'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '代理环境变量与 PAC'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '多源出口 IP 共识'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'Anthropic 地区合规'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'IP 纯净度与 ASN 画像'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'WebRTC / STUN 泄露'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '时区 / 地区 / 语言'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = '全网卡 IPv6 封锁'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'Anthropic 多端点延迟'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'TLS 证书与 MITM 校验'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'WebSocket 隧道握手'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' },
    @{ name = 'Claude 客户端与变量'; state = 'pending'; detail = '点击「一键全面体检」开始实时检测' }
)
Render-AuditCards $defaultItems

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
    $wdOn = $map['PERSISTENT_LOCK']
    $nodes = $map['ENTRY_NODES']
    $cc = $map['COUNTRY_TARGET']
    $script:currentLock = $lock

    if ($nodes -and $nodes -ne '未配置' -and [string]::IsNullOrWhiteSpace($nodesInput.Text)) { $nodesInput.Text = $nodes }
    $relaxWarnBanner.Visibility = if ($lock -eq 'relax') { [Windows.Visibility]::Visible } else { [Windows.Visibility]::Collapsed }

    if ($lock -eq 'on') {
        $statusText.Text = '一级安全锁已开启'; $statusText.Foreground = New-Brush '#FF16A34A'
        $statusDot.Fill = New-Brush '#FF16A34A'; $statusPill.Background = New-Brush '#FFDCFCE7'
        $statusSub.Text = "100% 公网流量强制只走 TUN · Claude 已放行 · 自愈守卫=$wdOn | 目标国: $cc"
        $toggleTitle.Text = '🟡 关闭一级安全锁（弹窗确认并退出 Claude → 恢复国内网络）'
        $toggleDesc.Text = '关闭后放行国内白名单网络，海外与 Claude 遥测持续阻断，Claude 全版本进程自动锁死'
        $btnToggleLock.Background = New-Brush '#FFD97706'; $btnToggleLock.BorderBrush = New-Brush '#FFB45309'
        $btnRelaxLock.Content = '⚠ 二级放宽锁（防国内误伤）'
        $btnRelaxLock.Background = New-Brush '#FFFEE2E2'; $btnRelaxLock.Foreground = New-Brush '#FFDC2626'
    } elseif ($lock -eq 'cn') {
        $statusText.Text = '国内白名单直连态'; $statusText.Foreground = New-Brush '#FFD97706'
        $statusDot.Fill = New-Brush '#FFD97706'; $statusPill.Background = New-Brush '#FFFEF3C7'
        $statusSub.Text = "Claude 全版本进程已锁死 + 海外与 34 个遥测域名持续阻断 | 目标国: $cc"
        $toggleTitle.Text = '🔒 开启一级安全锁（100% 流量强制只走 TUN · 解锁 Claude）'
        $toggleDesc.Text = '配合全局 + TUN 使用，物理网卡一切国内外公网/裸DNS/IPv6/STUN 全部 0ms 拦截'
        $btnToggleLock.Background = New-Brush '#FFD97757'; $btnToggleLock.BorderBrush = New-Brush '#FFC26142'
        $btnRelaxLock.Content = '⚠ 二级放宽锁（防国内误伤）'
        $btnRelaxLock.Background = New-Brush '#FFFEE2E2'; $btnRelaxLock.Foreground = New-Brush '#FFDC2626'
    } elseif ($lock -eq 'relax') {
        $statusText.Text = '二级放宽锁已打开'; $statusText.Foreground = New-Brush '#FFDC2626'
        $statusDot.Fill = New-Brush '#FFDC2626'; $statusPill.Background = New-Brush '#FFFEE2E2'
        $statusSub.Text = "⚠️ 无全网防护！严禁打开任何 Claude 服务或点击 Claude 邮件链接（底层进程与遥测黑洞仍锁定）"
        $toggleTitle.Text = '🔒 开启一级安全锁（100% 流量强制只走 TUN · 解锁 Claude）'
        $toggleDesc.Text = '点击立刻关闭放宽态并恢复 100% 全走 TUN 最高防护'
        $btnToggleLock.Background = New-Brush '#FFD97757'; $btnToggleLock.BorderBrush = New-Brush '#FFC26142'
        $btnRelaxLock.Content = '关闭二级放宽锁（恢复拦截）'
        $btnRelaxLock.Background = New-Brush '#FFDC2626'; $btnRelaxLock.Foreground = New-Brush '#FFFFFFFF'
    } else {
        $statusText.Text = '尚未初始化'; $statusText.Foreground = New-Brush '#FF6B665E'
        $statusDot.Fill = New-Brush '#FF9CA3AF'; $statusPill.Background = New-Brush '#FFF1F2F4'
        $statusSub.Text = '请先打开代理客户端「全局 + TUN」，再点击右侧「一键初始化」'
        $toggleTitle.Text = '🔒 开启一级安全锁（100% 流量强制只走 TUN · 解锁 Claude）'
        $toggleDesc.Text = '配合全局 + TUN 使用，物理网卡一切国内外公网/裸DNS/IPv6/STUN 全部 0ms 拦截'
        $btnToggleLock.Background = New-Brush '#FFD97757'; $btnToggleLock.BorderBrush = New-Brush '#FFC26142'
    }
}

function Run-UiOp([string]$Title, [string[]]$GuardArgs, [bool]$OpenLog = $false) {
    foreach ($b in $allBtns) { $b.IsEnabled = $false }
    Show-Toast "正在执行: $Title ..." $false
    $win.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
    try {
        $res = Invoke-GuardAction $GuardArgs
        $outputBox.Text = $res
        if ($OpenLog) { Set-ActiveTab 'log' }
        $isFail = ($res -match 'FAIL:' -or $res -match '\[✗\]')
        $lastLine = (($res -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 1)
        Show-Toast $(if ($lastLine) { $lastLine } else { "$Title 完成" }) $isFail
    } catch {
        $outputBox.Text = "执行失败: $($_.Exception.Message)"
        Show-Toast "执行失败: $($_.Exception.Message)" $true
    } finally {
        Refresh-State
        foreach ($b in $allBtns) { $b.IsEnabled = $true }
    }
}

function Run-FullAudit {
    foreach ($b in $allBtns) { $b.IsEnabled = $false }
    Set-ActiveTab 'dash'
    Show-Toast '正在并发执行 14 维度深度体检（IP 画像 / isp.ac DNS 泄露 / WebRTC / TLS / 延迟）...' $false
    $win.Dispatcher.Invoke([action]{}, [Windows.Threading.DispatcherPriority]::Background)
    try {
        $raw = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $AUDIT -ConfigPath $CFG -Json 2>&1 | Out-String).Trim()
        $data = $raw | ConvertFrom-Json
        Render-AuditCards $data.items
        $summaryBadge.Visibility = [Windows.Visibility]::Visible
        $summaryText.Text = "● $($data.summary.ok) 通过  ● $($data.summary.warn) 警告  ● $($data.summary.fail) 异常  |  覆盖 $($data.coverage_percent)%"
        if ([int]$data.summary.fail -eq 0) {
            Show-Toast "体检完成：$($data.summary.ok) 项绿灯通过，0 项高危异常（覆盖率 $($data.coverage_percent)%）" $false
        } else {
            Show-Toast "体检检出 $($data.summary.fail) 项红灯异常，请优先排查红灯卡片！" $true
        }
    } catch {
        $outputBox.Text = "体检输出解析异常:`r`n$raw`r`n$($_.Exception.Message)"
        Set-ActiveTab 'log'
        Show-Toast '体检执行异常，请查看执行日志' $true
    } finally {
        Refresh-State
        foreach ($b in $allBtns) { $b.IsEnabled = $true }
    }
}

$btnTabDash.Add_Click({ Set-ActiveTab 'dash' })
$btnTabLog.Add_Click({ Set-ActiveTab 'log' })

$btnToggleLock.Add_Click({
    if ($script:currentLock -eq 'on') {
        $msg = "确定要关闭一级安全锁并切换回国内网络吗？`n`n关闭时系统将自动执行：`n1. 立即退出正在运行的 Claude 桌面版、所有 Helper 与 Claude Code CLI；`n2. 切换为国内白名单直连网络，但一切海外与 Claude 遥测服务器仍持续阻断；`n3. Claude 全版本进程将被系统锁死，再次使用前请先开启一级安全锁。"
        $ans = [System.Windows.MessageBox]::Show($msg, '确认关闭一级安全锁并退出 Claude', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
        if ($ans -eq [System.Windows.MessageBoxResult]::Yes) {
            Run-UiOp '退出 Claude 并切换为国内白名单网络' @('unlock') $false
        }
    } else {
        $n = $nodesInput.Text.Trim()
        if ($n) { $null = Invoke-GuardAction @('set-nodes', $n) }
        Run-UiOp '开启一级安全锁 (100% 流量强制只走 TUN)' @('lock') $false
    }
})

$btnRelaxLock.Add_Click({
    if ($script:currentLock -eq 'relax') {
        Run-UiOp '关闭二级放宽锁 (恢复国内白名单与海外封锁)' @('unlock') $false
    } else {
        $msg = "⚠️ 警告：打开二级放宽锁后，此时电脑没有防护！`n`n为防止误伤国内规则未收录的流量，普通公网防火墙规则将被放宽。`n`n🚨 请务必遵守：在此期间请不要打开任何与 Claude 相关的服务，包括在电子邮件里不要点击 Claude 发来的电子邮件和 Claude 发来的任何链接！`n`n（注：底层 Claude 全版本进程锁与遥测黑洞仍将保持锁定，直到彻底卸载本软件。）"
        $ans = [System.Windows.MessageBox]::Show($msg, '⚠️ 高危警告：打开二级放宽锁', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
        if ($ans -eq [System.Windows.MessageBoxResult]::Yes) {
            Run-UiOp '打开二级放宽锁 (保持底层 Claude 进程与遥测黑洞锁定)' @('relax') $false
        }
    }
})

$btnSave.Add_Click({
    $n = $nodesInput.Text.Trim()
    Run-UiOp '保存第一跳代理入口白名单' @('set-nodes', $n) $false
    if ($script:currentLock -eq 'on') { Run-UiOp '同步白名单到防火墙' @('lock') $false }
})

$btnEmergency.Add_Click({ Run-UiOp '生成桌面《断网急救.txt》' @('write-emergency') $false })
$btnInit.Add_Click({
    Run-UiOp '一键初始化环境' @('init', $nodesInput.Text.Trim()) $false
    Run-FullAudit
})
$btnVerifyFw.Add_Click({ Run-UiOp '验收系统防火墙、全版本进程守卫与 DROP 日志' @('verify-firewall') $true })
$btnCheck.Add_Click({ Run-FullAudit })
$btnExport.Add_Click({ Run-UiOp '导出脱敏交机体检报告到桌面' @('export-report') $false })

$win.Add_Loaded({ Refresh-State })
$null = $win.ShowDialog()
