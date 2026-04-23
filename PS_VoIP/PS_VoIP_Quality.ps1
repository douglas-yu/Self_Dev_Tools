Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms

# XAML UI
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NetQuality-PS - VoIP Network Assessment"
        Height="650" Width="950"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <TextBlock Grid.Row="0" Text="NetQuality-PS  (ICMP / TCP / UDP network assessment)"
               FontSize="16" FontWeight="Bold" Margin="0,0,0,8"/>

    <!-- Controls -->
    <StackPanel Grid.Row="1" Orientation="Vertical" Margin="0,0,0,8">
      <WrapPanel Margin="0,0,0,4">
        <TextBlock Text="Target Host/IP:" VerticalAlignment="Center" Width="100"/>
        <TextBox x:Name="txtTarget" Width="200" Text="8.8.8.8" Margin="4,0,16,0"/>

        <TextBlock Text="Port (TCP/UDP):" VerticalAlignment="Center" Width="110"/>
        <TextBox x:Name="txtPort" Width="70" Text="5060" Margin="4,0,16,0"/>

        <TextBlock Text="Probes / Iterations:" VerticalAlignment="Center" Width="120"/>
        <TextBox x:Name="txtCount" Width="60" Text="100" Margin="4,0,16,0"/>

        <TextBlock Text="Interval (ms):" VerticalAlignment="Center" Width="90"/>
        <TextBox x:Name="txtInterval" Width="60" Text="50" Margin="4,0,16,0"/>

        <TextBlock Text="Timeout (ms, ICMP):" VerticalAlignment="Center" Width="120"/>
        <TextBox x:Name="txtTimeout" Width="70" Text="1000" Margin="4,0,16,0"/>
      </WrapPanel>

      <WrapPanel Margin="0,0,0,4">
        <TextBlock Text="Test Type:" VerticalAlignment="Center" Width="100"/>
        <ComboBox x:Name="cmbTestType" Width="200" SelectedIndex="0" Margin="4,0,16,0">
          <ComboBoxItem Content="ICMP VoIP (latency/jitter/loss/MOS)"/>
          <ComboBoxItem Content="TCP Load (single connection, repeated writes)"/>
          <ComboBoxItem Content="UDP Load (fire-and-forget)"/>
        </ComboBox>

        <TextBlock Text="Description:" VerticalAlignment="Center" Width="90"/>
        <TextBox x:Name="txtDescription" Width="350" Height="40"
                 Text="Quick network assessment"
                 TextWrapping="Wrap" AcceptsReturn="True" Margin="4,0,0,0"/>
      </WrapPanel>

      <WrapPanel Margin="0,4,0,0">
        <Button x:Name="btnStart" Content="Start Test" Width="100" Margin="0,0,8,0"/>
        <Button x:Name="btnStop"  Content="Stop" Width="80" IsEnabled="False" Margin="0,0,8,0"/>
        <Button x:Name="btnExport" Content="Export CSV" Width="100" IsEnabled="False" Margin="0,0,8,0"/>
        <TextBlock x:Name="lblStatus" Margin="16,0,0,0" VerticalAlignment="Center"
                   Foreground="DarkGreen"/>
      </WrapPanel>
    </StackPanel>

    <!-- Progress -->
    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,8">
      <TextBlock Text="Progress:" VerticalAlignment="Center" Width="70"/>
      <ProgressBar x:Name="pbProgress" Width="400" Height="18"
                   Minimum="0" Maximum="100" Margin="4,0,8,0"/>
      <TextBlock x:Name="lblProgress" VerticalAlignment="Center" Width="100"/>
    </StackPanel>

    <!-- Results grid -->
    <DataGrid x:Name="dgResults" Grid.Row="3" Margin="0,0,0,8"
              AutoGenerateColumns="True" IsReadOnly="True"
              CanUserAddRows="False" CanUserDeleteRows="False"
              HeadersVisibility="Column" />

    <!-- Summary -->
    <GroupBox Grid.Row="4" Header="Summary (VoIP / load view)">
      <TextBlock x:Name="txtSummary" Margin="6" TextWrapping="Wrap"/>
    </GroupBox>
  </Grid>
</Window>
'@

$reader  = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$window  = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$txtTarget     = $window.FindName("txtTarget")
$txtPort       = $window.FindName("txtPort")
$txtCount      = $window.FindName("txtCount")
$txtInterval   = $window.FindName("txtInterval")
$txtTimeout    = $window.FindName("txtTimeout")
$cmbTestType   = $window.FindName("cmbTestType")
$txtDescription= $window.FindName("txtDescription")
$btnStart      = $window.FindName("btnStart")
$btnStop       = $window.FindName("btnStop")
$btnExport     = $window.FindName("btnExport")
$lblStatus     = $window.FindName("lblStatus")
$pbProgress    = $window.FindName("pbProgress")
$lblProgress   = $window.FindName("lblProgress")
$dgResults     = $window.FindName("dgResults")
$txtSummary    = $window.FindName("txtSummary")

$script:cancelTest = $false

function Update-ProgressUI {
    param(
        [int]$Current,
        [int]$Total
    )
    if ($Total -le 0) { return }
    $pct = [math]::Round(($Current / $Total) * 100, 0)
    $pbProgress.Value = $pct
    $lblProgress.Text = "$Current / $Total  ($pct`%)"
    [System.Windows.Forms.Application]::DoEvents()
}

function Get-JitterStatistics {
    param([double[]]$Rtts)

    if (-not $Rtts -or $Rtts.Count -lt 2) {
        return [pscustomobject]@{
            AvgDelta = 0.0
            MaxDelta = 0.0
        }
    }

    $deltas = New-Object System.Collections.Generic.List[double]
    for ($i = 1; $i -lt $Rtts.Count; $i++) {
        $deltas.Add([math]::Abs($Rtts[$i] - $Rtts[$i-1]))
    }

    $avg = ($deltas | Measure-Object -Average).Average
    $max = ($deltas | Measure-Object -Maximum).Maximum

    [pscustomobject]@{
        AvgDelta = [math]::Round($avg, 2)
        MaxDelta = [math]::Round($max, 2)
    }
}

function Get-MosEstimate {
    param(
        [double]$AvgRttMs,
        [double]$LossPct
    )
    # Very rough E-model style MOS estimate assuming G.711, random loss
    $d = $AvgRttMs / 2.0  # approximate one-way delay
    if ($d -lt 0) { $d = 0 }

    $Id = 0.024 * $d + 0.11 * [math]::Max(0, $d - 177.3)

    $Ie   = 0     # codec impairment for G.711
    $Bpl  = 25.0  # packet loss robustness
    $Ppl  = [math]::Max(0.0, $LossPct)   # %
    $IeEff = $Ie + (95 - $Ie) * $Ppl / ($Ppl + $Bpl)

    $R = 94.2 - $Id - $IeEff
    if ($R -lt 0)   { $R = 0 }
    if ($R -gt 100) { $R = 100 }

    if ($R -le 0)   { return 1.0 }
    if ($R -ge 100) { return 4.5 }

    $mos = 1 + 0.035 * $R + 7e-6 * $R * ($R - 60) * (100 - $R)
    [math]::Round($mos, 2)
}

function Get-VoipQualityRating {
    param(
        [double]$AvgRtt,
        [double]$JitterAvg,
        [double]$LossPct,
        [double]$Mos
    )

    if ($Mos -ge 4.1 -and $LossPct -le 0.5 -and $JitterAvg -le 15 -and $AvgRtt -le 200) {
        return "Good – MOS≈$Mos, suitable for VoIP (G.711-class)"
    }
    elseif ($Mos -ge 3.6 -and $LossPct -le 1.0 -and $JitterAvg -le 30 -and $AvgRtt -le 300) {
        return "Fair – MOS≈$Mos, occasional artifacts likely"
    }
    else {
        return "Poor – MOS≈$Mos, expect frequent quality issues"
    }
}

function Start-IcmpVoipTest {
    param(
        [string]$Target,
        [int]$Count,
        [int]$IntervalMs,
        [int]$TimeoutMs
    )

    $ping = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]
    $sent = 0
    $recv = 0
    $lost = 0

    for ($i = 1; $i -le $Count; $i++) {
        if ($script:cancelTest) { break }
        $sent++

        try {
            $reply = $ping.Send($Target, $TimeoutMs)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $rtt = [double]$reply.RoundtripTime
                $rtts.Add($rtt)
                $recv++
                $status = "OK"
                $rttDisplay = "{0:N2}" -f $rtt
                $addr = $reply.Address.ToString()
            } else {
                $lost++
                $status = $reply.Status.ToString()
                $rttDisplay = "-"
                $addr = ""
            }

            $dgResults.Items.Add([pscustomobject]@{
                Seq       = $i
                Type      = "ICMP"
                Status    = $status
                RTT_ms    = $rttDisplay
                Address   = $addr
                TimeStamp = (Get-Date)
            }) | Out-Null
        }
        catch {
            $lost++
            $dgResults.Items.Add([pscustomobject]@{
                Seq       = $i
                Type      = "ICMP"
                Status    = "Error: $($_.Exception.Message)"
                RTT_ms    = "-"
                Address   = ""
                TimeStamp = (Get-Date)
            }) | Out-Null
        }

        Update-ProgressUI -Current $i -Total $Count
        Start-Sleep -Milliseconds $IntervalMs
    }

    $avgRtt = 0.0
    $minRtt = 0.0
    $maxRtt = 0.0

    if ($rtts.Count -gt 0) {
        $stats = $rtts | Measure-Object -Average -Minimum -Maximum
        $avgRtt = [math]::Round($stats.Average, 2)
        $minRtt = [math]::Round($stats.Minimum, 2)
        $maxRtt = [math]::Round($stats.Maximum, 2)
    }

    $lossPct = if ($sent -gt 0) {
        [math]::Round(($lost * 100.0) / $sent, 2)
    } else { 0.0 }

    $jitter = Get-JitterStatistics -Rtts $rtts
    $mos    = Get-MosEstimate -AvgRttMs $avgRtt -LossPct $lossPct
    $rating = Get-VoipQualityRating -AvgRtt $avgRtt -JitterAvg $jitter.AvgDelta -LossPct $lossPct -Mos $mos

    [pscustomobject]@{
        Sent      = $sent
        Received  = $recv
        Lost      = $lost
        LossPct   = $lossPct
        AvgRtt    = $avgRtt
        MinRtt    = $minRtt
        MaxRtt    = $maxRtt
        JitterAvg = $jitter.AvgDelta
        JitterMax = $jitter.MaxDelta
        Mos       = $mos
        Rating    = $rating
    }
}

function Start-TcpLoadTest {
    param(
        [string]$Target,
        [int]$Port,
        [int]$Iterations,
        [int]$IntervalMs
    )

    $client = $null
    $stream = $null
    $bytesSent = 0L
    $payloadSize = 1200 # bytes per write, roughly MTU-sized

    $payload = New-Object byte[] $payloadSize
    $rand    = [System.Random]::new()
    $rand.NextBytes($payload)

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.NoDelay = $true
        $client.Connect($Target, $Port)
        $stream = $client.GetStream()

        for ($i = 1; $i -le $Iterations; $i++) {
            if ($script:cancelTest) { break }

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $stream.Write($payload, 0, $payload.Length)
                $stream.Flush()
                $sw.Stop()
                $bytesSent += $payload.Length

                $dgResults.Items.Add([pscustomobject]@{
                    Seq          = $i
                    Type         = "TCP"
                    Status       = "Sent"
                    BytesSent    = $payload.Length
                    SendTime_ms  = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                    TimeStamp    = (Get-Date)
                }) | Out-Null
            }
            catch {
                $sw.Stop()
                $dgResults.Items.Add([pscustomobject]@{
                    Seq          = $i
                    Type         = "TCP"
                    Status       = "Error: $($_.Exception.Message)"
                    BytesSent    = 0
                    SendTime_ms  = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                    TimeStamp    = (Get-Date)
                }) | Out-Null
                break
            }

            Update-ProgressUI -Current $i -Total $Iterations
            Start-Sleep -Milliseconds $IntervalMs
        }
    }
    catch {
        $dgResults.Items.Add([pscustomobject]@{
            Seq          = 0
            Type         = "TCP"
            Status       = "Connect failed: $($_.Exception.Message)"
            BytesSent    = 0
            SendTime_ms  = 0
            TimeStamp    = (Get-Date)
        }) | Out-Null
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Close() }
        $swTotal.Stop()
    }

    $durationSec = [math]::Max(0.001, $swTotal.Elapsed.TotalSeconds)
    $mbSent      = [math]::Round($bytesSent / 1MB, 3)
    $mbps        = [math]::Round(($bytesSent * 8.0 / 1MB) / $durationSec, 3)

    [pscustomobject]@{
        BytesSentMB   = $mbSent
        DurationSec   = [math]::Round($durationSec, 3)
        ThroughputMbps= $mbps
    }
}

function Start-UdpLoadTest {
    param(
        [string]$Target,
        [int]$Port,
        [int]$Iterations,
        [int]$IntervalMs
    )

    $udp = $null
    $bytesSent = 0L
    $payloadSize = 160   # bytes, roughly one G.711 20ms frame
    $payload = New-Object byte[] $payloadSize
    $rand    = [System.Random]::new()
    $rand.NextBytes($payload)

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Connect($Target, $Port)

        for ($i = 1; $i -le $Iterations; $i++) {
            if ($script:cancelTest) { break }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $sent = $udp.Send($payload, $payload.Length)
                $sw.Stop()
                $bytesSent += $sent

                $dgResults.Items.Add([pscustomobject]@{
                    Seq         = $i
                    Type        = "UDP"
                    Status      = "Sent"
                    BytesSent   = $sent
                    SendTime_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                    TimeStamp   = (Get-Date)
                }) | Out-Null
            }
            catch {
                $sw.Stop()
                $dgResults.Items.Add([pscustomobject]@{
                    Seq         = $i
                    Type        = "UDP"
                    Status      = "Error: $($_.Exception.Message)"
                    BytesSent   = 0
                    SendTime_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
                    TimeStamp   = (Get-Date)
                }) | Out-Null
                break
            }

            Update-ProgressUI -Current $i -Total $Iterations
            Start-Sleep -Milliseconds $IntervalMs
        }
    }
    catch {
        $dgResults.Items.Add([pscustomobject]@{
            Seq         = 0
            Type        = "UDP"
            Status      = "Init failed: $($_.Exception.Message)"
            BytesSent   = 0
            SendTime_ms = 0
            TimeStamp   = (Get-Date)
        }) | Out-Null
    }
    finally {
        if ($udp) { $udp.Close() }
        $swTotal.Stop()
    }

    $durationSec = [math]::Max(0.001, $swTotal.Elapsed.TotalSeconds)
    $mbSent      = [math]::Round($bytesSent / 1MB, 3)
    $mbps        = [math]::Round(($bytesSent * 8.0 / 1MB) / $durationSec, 3)

    [pscustomobject]@{
        BytesSentMB   = $mbSent
        DurationSec   = [math]::Round($durationSec, 3)
        ThroughputMbps= $mbps
    }
}

function Start-NetQualityTest {
    $targetHost  = $txtTarget.Text.Trim()
    $port        = [int]($txtPort.Text)
    $count       = [int]($txtCount.Text)
    $interval    = [int]($txtInterval.Text)
    $timeout     = [int]($txtTimeout.Text)
    $testTypeIdx = $cmbTestType.SelectedIndex

    if ([string]::IsNullOrWhiteSpace($targetHost)) {
        [System.Windows.MessageBox]::Show("Target host/IP is required.","Validation",
            [System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning) | Out-Null
        return
    }
    if ($count -le 0)    { $count    = 50 }
    if ($interval -le 0) { $interval = 50 }
    if ($timeout -le 0)  { $timeout  = 1000 }
    if ($port -le 0)     { $port     = 5060 }

    $btnStart.IsEnabled  = $false
    $btnStop.IsEnabled   = $true
    $btnExport.IsEnabled = $false
    $script:cancelTest   = $false
    $lblStatus.Text      = "Running..."
    $lblStatus.Foreground= 'DarkOrange'
    $dgResults.Items.Clear()
    $txtSummary.Text     = ""
    $pbProgress.Value    = 0
    $lblProgress.Text    = ""

    $summaryObj = $null

    switch ($testTypeIdx) {
        0 { # ICMP VoIP
            $summaryObj = Start-IcmpVoipTest -Target $targetHost -Count $count -IntervalMs $interval -TimeoutMs $timeout
        }
        1 { # TCP load
            $summaryObj = Start-TcpLoadTest -Target $targetHost -Port $port -Iterations $count -IntervalMs $interval
        }
        2 { # UDP load
            $summaryObj = Start-UdpLoadTest -Target $targetHost -Port $port -Iterations $count -IntervalMs $interval
        }
    }

    # Build summary text
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("Target: $targetHost")
    if ($txtDescription.Text.Trim()) {
        $null = $sb.AppendLine("Description: $($txtDescription.Text.Trim())")
    }
    $null = $sb.AppendLine("Test type: $($cmbTestType.Text)")
    $null = $sb.AppendLine("Port (for TCP/UDP): $port")
    $null = $sb.AppendLine("Iterations: $count  Interval: ${interval}ms")
    $null = $sb.AppendLine()

    if ($summaryObj) {
        if ($cmbTestType.SelectedIndex -eq 0) {
            $null = $sb.AppendLine("ICMP/VoIP metrics:")
            $null = $sb.AppendLine("  Sent:      {0}"  -f $summaryObj.Sent)
            $null = $sb.AppendLine("  Received:  {0}"  -f $summaryObj.Received)
            $null = $sb.AppendLine("  Lost:      {0}  ({1}% loss)" -f $summaryObj.Lost, $summaryObj.LossPct)
            $null = $sb.AppendLine("  RTT (ms):  avg={0}  min={1}  max={2}" -f $summaryObj.AvgRtt,$summaryObj.MinRtt,$summaryObj.MaxRtt)
            $null = $sb.AppendLine("  Jitter (ms, successive deltas): avg={0}  max={1}" -f $summaryObj.JitterAvg,$summaryObj.JitterMax)
            $null = $sb.AppendLine("  MOS (est.): {0}" -f $summaryObj.Mos)
            $null = $sb.AppendLine("  Rating:     {0}" -f $summaryObj.Rating)
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("Rule of thumb (G.711-ish):")
            $null = $sb.AppendLine("  Good: MOS≥4.1, loss≤0.5%, jitter≤15ms, RTT≤200ms")
            $null = $sb.AppendLine("  Fair: MOS≈3.6–4.1, loss≤1%, jitter≤30ms, RTT≤300ms")
        }
        else {
            $null = $sb.AppendLine("Load test summary:")
            $null = $sb.AppendLine("  Bytes sent: {0} MB" -f $summaryObj.BytesSentMB)
            $null = $sb.AppendLine("  Duration:   {0} s"  -f $summaryObj.DurationSec)
            $null = $sb.AppendLine("  Throughput: {0} Mbps (client-side estimate)" -f $summaryObj.ThroughputMbps)
            if ($cmbTestType.SelectedIndex -eq 2) {
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("Note: UDP test is fire-and-forget; without a cooperating echo server")
                $null = $sb.AppendLine("      this measures send rate only, not actual loss/RTT.")
            }
        }
    }

    $txtSummary.Text = $sb.ToString()

    if ($script:cancelTest) {
        $lblStatus.Text = "Canceled."
        $lblStatus.Foreground = 'Gray'
    } else {
        $lblStatus.Text = "Completed."
        $lblStatus.Foreground = 'DarkGreen'
    }

    $btnStart.IsEnabled  = $true
    $btnStop.IsEnabled   = $false
    $btnExport.IsEnabled = ($dgResults.Items.Count -gt 0)
}

function Export-NetQualityCsv {
    if ($dgResults.Items.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No rows to export.","Export CSV",
            [System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
        return
    }

    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dlg.FileName = "NetQualityPS_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)
    if ($dlg.ShowDialog() -ne $true) { return }

    $rows = @()
    foreach ($item in $dgResults.Items) {
        if ($item -ne $null) { $rows += $item }
    }

    try {
        $rows | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
        [System.Windows.MessageBox]::Show("Exported to:`n$($dlg.FileName)","Export CSV",
            [System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
    }
    catch {
        [System.Windows.MessageBox]::Show("Export failed: $($_.Exception.Message)","Export CSV",
            [System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
    }
}

# Wire up buttons
$btnStart.Add_Click({ Start-NetQualityTest })
$btnStop.Add_Click({ $script:cancelTest = $true })
$btnExport.Add_Click({ Export-NetQualityCsv })

# Run window
$window.ShowDialog() | Out-Null