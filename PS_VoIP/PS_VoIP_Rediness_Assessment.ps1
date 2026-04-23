Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Net, System.Net.Sockets
Add-Type -AssemblyName System.Windows.Formswin



# XAML UI
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="NetQuality-PS - VoIP / RTP Network Assessment"
        Height="680" Width="980"
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
    <TextBlock Grid.Row="0"
               Text="NetQuality-PS (ICMP / TCP echo / RTP-over-UDP with G.711 / G.729)"
               FontSize="16" FontWeight="Bold" Margin="0,0,0,8"/>

    <!-- Controls -->
    <StackPanel Grid.Row="1" Orientation="Vertical" Margin="0,0,0,8">
      <WrapPanel Margin="0,0,0,4">
        <TextBlock Text="Target Host/IP:" VerticalAlignment="Center" Width="110"/>
        <TextBox x:Name="txtTarget" Width="210" Text="127.0.0.1" Margin="4,0,16,0"/>

        <TextBlock Text="Port (TCP/UDP):" VerticalAlignment="Center" Width="120"/>
        <TextBox x:Name="txtPort" Width="80" Text="5004" Margin="4,0,16,0"/>

        <TextBlock Text="Probes / Frames:" VerticalAlignment="Center" Width="120"/>
        <TextBox x:Name="txtCount" Width="70" Text="300" Margin="4,0,16,0"/>

        <TextBlock Text="Interval (ms):" VerticalAlignment="Center" Width="90"/>
        <TextBox x:Name="txtInterval" Width="70" Text="20" Margin="4,0,16,0"/>

        <TextBlock Text="Timeout (ms, ICMP/UDP):" VerticalAlignment="Center" Width="150"/>
        <TextBox x:Name="txtTimeout" Width="80" Text="1000" Margin="4,0,16,0"/>
      </WrapPanel>

      <WrapPanel Margin="0,0,0,4">
        <TextBlock Text="Test Type:" VerticalAlignment="Center" Width="110"/>
        <ComboBox x:Name="cmbTestType" Width="280" SelectedIndex="0" Margin="4,0,16,0">
          <ComboBoxItem Content="ICMP VoIP (latency/jitter/loss/MOS)"/>
          <ComboBoxItem Content="TCP Echo (RTP-size frames)"/>
          <ComboBoxItem Content="RTP over UDP – G.711 (64k, 20ms)"/>
          <ComboBoxItem Content="RTP over UDP – G.729 (8k, 20ms)"/>
        </ComboBox>

        <TextBlock Text="Description:" VerticalAlignment="Center" Width="90"/>
        <TextBox x:Name="txtDescription" Width="330" Height="40"
                 Text="VoIP / RTP network assessment"
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
      <ProgressBar x:Name="pbProgress" Width="420" Height="18"
                   Minimum="0" Maximum="100" Margin="4,0,8,0"/>
      <TextBlock x:Name="lblProgress" VerticalAlignment="Center" Width="140"/>
    </StackPanel>

    <!-- Results grid -->
    <DataGrid x:Name="dgResults" Grid.Row="3" Margin="0,0,0,8"
              AutoGenerateColumns="True" IsReadOnly="True"
              CanUserAddRows="False" CanUserDeleteRows="False"
              HeadersVisibility="Column" />

    <!-- Summary -->
    <GroupBox Grid.Row="4" Header="Summary (VoIP / RTP / load view)">
      <TextBlock x:Name="txtSummary" Margin="6" TextWrapping="Wrap"/>
    </GroupBox>
  </Grid>
</Window>
'@

$reader  = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$window  = [Windows.Markup.XamlReader]::Load($reader)

# Controls
$txtTarget      = $window.FindName("txtTarget")
$txtPort        = $window.FindName("txtPort")
$txtCount       = $window.FindName("txtCount")
$txtInterval    = $window.FindName("txtInterval")
$txtTimeout     = $window.FindName("txtTimeout")
$cmbTestType    = $window.FindName("cmbTestType")
$txtDescription = $window.FindName("txtDescription")
$btnStart       = $window.FindName("btnStart")
$btnStop        = $window.FindName("btnStop")
$btnExport      = $window.FindName("btnExport")
$lblStatus      = $window.FindName("lblStatus")
$pbProgress     = $window.FindName("pbProgress")
$lblProgress    = $window.FindName("lblProgress")
$dgResults      = $window.FindName("dgResults")
$txtSummary     = $window.FindName("txtSummary")

# Results collection for DataGrid
$script:results = New-Object System.Collections.ObjectModel.ObservableCollection[object]
$dgResults.ItemsSource = $script:results

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
    # Rough E-model MOS estimate assuming G.711
    $d = $AvgRttMs / 2.0  # approximate one-way delay
    if ($d -lt 0) { $d = 0 }

    $Id = 0.024 * $d + 0.11 * [math]::Max(0, $d - 177.3)

    $Ie   = 0
    $Bpl  = 25.0
    $Ppl  = [math]::Max(0.0, $LossPct)
    $IeEff = $Ie + (95 - $Ie) * $Ppl / ($Ppl + $Bpl)

    $R = 94.2 - $Id - $IeEff
    if     ($R -lt   0) { $R = 0 }
    elseif ($R -gt 100) { $R = 100 }

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

# --- ICMP VoIP test (same as before) ---
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

            $script:results.Add([pscustomobject]@{
                Seq       = $i
                Type      = "ICMP"
                Status    = $status
                RTT_ms    = $rttDisplay
                Address   = $addr
                TimeStamp = (Get-Date)
            })
        }
        catch {
            $lost++
            $script:results.Add([pscustomobject]@{
                Seq       = $i
                Type      = "ICMP"
                Status    = "Error: $($_.Exception.Message)"
                RTT_ms    = "-"
                Address   = ""
                TimeStamp = (Get-Date)
            })
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

# --- TCP echo test (RTP-size frames over TCP) ---
function Start-TcpEchoTest {
    param(
        [string]$Target,
        [int]$Port,
        [int]$Iterations,
        [int]$IntervalMs
    )

    $client = $null
    $stream = $null
    $rtts   = New-Object System.Collections.Generic.List[double]
    $sent   = 0
    $recv   = 0
    $lost   = 0

    # Use G.711 20ms-like frame (160 bytes) as "RTP-size frame"
    $payloadSize = 160
    $payload = New-Object byte[] $payloadSize
    $rand    = [System.Random]::new()
    $rand.NextBytes($payload)

    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.NoDelay = $true
        $client.Connect($Target, $Port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 2000

        for ($i = 1; $i -le $Iterations; $i++) {
            if ($script:cancelTest) { break }
            $sent++

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $stream.Write($payload, 0, $payload.Length)
                $stream.Flush()

                $buffer = New-Object byte[] $payloadSize
                $totalRead = 0
                while ($totalRead -lt $payloadSize) {
                    $read = $stream.Read($buffer, $totalRead, $payloadSize - $totalRead)
                    if ($read -le 0) { break }
                    $totalRead += $read
                }
                $sw.Stop()

                if ($totalRead -eq $payloadSize) {
                    $rtt = $sw.Elapsed.TotalMilliseconds
                    $rtts.Add($rtt)
                    $recv++
                    $status = "Echo OK"
                    $rttDisplay = "{0:N2}" -f $rtt
                } else {
                    $lost++
                    $status = "Short read ($totalRead/$payloadSize)"
                    $rttDisplay = "-"
                }

                $script:results.Add([pscustomobject]@{
                    Seq       = $i
                    Type      = "TCP-echo"
                    Status    = $status
                    RTT_ms    = $rttDisplay
                    Bytes     = $payloadSize
                    TimeStamp = (Get-Date)
                })
            }
            catch {
                $sw.Stop()
                $lost++
                $script:results.Add([pscustomobject]@{
                    Seq       = $i
                    Type      = "TCP-echo"
                    Status    = "Error: $($_.Exception.Message)"
                    RTT_ms    = "-"
                    Bytes     = 0
                    TimeStamp = (Get-Date)
                })
            }

            Update-ProgressUI -Current $i -Total $Iterations
            Start-Sleep -Milliseconds $IntervalMs
        }
    }
    catch {
        $script:results.Add([pscustomobject]@{
            Seq       = 0
            Type      = "TCP-echo"
            Status    = "Connect failed: $($_.Exception.Message)"
            RTT_ms    = "-"
            Bytes     = 0
            TimeStamp = (Get-Date)
        })
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Close() }
    }

    # Summaries
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

# --- RTP over UDP test (G.711 or G.729) ---
function New-RtpPacket {
    param(
        [int]$Sequence,
        [uint32]$Timestamp,
        [uint32]$Ssrc,
        [byte]$PayloadType,
        [byte[]]$PayloadBytes
    )
    # RTP header: 12 bytes
    $buffer = New-Object byte[] (12 + $PayloadBytes.Length)

    # V=2, P=0, X=0, CC=0  -> 0x80
    $buffer[0] = 0x80
    # M=0, PT=payloadType
    $buffer[1] = $PayloadType
    # sequence number (big endian)
    $buffer[2] = [byte](($Sequence -band 0xFF00) -shr 8)
    $buffer[3] = [byte]($Sequence -band 0x00FF)
    # timestamp (big endian)
    $buffer[4] = [byte](($Timestamp -band 0xFF000000) -shr 24)
    $buffer[5] = [byte](($Timestamp -band 0x00FF0000) -shr 16)
    $buffer[6] = [byte](($Timestamp -band 0x0000FF00) -shr 8)
    $buffer[7] = [byte]($Timestamp -band 0x000000FF)
    # SSRC (big endian)
    $buffer[8]  = [byte](($Ssrc -band 0xFF000000) -shr 24)
    $buffer[9]  = [byte](($Ssrc -band 0x00FF0000) -shr 16)
    $buffer[10] = [byte](($Ssrc -band 0x0000FF00) -shr 8)
    $buffer[11] = [byte]($Ssrc -band 0x000000FF)

    # payload
    [Array]::Copy($PayloadBytes, 0, $buffer, 12, $PayloadBytes.Length)
    $buffer
}

function Start-RtpUdpTest {
    param(
        [string]$Target,
        [int]$Port,
        [int]$Count,
        [int]$IntervalMs,
        [int]$TimeoutMs,
        [ValidateSet("G711","G729")]
        [string]$Codec
    )

    $udp = New-Object System.Net.Sockets.UdpClient
    $udp.Connect($Target, $Port)
    $udp.Client.ReceiveTimeout = $TimeoutMs

    $remoteEnd = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

    # Codec-specific payload size & payload type
    switch ($Codec) {
        "G711" {
            $payloadSize = 160   # 20ms of 8kHz * 1 byte
            $pt          = 0     # RTP PT 0 PCMU (G.711)
        }
        "G729" {
            $payloadSize = 20    # 20ms of 8kbps
            $pt          = 18    # RTP PT 18 G.729
        }
    }

    $rand    = [System.Random]::new()
    $ssrc    = [uint32]$rand.Next(1, [int][uint32]::MaxValue)
    $seq     = 0
    $ts      = 0

    # timestamp increment per packet; for 20ms @ 8kHz -> 160
    $tsStep = 160

    $rtts = New-Object System.Collections.Generic.List[double]
    $sent = 0
    $recv = 0
    $lost = 0

    for ($i = 1; $i -le $Count; $i++) {
        if ($script:cancelTest) { break }
        $sent++
        $seq++
        $ts += $tsStep

        $payload = New-Object byte[] $payloadSize
        $rand.NextBytes($payload)

        $packet = New-RtpPacket -Sequence $seq -Timestamp $ts -Ssrc $ssrc -PayloadType $pt -PayloadBytes $payload

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $udp.Send($packet, $packet.Length) | Out-Null

            $bytes = $null
            try {
                $bytes = $udp.Receive([ref]$remoteEnd)
            }
            catch [System.Net.Sockets.SocketException] {
                # timeout
            }

            $sw.Stop()

            if ($bytes -ne $null -and $bytes.Length -ge 12) {
                $rtt = $sw.Elapsed.TotalMilliseconds
                $rtts.Add($rtt)
                $recv++
                $status = "Echo OK"
                $rttDisplay = "{0:N2}" -f $rtt
            } else {
                $lost++
                $status = "Timeout / No echo"
                $rttDisplay = "-"
            }

            $script:results.Add([pscustomobject]@{
                Seq       = $i
                Type      = "RTP-$Codec"
                Status    = $status
                RTT_ms    = $rttDisplay
                Bytes     = $packet.Length
                TimeStamp = (Get-Date)
            })
        }
        catch {
            $sw.Stop()
            $lost++
            $script:results.Add([pscustomobject]@{
                Seq       = $i
                Type      = "RTP-$Codec"
                Status    = "Error: $($_.Exception.Message)"
                RTT_ms    = "-"
                Bytes     = 0
                TimeStamp = (Get-Date)
            })
        }

        Update-ProgressUI -Current $i -Total $Count
        Start-Sleep -Milliseconds $IntervalMs
    }

    $udp.Close()

    # Summaries (VoIP-style)
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
        Codec     = $Codec
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
    if ($interval -le 0) { $interval = 20 }
    if ($timeout -le 0)  { $timeout  = 1000 }
    if ($port -le 0)     { $port     = 5004 }

    $btnStart.IsEnabled  = $false
    $btnStop.IsEnabled   = $true
    $btnExport.IsEnabled = $false
    $script:cancelTest   = $false
    $lblStatus.Text      = "Running..."
    $lblStatus.Foreground= 'DarkOrange'
    $script:results.Clear()
    $txtSummary.Text     = ""
    $pbProgress.Value    = 0
    $lblProgress.Text    = ""

    $summaryObj = $null

    switch ($testTypeIdx) {
        0 { # ICMP
            $summaryObj = Start-IcmpVoipTest -Target $targetHost -Count $count -IntervalMs $interval -TimeoutMs $timeout
        }
        1 { # TCP echo
            $summaryObj = Start-TcpEchoTest -Target $targetHost -Port $port -Iterations $count -IntervalMs $interval
        }
        2 { # RTP G.711
            $summaryObj = Start-RtpUdpTest -Target $targetHost -Port $port -Count $count -IntervalMs $interval -TimeoutMs $timeout -Codec "G711"
        }
        3 { # RTP G.729
            $summaryObj = Start-RtpUdpTest -Target $targetHost -Port $port -Count $count -IntervalMs $interval -TimeoutMs $timeout -Codec "G729"
        }
    }

    # Build summary text
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine("Target: $targetHost")
    if ($txtDescription.Text.Trim()) {
        $null = $sb.AppendLine("Description: $($txtDescription.Text.Trim())")
    }
    $null = $sb.AppendLine("Test type: $($cmbTestType.Text)")
    $null = $sb.AppendLine("Port: $port")
    $null = $sb.AppendLine("Frames/Probes: $count  Interval: ${interval}ms")
    $null = $sb.AppendLine()

    if ($summaryObj) {
        if ($testTypeIdx -eq 0 -or $testTypeIdx -eq 1 -or $testTypeIdx -ge 2) {
            # All tests use similar summary object
            if ($testTypeIdx -ge 2) {
                $null = $sb.AppendLine("Codec: $($summaryObj.Codec)")
            }
            $null = $sb.AppendLine("Sent:      {0}"  -f $summaryObj.Sent)
            $null = $sb.AppendLine("Received:  {0}"  -f $summaryObj.Received)
            $null = $sb.AppendLine("Lost:      {0}  ({1}% loss)" -f $summaryObj.Lost, $summaryObj.LossPct)
            $null = $sb.AppendLine("RTT (ms):  avg={0}  min={1}  max={2}" -f $summaryObj.AvgRtt,$summaryObj.MinRtt,$summaryObj.MaxRtt)
            $null = $sb.AppendLine("Jitter (ms, successive deltas): avg={0}  max={1}" -f $summaryObj.JitterAvg,$summaryObj.JitterMax)
            $null = $sb.AppendLine("MOS (est.): {0}" -f $summaryObj.Mos)
            $null = $sb.AppendLine("Rating:     {0}" -f $summaryObj.Rating)
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("Rule of thumb (G.711-ish):")
            $null = $sb.AppendLine("  Good: MOS≥4.1, loss≤0.5%, jitter≤15ms, RTT≤200ms")
            $null = $sb.AppendLine("  Fair: MOS≈3.6–4.1, loss≤1%, jitter≤30ms, RTT≤300ms")
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
    $btnExport.IsEnabled = ($script:results.Count -gt 0)
}

function Export-NetQualityCsv {
    if ($script:results.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No rows to export.","Export CSV",
            [System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
        return
    }

    $dlg = New-Object Microsoft.Win32.SaveFileDialog
    $dlg.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dlg.FileName = "NetQualityPS_RTP_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)
    if ($dlg.ShowDialog() -ne $true) { return }

    try {
        $script:results | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
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