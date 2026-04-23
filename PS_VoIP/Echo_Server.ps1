param(
    [int]$UdpPort = 5004,   # typical RTP port
    [int]$TcpPort = 7000    # arbitrary TCP echo port
)

#Add-Type -AssemblyName System.Net, System.Net.Sockets

Write-Host "VoIP Echo Server starting..."
Write-Host " UDP echo on port $UdpPort"
Write-Host " TCP echo on port $TcpPort"
Write-Host "Press Ctrl+C to stop.`n"

# --- UDP echo socket ---
$udpClient = New-Object System.Net.Sockets.UdpClient($UdpPort)
$udpRemote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

# --- TCP listener + active clients ---
$tcpListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $TcpPort)
$tcpListener.Start()

$tcpClients = New-Object System.Collections.Generic.List[System.Net.Sockets.TcpClient]

try {
    while ($true) {
        # Handle UDP echo
        if ($udpClient.Available -gt 0) {
            try {
                $bytes = $udpClient.Receive([ref]$udpRemote)
                if ($bytes -and $bytes.Length -gt 0) {
                    # Echo back to sender
                    $null = $udpClient.Send($bytes, $bytes.Length, $udpRemote)
                }
            }
            catch {
                Write-Warning "UDP error: $($_.Exception.Message)"
            }
        }

        # Accept new TCP clients (non-blocking)
        if ($tcpListener.Pending()) {
            try {
                $newClient = $tcpListener.AcceptTcpClient()
                $tcpClients.Add($newClient)
                Write-Host "New TCP client from $($newClient.Client.RemoteEndPoint)"
            }
            catch {
                Write-Warning "TCP accept error: $($_.Exception.Message)"
            }
        }

        # Handle existing TCP clients (echo)
        for ($i = $tcpClients.Count - 1; $i -ge 0; $i--) {
            $c = $tcpClients[$i]
            try {
                if (-not $c.Connected) {
                    $c.Close()
                    $tcpClients.RemoveAt($i)
                    continue
                }

                $stream = $c.GetStream()
                if ($stream.DataAvailable) {
                    $buffer = New-Object byte[] 4096
                    $read = $stream.Read($buffer, 0, $buffer.Length)
                    if ($read -le 0) {
                        # client closed
                        $c.Close()
                        $tcpClients.RemoveAt($i)
                        continue
                    }

                    # Echo back what we got
                    $stream.Write($buffer, 0, $read)
                    $stream.Flush()
                }
            }
            catch {
                Write-Warning "TCP client error: $($_.Exception.Message)"
                try { $c.Close() } catch {}
                $tcpClients.RemoveAt($i)
            }
        }

        # Avoid tight spin
        Start-Sleep -Milliseconds 2
    }
}
finally {
    Write-Host "`nShutting down..."
    if ($udpClient) { $udpClient.Close() }
    if ($tcpListener) { $tcpListener.Stop() }
    foreach ($c in $tcpClients) {
        try { $c.Close() } catch {}
    }
}