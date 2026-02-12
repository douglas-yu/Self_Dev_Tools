<#
.SYNOPSIS
  Remote FTK-like Forensic Triage GUI

.DESCRIPTION
  - Connects to remote Windows host using credentials
  - Left: TreeView of remote file system (lazy-loaded)
  - Right-top: List of items in selected folder
  - Right-bottom: Tabbed preview of selected file (Text / Hex / Image)
  - Uses PowerShell Remoting (PSSession) for all remote operations

.NOTES
  Requirements:
    - WinRM / PowerShell Remoting enabled on target
    - Sufficient privileges for file access
    - Run from PowerShell (not minimal host without WPF)
#>

Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
Add-Type -AssemblyName System.Xaml
Add-Type -AssemblyName System.Windows.Forms   # For FolderBrowserDialog

# --------------------------------------------------------------------
# Global State
# --------------------------------------------------------------------

$global:RemoteSession   = $null
$global:CurrentFolder   = $null
$global:CurrentFileInfo = $null

# Size limit for automatic preview (in bytes)
$global:PreviewSizeLimit = 10MB

# --------------------------------------------------------------------
# XAML UI Definition
# --------------------------------------------------------------------

[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Remote Forensic Triage GMOL" Height="800" Width="1400"
        WindowStartupLocation="CenterScreen">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <Grid.ColumnDefinitions>
      <ColumnDefinition Width="*"/>
    </Grid.ColumnDefinitions>

    <!-- Connection Bar -->
    <DockPanel Grid.Row="0" LastChildFill="True" Margin="0,0,0,10">
      <StackPanel Orientation="Horizontal" DockPanel.Dock="Left">
        <TextBlock Text="Remote Host:" VerticalAlignment="Center" Margin="0,0,5,0"/>
        <TextBox x:Name="txtHost" Width="150" Margin="0,0,10,0"/>

        <TextBlock Text="Username:" VerticalAlignment="Center" Margin="0,0,5,0"/>
        <TextBox x:Name="txtUser" Width="160" Margin="0,0,10,0"/>

        <TextBlock Text="Password:" VerticalAlignment="Center" Margin="0,0,5,0"/>
        <PasswordBox x:Name="txtPassword" Width="150" Margin="0,0,10,0"/>

        <Button x:Name="btnConnect" Content="Connect" Width="90" Margin="0,0,10,0"/>
      </StackPanel>

      <TextBlock x:Name="lblStatus" VerticalAlignment="Center"
                 Foreground="DarkGreen" Text="" />
       <TextBlock x:Name="lblgm" VerticalAlignment="Center" HorizontalAlignment="Right"
                 Foreground="DarkBlue" Text="GM ISRM Inside Risk Tool" />
    </DockPanel>

    <!-- Main area: Left Tree, Right Split (top list, bottom preview) -->
    <Grid Grid.Row="1">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="3*"/>
        <ColumnDefinition Width="7*"/>
      </Grid.ColumnDefinitions>

      <!-- Left: Remote File System -->
      <GroupBox Header="Remote File System" Grid.Column="0" Margin="0,0,10,0">
        <Grid>
          <TreeView x:Name="tvFileSystem" Margin="5"/>
        </Grid>
      </GroupBox>

      <!-- Right: File List (top) + Preview (bottom) -->
      <Grid Grid.Column="1">
        <Grid.RowDefinitions>
          <RowDefinition Height="3*"/>
          <RowDefinition Height="4*"/>
        </Grid.RowDefinitions>

        <!-- File List -->
        <GroupBox Header="Folder Contents" Grid.Row="0" Margin="0,0,0,5">
          <Grid>
                <ListView x:Name="lvFiles" Margin="5" SelectionMode="Extended">
                  <ListView.ContextMenu>
                    <ContextMenu>
                      <MenuItem Header="Export Selected File(s)..." />
                    </ContextMenu>
                  </ListView.ContextMenu>

                  <ListView.View>
                    <GridView>
                      <GridViewColumn Header="Name" DisplayMemberBinding="{Binding Name}" Width="250"/>
                      <GridViewColumn Header="Type" DisplayMemberBinding="{Binding ItemType}" Width="80"/>
                      <GridViewColumn Header="Size" DisplayMemberBinding="{Binding Size}" Width="80"/>
                      <GridViewColumn Header="LastWrite" DisplayMemberBinding="{Binding LastWriteTime}" Width="160"/>
                      <GridViewColumn Header="Full Path" DisplayMemberBinding="{Binding FullName}" Width="300"/>
                    </GridView>
                  </ListView.View>
                </ListView>
          </Grid>
        </GroupBox>

        <!-- Preview Tabs -->
        <GroupBox Header="Preview" Grid.Row="1">
          <Grid>
            <TabControl x:Name="tabPreview" Margin="5">
              <TabItem Header="Text">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                  <TextBox x:Name="txtPreview"
                           FontFamily="Consolas"
                           FontSize="12"
                           AcceptsReturn="True"
                           AcceptsTab="True"
                           TextWrapping="NoWrap"
                           VerticalScrollBarVisibility="Auto"
                           HorizontalScrollBarVisibility="Auto"
                           IsReadOnly="True"/>
                </ScrollViewer>
              </TabItem>
              <TabItem Header="Hex">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
                  <TextBox x:Name="txtHex"
                           FontFamily="Consolas"
                           FontSize="12"
                           AcceptsReturn="True"
                           AcceptsTab="True"
                           TextWrapping="NoWrap"
                           VerticalScrollBarVisibility="Auto"
                           HorizontalScrollBarVisibility="Auto"
                           IsReadOnly="True"/>
                </ScrollViewer>
              </TabItem>
              <TabItem Header="Image">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" Background="#FF202020">
                  <Image x:Name="imgPreview" Stretch="Uniform" Margin="5"/>
                </ScrollViewer>
              </TabItem>
            </TabControl>
          </Grid>
        </GroupBox>
      </Grid>
    </Grid>
  </Grid>
</Window>
"@

# --------------------------------------------------------------------
# Load XAML & Controls
# --------------------------------------------------------------------

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

$txtHost     = $window.FindName('txtHost')
$txtUser     = $window.FindName('txtUser')
$txtPassword = $window.FindName('txtPassword')
$btnConnect  = $window.FindName('btnConnect')
$lblStatus   = $window.FindName('lblStatus')
$lblgm   = $window.FindName('lblgm')

$tvFileSystem = $window.FindName('tvFileSystem')
$lvFiles      = $window.FindName('lvFiles')

$tabPreview = $window.FindName('tabPreview')
$txtPreview = $window.FindName('txtPreview')
$txtHex     = $window.FindName('txtHex')
$imgPreview = $window.FindName('imgPreview')

# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

function Show-InfoMessage {
    param([string]$Message, [string]$Title = "Info")
    [System.Windows.MessageBox]::Show($Message, $Title, 'OK', 'Information') | Out-Null
}

function Show-ErrorMessage {
    param([string]$Message, [string]$Title = "Error")
    [System.Windows.MessageBox]::Show($Message, $Title, 'OK', 'Error') | Out-Null
}

# Convert bytes to hex dump string (similar to hexdump)
function Convert-ToHexDump {
    param(
        [byte[]]$Bytes,
        [int]$Width = 16
    )

    if (-not $Bytes) { return "" }

    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Bytes.Length; $i += $Width) {
        $chunk = $Bytes[$i..([Math]::Min($i + $Width - 1, $Bytes.Length - 1))]

        # Offset
        [void]$sb.AppendFormat("{0:X8}  ", $i)

        # Hex
        $hexPart = ($chunk | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        $hexPart = $hexPart.PadRight($Width * 3)
        [void]$sb.Append($hexPart)
        [void]$sb.Append(" ")

        # ASCII
        $ascii = ($chunk | ForEach-Object {
            if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' }
        }) -join ""
        [void]$sb.Append($ascii)
        [void]$sb.AppendLine()
    }
    return $sb.ToString()
}

function Is-ImageExtension {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path)
    if (-not $ext) { return $false }
    $ext = $ext.ToLowerInvariant()
    return $ext -in '.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tif', '.tiff', '.ico'
}

# --------------------------------------------------------------------
# Remote Session Helpers
# --------------------------------------------------------------------

function Connect-RemoteHost {
    param(
        [string]$ComputerName,
        [string]$UserName,
        [System.Security.SecureString]$SecurePassword
    )

    if (-not $ComputerName) { Show-ErrorMessage "Remote host is required."; return $null }
    if (-not $UserName)     { Show-ErrorMessage "Username is required."; return $null }

    try {
        $cred = New-Object System.Management.Automation.PSCredential($UserName, $SecurePassword)
    } catch {
        Show-ErrorMessage "Failed to create credential: $($_.Exception.Message)"
        return $null
    }

    try {
        $session = New-PSSession -ComputerName $ComputerName -Credential $cred -ErrorAction Stop
        return $session
    } catch {
        Show-ErrorMessage "Failed to connect to $ComputerName : $($_.Exception.Message)"
        return $null
    }
}

# --------------------------------------------------------------------
# File System Tree & Folder Listing
# --------------------------------------------------------------------

function New-TreeItem {
    param(
        [string]$Header,
        [string]$Tag,
        [bool]$HasDummyChild = $false
    )

    $item = New-Object System.Windows.Controls.TreeViewItem
    $item.Header = $Header
    $item.Tag    = $Tag

    if ($HasDummyChild) {
        # Add dummy child so the node shows an expand arrow
        [void]$item.Items.Add("*")
    }

    # Attach Expanded handler per-item for lazy loading
    $item.Add_Expanded({
        param($sender, $e)

        if (-not $global:RemoteSession) { return }

        # $sender is the TreeViewItem that was expanded
        Load-ChildItems -Session $global:RemoteSession -Item $sender
    })

    return $item
}

function Load-RootDrives {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [System.Windows.Controls.TreeView]$TreeView
    )

    $TreeView.Items.Clear()
    if (-not $Session) { return }

    $drives = Invoke-Command -Session $Session -ScriptBlock {
        Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root
    } -ErrorAction SilentlyContinue

    foreach ($d in $drives) {
        $header = "{0} ({1})" -f $d.Name, $d.Root   # e.g. "C (C:\)"
        $ti = New-TreeItem -Header $header -Tag $d.Root -HasDummyChild $true
        [void]$TreeView.Items.Add($ti)
    }
}


function Load-ChildItems {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [System.Windows.Controls.TreeViewItem]$Item
    )

    if (-not $Session) { return }

    # Only process if we still have the single dummy child "*"
    if ($Item.Items.Count -eq 1 -and $Item.Items[0] -is [string] -and $Item.Items[0] -eq "*") {
        $Item.Items.Clear()
        $path = [string]$Item.Tag

        try {
            $children = Invoke-Command -Session $Session -ScriptBlock {
                param($p)
                Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |
                    Select-Object FullName, Name, PSIsContainer
            } -ArgumentList $path -ErrorAction Stop
        } catch {
            # If enumeration fails (access denied, etc.), just leave node empty
            return
        }

        foreach ($c in $children) {
            if ($c.PSIsContainer) {
                $childItem = New-TreeItem -Header $c.Name -Tag $c.FullName -HasDummyChild $true
                [void]$Item.Items.Add($childItem)
            }
        }
    }
}

function Load-FolderContents {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$FolderPath
    )

    if (-not $Session) { return }

    $global:CurrentFolder = $FolderPath
    $lvFiles.ItemsSource = $null

    try {
        $items = Invoke-Command -Session $Session -ScriptBlock {
            param($p)
            Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue |
                Select-Object FullName, Name, Length, LastWriteTime, PSIsContainer
        } -ArgumentList $FolderPath -ErrorAction Stop
    } catch {
        Show-ErrorMessage "Failed to list folder '$FolderPath': $($_.Exception.Message)"
        return
    }

    $list = @()
    foreach ($i in $items) {
        $itemType = if ($i.PSIsContainer) { "Dir" } else { "File" }
        $size     = if ($i.PSIsContainer) { "" } else { $i.Length }

        $list += [pscustomobject]@{
            Name         = $i.Name
            FullName     = $i.FullName
            ItemType     = $itemType
            Size         = $size
            LastWriteTime= $i.LastWriteTime
            PSIsContainer= $i.PSIsContainer
        }
    }

    $lvFiles.ItemsSource = $list
}
function Export-SelectedFiles {
    if (-not $global:RemoteSession) {
        Show-ErrorMessage "Not connected to a remote session."
        return
    }

    $selected = @($lvFiles.SelectedItems)
    if (-not $selected -or $selected.Count -eq 0) {
        Show-ErrorMessage "No items selected."
        return
    }

    # Only export files (skip directories for now)
    $files = $selected | Where-Object { -not $_.PSIsContainer }
    if (-not $files -or $files.Count -eq 0) {
        Show-ErrorMessage "No files selected (directories are not exported in this version)."
        return
    }

    # Choose local destination folder
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select local destination folder for exported file(s)."
    $dialog.ShowNewFolderButton = $true

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    $destRoot = $dialog.SelectedPath
    $errors   = @()

    $window.Cursor = 'Wait'
    foreach ($f in $files) {
        $remotePath = $f.FullName
        $localPath  = Join-Path $destRoot $f.Name

        try {
            # Preferred: direct copy from remote session (PS 5+)
            Copy-Item -Path $remotePath -Destination $localPath -FromSession $global:RemoteSession -ErrorAction Stop
        } catch {
            # Fallback: read bytes via remoting and write locally
            try {
                $bytes = Invoke-Command -Session $global:RemoteSession -ScriptBlock {
                    param($p)
                    [System.IO.File]::ReadAllBytes($p)
                } -ArgumentList $remotePath -ErrorAction Stop

                [System.IO.File]::WriteAllBytes($localPath, $bytes)
            } catch {
                $errors += "Failed to export $remotePath -> $localPath : $($_.Exception.Message)"
            }
        }
    }
    $window.Cursor = 'Arrow'

    if ($errors.Count -gt 0) {
        Show-ErrorMessage ("Some files failed to export:`r`n" + ($errors -join "`r`n"))
    } else {
        Show-InfoMessage "Export completed to:`r`n$destRoot"
    }
}

# --------------------------------------------------------------------
# File Preview
# --------------------------------------------------------------------

function Clear-Preview {
    $txtPreview.Text = ""
    $txtHex.Text     = ""
    $imgPreview.Source = $null
    $global:CurrentFileInfo = $null
}

function Load-FilePreview {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [pscustomobject]$FileInfo
    )

    Clear-Preview

    if (-not $Session -or -not $FileInfo -or $FileInfo.PSIsContainer) { return }

    $global:CurrentFileInfo = $FileInfo

    $path = $FileInfo.FullName
    $size = [int64]($FileInfo.Size)

    if ($size -gt $global:PreviewSizeLimit) {
        $msg = "File is larger than preview limit ({0} MB). Size: {1:N2} MB." -f `
            ($global:PreviewSizeLimit / 1MB), ($size / 1MB)
        Show-InfoMessage $msg "Preview Skipped"
        return
    }

    $window.Cursor = 'Wait'
    try {
        # Get bytes from remote
        $bytes = Invoke-Command -Session $Session -ScriptBlock {
            param($p)
            [System.IO.File]::ReadAllBytes($p)
        } -ArgumentList $path -ErrorAction Stop

        # Text preview (best-effort)
        try {
            $encoding = [System.Text.Encoding]::UTF8
            $text = $encoding.GetString($bytes)
        } catch {
            $text = ""
        }
        $txtPreview.Text = $text

        # Hex preview
        $txtHex.Text = Convert-ToHexDump -Bytes $bytes -Width 16

        # Image preview (if ext appears to be image)
        if (Is-ImageExtension -Path $path) {
            try {
                $ms = New-Object System.IO.MemoryStream(,$bytes)
                $img = New-Object System.Windows.Media.Imaging.BitmapImage
                $img.BeginInit()
                $img.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
                $img.StreamSource = $ms
                $img.EndInit()
                $img.Freeze()
                $imgPreview.Source = $img
            } catch {
                $imgPreview.Source = $null
            }
        } else {
            $imgPreview.Source = $null
        }
    } catch {
        Show-ErrorMessage "Failed to preview file '$path': $($_.Exception.Message)"
    } finally {
        $window.Cursor = 'Arrow'
    }
}

# --------------------------------------------------------------------
# Event Wiring
# --------------------------------------------------------------------

# Connect button
$btnConnect.Add_Click({
    $lblStatus.Text = ""

    if ($global:RemoteSession) {
        try { Remove-PSSession -Session $global:RemoteSession -ErrorAction SilentlyContinue } catch {}
        $global:RemoteSession = $null
    }

    $computer = $txtHost.Text.Trim()
    $user     = $txtUser.Text.Trim()
    $pwd      = $txtPassword.SecurePassword

    $session = Connect-RemoteHost -ComputerName $computer -UserName $user -SecurePassword $pwd
    if ($session) {
        $global:RemoteSession = $session
        $lblStatus.Text       = "Connected to $computer"
        $lblStatus.Foreground = [System.Windows.Media.Brushes]::DarkGreen
        Load-RootDrives -Session $global:RemoteSession -TreeView $tvFileSystem
    } else {
        $lblStatus.Text       = "Not connected"
        $lblStatus.Foreground = [System.Windows.Media.Brushes]::DarkRed
    }
})

# TreeView expand for lazy-load

$lvFiles      = $window.FindName('lvFiles')

# First (and only) MenuItem in the ListView's context menu
$miExportFiles = $lvFiles.ContextMenu.Items[0]

$miExportFiles.Add_Click({
    Export-SelectedFiles
})
# TreeView selected item: load folder contents
$tvFileSystem.Add_SelectedItemChanged({
    param($sender, $e)
    if (-not $global:RemoteSession) { return }

    $item = $tvFileSystem.SelectedItem
    if ($item -is [System.Windows.Controls.TreeViewItem]) {
        $path = [string]$item.Tag
        if ($path) {
            Load-FolderContents -Session $global:RemoteSession -FolderPath $path
            Clear-Preview
        }
    }
})

# File list: double-click to open folder (if dir) or preview (if file)
$lvFiles.Add_MouseDoubleClick({
    param($sender, $e)

    $selected = $lvFiles.SelectedItem
    if (-not $selected) { return }

    if ($selected.PSIsContainer) {
        # Navigate into directory
        if ($global:RemoteSession) {
            Load-FolderContents -Session $global:RemoteSession -FolderPath $selected.FullName
            Clear-Preview
        }
    } else {
        if ($global:RemoteSession) {
            Load-FilePreview -Session $global:RemoteSession -FileInfo $selected
        }
    }
})

# File selection (single click) – optional: auto preview file
$lvFiles.Add_SelectionChanged({
    param($sender, $e)

    $selected = $lvFiles.SelectedItem
    if (-not $selected) { return }
    if ($selected.PSIsContainer) {
        Clear-Preview
        return
    }

    if ($global:RemoteSession) {
        Load-FilePreview -Session $global:RemoteSession -FileInfo $selected
    }
})

# Clean up on window close
$window.Add_Closed({
    if ($global:RemoteSession) {
        try { Remove-PSSession -Session $global:RemoteSession -ErrorAction SilentlyContinue } catch {}
    }
})

# --------------------------------------------------------------------
# Run UI
# --------------------------------------------------------------------

[void]$window.ShowDialog()