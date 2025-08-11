<#
.SYNOPSIS
    Measures SMB (Server Message Block) file transfer speeds while collecting system performance metrics and network information.

.DESCRIPTION
    This PowerShell script provides both command-line and GUI interfaces for testing SMB file transfer performance.
    It copies files from a source location to a destination while measuring transfer speeds and collecting
    system information including CPU frequency, power settings, Zscaler status, and network details.
    
    The script offers detailed progress tracking, error handling, and generates detailed reports
    including transfer statistics, system configuration, and network diagnostics.

.PARAMETER SourcePath
    Specifies the source path for file transfer. Supports both local paths and UNC network paths.
    This parameter is mandatory when not using the GUI interface.

.PARAMETER DestinationPath
    Specifies the destination path where files will be copied. The directory will be created if it doesn't exist.
    This parameter is mandatory when not using the GUI interface.

.PARAMETER Recurse
    When specified, includes subdirectories in the file transfer operation.
    Default behavior only processes files in the root of the source directory.

.PARAMETER ShowGUI
    Controls whether to display the graphical user interface for interactive operation.
    Valid values: "Yes" or "No" (default: "No")
    When set to "Yes", launches a WPF-based GUI for easy path selection and operation monitoring.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Console output displaying transfer statistics, system information, and performance metrics.
    GUI mode provides real-time progress updates in a dedicated text output area.

.EXAMPLE
    Measure-SMBTransferSpeed -SourcePath "\\server\share\folder" -DestinationPath "C:\temp" -Recurse -Runs 5
    
    Copies all files and subdirectories from the network share to the local destination,
    measuring transfer speed and displaying system metrics.

.EXAMPLE
    Measure-SMBTransferSpeed -ShowGUI Yes
    
    Launches the graphical user interface for interactive file transfer testing.

.NOTES
    File Name      : Measure-SMBTransferSpeed.ps1
    Author         : Mattias Melkersen
    Version        : 1.0.0
    Prerequisite   : PowerShell 5.1 or later
    Framework      : .NET Framework 4.5+ (for GUI functionality)
    
    System Requirements:
    - Windows PowerShell 5.1 or PowerShell 7+
    - .NET Framework 4.5+ for GUI components
    - Appropriate network permissions for SMB access
    - Administrative privileges may be required for some system information queries
    
    Features:
    - Real-time transfer speed calculation
    - System performance metrics collection
    - Zscaler VPN detection and status reporting
    - DNS resolution for network targets
    - Power management and CPU frequency monitoring
    - Progress tracking with detailed statistics
    - Both command-line and GUI operation modes
    - Error handling and validation

.LINK
    https://docs.microsoft.com/en-us/powershell/
    https://learn.microsoft.com/en-us/windows/win32/power/power-setting-guids 

.FUNCTIONALITY
    Network Performance Testing, File Transfer Utilities, System Diagnostics
#>
function Measure-SMBTransferSpeed {
    param(
        [Parameter(Mandatory=$false)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationPath,
        
        [switch]$Recurse,
        
        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 50)]
        [int]$Runs = 1,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Yes", "No")]
        [string]$ShowGUI = "No",
        
        [switch]$CheckSignature
    )
    
    if ($ShowGUI -eq "Yes") {
        Show-SMBTransferGUI
        return
    }
    
    # Validate required parameters when not using GUI
    if (-not $SourcePath -or -not $DestinationPath) {
        Write-Error "SourcePath and DestinationPath are required when not using GUI"
        return
    }
    
    # Get system information
    $cpuInfo = Get-WmiObject -Class Win32_Processor | Select-Object -First 1
    $cpuFrequencyMHz = $cpuInfo.CurrentClockSpeed
    $cpuFrequencyGHz = [math]::Round($cpuFrequencyMHz / 1000, 2)
    
    $battery = Get-WmiObject -Class Win32_Battery
    $powerSource = if ($battery -and $battery.BatteryStatus -eq 2) { "AC Power" } else { "Battery" }
    
    # Get active power scheme GUID and translate to human readable name
    $activeSchemeGuid = (powercfg /getactivescheme).Split(':')[1].Trim().Split('(')[0].Trim()
    
    # Define power scheme GUID mappings
    $powerSchemeMap = @{
        '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
        '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
        'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'
        'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Ultimate Performance'
    }
    
    # Get human readable name or use GUID if not found
    $powerScheme = if ($powerSchemeMap.ContainsKey($activeSchemeGuid)) {
        $powerSchemeMap[$activeSchemeGuid]
    } else {
        "Custom ($activeSchemeGuid)"
    }
    
    # Check digital signature settings if requested
    $enableSecuritySignature = "N/A"
    $requireSecuritySignature = "N/A"
    
    if ($CheckSignature) {
        try {
            $enableSignatureValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
            $enableSecuritySignature = if ($enableSignatureValue.EnableSecuritySignature -eq 1) { "Enabled" } elseif ($enableSignatureValue.EnableSecuritySignature -eq 0) { "Disabled" } else { "Not configured" }
            
            $requireSignatureValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
            $requireSecuritySignature = if ($requireSignatureValue.RequireSecuritySignature -eq 1) { "Enabled" } elseif ($requireSignatureValue.RequireSecuritySignature -eq 0) { "Disabled" } else { "Not configured" }
        }
        catch {
            $enableSecuritySignature = "Check failed"
            $requireSecuritySignature = "Check failed"
        }
    }
    
    # Check Zscaler status
    $zscalerStatus = "Not installed"
    $zpaStatus = "N/A"
    
    try {
        # Check if Zscaler service is running
        $zscalerService = Get-Service -Name "ZSAService" -ErrorAction SilentlyContinue
        if ($zscalerService) {
            $zscalerStatus = if ($zscalerService.Status -eq 'Running') { "Active" } else { "Inactive" }
            
            # Check for ZPA (Private Access) status from registry
            try {
                $zpaAuthState = Get-ItemProperty -Path "HKCU:\Software\Zscaler\App" -Name "ZPAAuth_State" -ErrorAction SilentlyContinue
                if ($zpaAuthState -and $zpaAuthState.ZPAAuth_State -eq "AUTHENTICATED") {
                    $zpaStatus = "Active"
                } else {
                    $zpaStatus = "N/A"
                }
            }
            catch {
                $zpaStatus = "N/A"
            }
        }
    }
    catch {
        $zscalerStatus = "Check failed"
        $zpaStatus = "N/A"
    }
    
    # Extract hostname from UNC path and perform nslookup
    $sourceHostname = $null
    $sourceIP = $null
    if ($SourcePath -match '^\\\\([^\\]+)') {
        $sourceHostname = $matches[1]
        try {
            $nslookup = Resolve-DnsName -Name $sourceHostname -ErrorAction Stop
            $sourceIP = ($nslookup | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1).IPAddress
        }
        catch {
            $sourceIP = "DNS lookup failed"
        }
    }
    
    # Validate source path exists
    if (!(Test-Path $SourcePath)) {
        Write-Error "Source path does not exist: $SourcePath"
        return
    }
    
    # Calculate total size once
    Write-Host "Calculating total size..." -ForegroundColor Yellow
    if ($Recurse) {
        $files = Get-ChildItem -Path $SourcePath -Recurse -File
    } else {
        $files = Get-ChildItem -Path $SourcePath -File
    }
    
    $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
    $totalSizeMB = [math]::Round($totalSize / 1MB, 2)
    $totalFiles = $files.Count
    Write-Host "Total files: $totalFiles, Total size: $totalSizeMB MB" -ForegroundColor Green
    
    # Arrays to store results from each run
    $durations = @()
    $transferSpeeds = @()
    
    Write-Host "`nStarting $Runs transfer test(s)..." -ForegroundColor Green
    
    for ($run = 1; $run -le $Runs; $run++) {
        Write-Host "`nRun $run of $Runs" -ForegroundColor Yellow
        
        # Create unique destination folder for each run
        $runDestination = if ($Runs -gt 1) {
            Join-Path $DestinationPath "Run$run"
        } else {
            $DestinationPath
        }
        
        # Create destination directory if it doesn't exist
        if (!(Test-Path $runDestination)) {
            New-Item -ItemType Directory -Path $runDestination -Force | Out-Null
        } elseif ($Runs -gt 1) {
            # Clean destination folder for multiple runs to ensure consistent results
            Remove-Item -Path $runDestination -Recurse -Force
            New-Item -ItemType Directory -Path $runDestination -Force | Out-Null
        }
        
        # Start timing
        $startTime = Get-Date
        Write-Host "Starting transfer at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Green
        
        try {
            # Copy files with progress tracking
            $currentFile = 0
            $copiedSize = 0
            
            foreach ($file in $files) {
                $currentFile++
                $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\')
                $destFile = Join-Path -Path $runDestination -ChildPath $relativePath
                $destDir = Split-Path -Path $destFile -Parent
                
                # Create destination directory if needed
                if (!(Test-Path $destDir)) {
                    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                }
                
                # Copy the file
                Copy-Item -Path $file.FullName -Destination $destFile -Force
                
                # Update progress
                $copiedSize += $file.Length
                $percentComplete = [math]::Round(($copiedSize / $totalSize) * 100, 1)
                $copiedSizeMB = [math]::Round($copiedSize / 1MB, 2)
                
                Write-Progress -Activity "Copying Files (Run $run of $Runs)" -Status "File $currentFile of $totalFiles - $($file.Name)" -PercentComplete $percentComplete -CurrentOperation "$copiedSizeMB MB of $totalSizeMB MB copied ($percentComplete%)"
            }
            
            Write-Progress -Activity "Copying Files" -Completed
            
            # End timing
            $endTime = Get-Date
            $duration = $endTime - $startTime
            
            # Calculate transfer speed
            $transferSpeedMBps = [math]::Round($totalSizeMB / $duration.TotalSeconds, 2)
            
            # Store results
            $durations += $duration.TotalSeconds
            $transferSpeeds += $transferSpeedMBps
            
            # Display run results
            Write-Host "Run $run completed!" -ForegroundColor Green
            Write-Host "Duration: $($duration.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Cyan
            Write-Host "Speed: $transferSpeedMBps MB/s" -ForegroundColor Yellow
            # Add a 5-second pause between runs
            if ($run -lt $Runs) {
                Write-Host "Pausing for 5 seconds before next run..." -ForegroundColor Yellow
                Start-Sleep -Seconds 5
            }
        }
        catch {
            Write-Progress -Activity "Copying Files" -Completed
            Write-Error "Run $run failed: $($_.Exception.Message)"
            continue
        }
    }
    
    # Calculate and display average results
    if ($durations.Count -gt 0) {
        $avgDurationSeconds = ($durations | Measure-Object -Average).Average
        $avgDuration = [TimeSpan]::FromSeconds($avgDurationSeconds)
        $avgSpeed = ($transferSpeeds | Measure-Object -Average).Average
        $minSpeed = ($transferSpeeds | Measure-Object -Minimum).Minimum
        $maxSpeed = ($transferSpeeds | Measure-Object -Maximum).Maximum
        
        Write-Host "TRANSFER SUMMARY" -ForegroundColor Yellow
        Write-Host "Successful runs: $($durations.Count) of $Runs" -ForegroundColor Cyan
        Write-Host "Total size per run: $totalSizeMB MB" -ForegroundColor Cyan
        Write-Host "Average duration: $($avgDuration.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Green
        Write-Host "Average speed: $([math]::Round($avgSpeed, 2)) MB/s" -ForegroundColor Yellow
        if ($durations.Count -gt 1) {
            Write-Host "Minimum speed: $([math]::Round($minSpeed, 2)) MB/s" -ForegroundColor Magenta
            Write-Host "Maximum speed: $([math]::Round($maxSpeed, 2)) MB/s" -ForegroundColor Magenta
            Write-Host "Speed variation: $([math]::Round($maxSpeed - $minSpeed, 2)) MB/s" -ForegroundColor Magenta
        }
        Write-Host "CPU frequency: $cpuFrequencyGHz GHz" -ForegroundColor Magenta
        Write-Host "Power source: $powerSource" -ForegroundColor Magenta
        Write-Host "Power scheme: $powerScheme" -ForegroundColor Magenta
        Write-Host "Zscaler status: $zscalerStatus" -ForegroundColor Magenta
        Write-Host "ZPA (Private Access): $zpaStatus" -ForegroundColor Magenta
        if ($CheckSignature) {
            Write-Host "SMB Security Signature (Enable): $enableSecuritySignature" -ForegroundColor Magenta
            Write-Host "SMB Security Signature (Require): $requireSecuritySignature" -ForegroundColor Magenta
        }
        if ($sourceHostname) {
            Write-Host "Source hostname: $sourceHostname" -ForegroundColor Magenta
            Write-Host "Source IP: $sourceIP" -ForegroundColor Magenta
        }
    }
}

function Show-SMBTransferGUI {
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName System.Windows.Forms

    [xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="SMB Transfer Speed Tester" Height="850" Width="800"
        WindowStartupLocation="CenterScreen">
    <Grid Margin="10">
        <TabControl>
            <TabItem Header="Transfer Test">
                <Grid Margin="10">
                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="*"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>
                    
                    <Label Grid.Row="0" Content="Source Path:" FontWeight="Bold"/>
                    <Grid Grid.Row="1" Margin="0,5,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="txtSourcePath" Grid.Column="0" Height="25" VerticalContentAlignment="Center"/>
                        <Button Name="btnBrowseSource" Grid.Column="1" Content="Browse" Width="80" Height="25" Margin="5,0,0,0"/>
                    </Grid>
                    
                    <Label Grid.Row="2" Content="Destination Path:" FontWeight="Bold"/>
                    <Grid Grid.Row="3" Margin="0,5,0,10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <TextBox Name="txtDestinationPath" Grid.Column="0" Height="25" VerticalContentAlignment="Center"/>
                        <Button Name="btnBrowseDestination" Grid.Column="1" Content="Browse" Width="80" Height="25" Margin="5,0,0,0"/>
                    </Grid>
                    
                    <Grid Grid.Row="4" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <CheckBox Name="chkRecurse" Grid.Column="0" Content="Include subdirectories (Recurse)" Margin="0,0,20,0"/>
                        <Label Grid.Column="1" Content="Number of runs:" FontWeight="Bold" VerticalAlignment="Center"/>
                        <ComboBox Name="cmbRuns" Grid.Column="2" Width="60" Height="25" Margin="5,0,0,0" SelectedIndex="0"/>
                    </Grid>
                    
                    <Grid Grid.Row="5" Margin="0,0,0,15">
                        <CheckBox Name="chkCheckSignature" Content="Check SMB Security Signature settings" FontWeight="Bold"/>
                    </Grid>
                    
                    <RichTextBox Name="txtOutput" Grid.Row="7" IsReadOnly="True" VerticalScrollBarVisibility="Auto" 
                                 Background="Black" FontFamily="Consolas" FontSize="12"
                                 Margin="0,0,0,10"/>
                    
                    <Grid Grid.Row="8">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Button Name="btnStart" Grid.Column="0" Content="Start Transfer" Height="35" FontWeight="Bold" Margin="0,0,5,0"/>
                        <Button Name="btnCopyResults" Grid.Column="1" Content="Copy Results" Height="35" Width="100" IsEnabled="False"/>
                    </Grid>
                </Grid>
            </TabItem>
            
            <TabItem Header="SMB Documentation">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                    <StackPanel Margin="10">
                        <TextBlock FontSize="16" FontWeight="Bold" Text="SMB Configuration Guide and Best Practices (use on your own risk!)" Margin="0,0,0,20" 
                                   Foreground="DarkBlue"/>
                        
                        <Expander Header="SMB Protocol Versions" IsExpanded="True" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock TextWrapping="Wrap" Margin="0,0,0,10">
                                    <Run FontWeight="Bold">SMB 1.0/CIFS:</Run> Legacy protocol - DISABLE for security reasons<LineBreak/>
                                    <Run FontWeight="Bold">SMB 2.0:</Run> Windows Vista/Server 2008 - Improved performance<LineBreak/>
                                    <Run FontWeight="Bold">SMB 2.1:</Run> Windows 7/Server 2008 R2 - Added opportunistic locking<LineBreak/>
                                    <Run FontWeight="Bold">SMB 3.0:</Run> Windows 8/Server 2012 - Encryption, multichannel<LineBreak/>
                                    <Run FontWeight="Bold">SMB 3.0.2:</Run> Windows 8.1/Server 2012 R2 - Performance improvements<LineBreak/>
                                    <Run FontWeight="Bold">SMB 3.1.1:</Run> Windows 10/Server 2016+ - Enhanced security, pre-authentication integrity
                                </TextBlock>
                            </StackPanel>
                        </Expander>
                        
                        <Expander Header="Performance Optimization" IsExpanded="False" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock FontWeight="Bold" Text="Registry Optimizations:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Increase SMB buffer sizes (requires reboot)&#x0A;[HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]&#x0A;SizReqBuf = 17424 (REG_DWORD)&#x0A;MaxMpxCt = 2048 (REG_DWORD)&#x0A;&#x0A;# Client-side optimizations&#x0A;[HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters]&#x0A;MaxCollectionCount = 32 (REG_DWORD)&#x0A;MaxCmds = 2048 (REG_DWORD)"/>
                                
                                <TextBlock FontWeight="Bold" Text="PowerShell Commands:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Enable SMB Multichannel (SMB 3.0+)&#x0A;Set-SmbClientConfiguration -EnableMultiChannel $true&#x0A;&#x0A;# Disable SMB1 (security best practice)&#x0A;Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol&#x0A;&#x0A;# Check SMB configuration&#x0A;Get-SmbClientConfiguration&#x0A;Get-SmbServerConfiguration"/>
                            </StackPanel>
                        </Expander>
                        
                        <Expander Header="Security Configuration" IsExpanded="False" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock FontWeight="Bold" Text="SMB Signing:" Margin="0,10,0,5"/>
                                <TextBlock TextWrapping="Wrap" Margin="0,0,0,10">
                                    SMB signing provides authentication and integrity protection for SMB connections.
                                    <LineBreak/><LineBreak/>
                                    <Run FontWeight="Bold">Enable (Recommended):</Run> Provides security without major performance impact
                                    <LineBreak/>
                                    <Run FontWeight="Bold">Require:</Run> Maximum security but may impact performance
                                </TextBlock>
                                
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Enable SMB signing via PowerShell&#x0A;Set-SmbClientConfiguration -RequireSecuritySignature $true&#x0A;Set-SmbServerConfiguration -RequireSecuritySignature $true&#x0A;&#x0A;# Via Registry (Client)&#x0A;[HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters]&#x0A;RequireSecuritySignature = 1 (REG_DWORD)&#x0A;EnableSecuritySignature = 1 (REG_DWORD)&#x0A;&#x0A;# Via Registry (Server)&#x0A;[HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]&#x0A;RequireSecuritySignature = 1 (REG_DWORD)&#x0A;EnableSecuritySignature = 1 (REG_DWORD)"/>
                                
                                <TextBlock FontWeight="Bold" Text="SMB Encryption:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Enable SMB encryption (SMB 3.0+)&#x0A;Set-SmbServerConfiguration -EncryptData $true&#x0A;Set-SmbShare -Name 'ShareName' -EncryptData $true"/>
                            </StackPanel>
                        </Expander>
                        
                        <Expander Header="Network Configuration" IsExpanded="False" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock FontWeight="Bold" Text="Network Adapter Settings:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Check and configure RSS (Receive Side Scaling)&#x0A;Get-NetAdapterRss&#x0A;Set-NetAdapterRss -Name 'Ethernet' -Enabled $true&#x0A;&#x0A;# Configure jumbo frames (9000 bytes) for Gigabit+ networks&#x0A;Set-NetAdapterAdvancedProperty -Name 'Ethernet' -DisplayName 'Jumbo Packet' -DisplayValue '9014 Bytes'&#x0A;&#x0A;# Disable TCP chimney offload (can cause issues)&#x0A;netsh int tcp set global chimney=disabled&#x0A;&#x0A;# Enable TCP window auto-tuning&#x0A;netsh int tcp set global autotuninglevel=normal"/>
                                
                                <TextBlock FontWeight="Bold" Text="SMB Multichannel:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Verify multichannel capabilities&#x0A;Get-SmbMultichannelCapability&#x0A;Get-SmbMultichannelConnection&#x0A;&#x0A;# Configure SMB client for multichannel&#x0A;Set-SmbClientConfiguration -EnableMultiChannel $true -ConnectionCountPerRssNetworkInterface 4"/>
                            </StackPanel>
                        </Expander>
                        
                        <Expander Header="Troubleshooting Tools" IsExpanded="False" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock FontWeight="Bold" Text="PowerShell Diagnostics:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Check SMB connections&#x0A;Get-SmbConnection&#x0A;&#x0A;# View SMB shares&#x0A;Get-SmbShare&#x0A;&#x0A;# Check SMB client/server configuration&#x0A;Get-SmbClientConfiguration&#x0A;Get-SmbServerConfiguration&#x0A;&#x0A;# Monitor SMB performance counters&#x0A;Get-Counter '\SMB Client Shares(*)\*'&#x0A;Get-Counter '\SMB Server Shares(*)\*'&#x0A;&#x0A;# Test network connectivity&#x0A;Test-NetConnection -ComputerName 'servername' -Port 445"/>
                                
                                <TextBlock FontWeight="Bold" Text="Event Logs:" Margin="0,10,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# Check SMB client events&#x0A;Get-WinEvent -LogName 'Microsoft-Windows-SmbClient/Connectivity'&#x0A;Get-WinEvent -LogName 'Microsoft-Windows-SmbClient/Security'&#x0A;&#x0A;# Check SMB server events&#x0A;Get-WinEvent -LogName 'Microsoft-Windows-SmbServer/Connectivity'&#x0A;Get-WinEvent -LogName 'Microsoft-Windows-SmbServer/Security'"/>
                            </StackPanel>
                        </Expander>
                        
                        <Expander Header="Common Issues and Solutions" IsExpanded="False" Margin="0,0,0,10">
                            <StackPanel Margin="20,10,0,0">
                                <TextBlock FontWeight="Bold" Text="Performance Issues:" Margin="0,0,0,5"/>
                                <TextBlock TextWrapping="Wrap" Margin="0,0,0,10">
                                    - <Run FontWeight="Bold">Slow transfers:</Run> Check SMB version, enable multichannel, verify network configuration
                                    <LineBreak/>
                                    - <Run FontWeight="Bold">High CPU usage:</Run> Disable SMB1, check signing requirements
                                    <LineBreak/>
                                    - <Run FontWeight="Bold">Timeouts:</Run> Adjust resilient handle timeouts, check network stability
                                </TextBlock>
                                
                                <TextBlock FontWeight="Bold" Text="Security Issues:" Margin="0,10,0,5"/>
                                <TextBlock TextWrapping="Wrap" Margin="0,0,0,10">
                                    - <Run FontWeight="Bold">Authentication failures:</Run> Check signing requirements, verify credentials
                                    <LineBreak/>
                                    - <Run FontWeight="Bold">Access denied:</Run> Verify NTFS and share permissions
                                    <LineBreak/>
                                    - <Run FontWeight="Bold">Man-in-the-middle:</Run> Enable SMB encryption for sensitive data
                                </TextBlock>
                                
                                <TextBlock FontWeight="Bold" Text="Connectivity Issues:" Margin="0,10,0,5"/>
                                <TextBlock TextWrapping="Wrap" Margin="0,0,0,10">
                                    - <Run FontWeight="Bold">Cannot connect:</Run> Check firewall rules (port 445), verify DNS resolution
                                    <LineBreak/>
                                    - <Run FontWeight="Bold">Intermittent disconnections:</Run> Check power management, network adapter settings
                                </TextBlock>
                                
                                <TextBlock FontWeight="Bold" Text="Microsoft Resources:" Margin="0,15,0,5"/>
                                <TextBox IsReadOnly="True" TextWrapping="Wrap" Background="LightGray" Padding="5" Margin="0,0,0,10"
                                         Text="# SMB Troubleshooting and Best Practices&#x0A;https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smb-known-issues&#x0A;&#x0A;# SMB Performance Tuning&#x0A;https://docs.microsoft.com/en-us/windows-server/administration/performance-tuning/role/file-server/smb-file-server&#x0A;&#x0A;# SMB Security Considerations&#x0A;https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security&#x0A;&#x0A;# SMB Direct and RDMA Performance&#x0A;https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-direct&#x0A;&#x0A;# Windows Server SMB Known Issues&#x0A;https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/smb-known-issues&#x0A;&#x0A;# SMB Multichannel Troubleshooting&#x0A;https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/smb-multichannel-troubleshooting"/>
                            </StackPanel>
                        </Expander>
                    </StackPanel>
                </ScrollViewer>
            </TabItem>
        </TabControl>
    </Grid>
</Window>
"@

    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Get controls
    $txtSourcePath = $window.FindName("txtSourcePath")
    $txtDestinationPath = $window.FindName("txtDestinationPath")
    $btnBrowseSource = $window.FindName("btnBrowseSource")
    $btnBrowseDestination = $window.FindName("btnBrowseDestination")
    $chkRecurse = $window.FindName("chkRecurse")
    $chkCheckSignature = $window.FindName("chkCheckSignature")
    $cmbRuns = $window.FindName("cmbRuns")
    $txtOutput = $window.FindName("txtOutput")
    $btnStart = $window.FindName("btnStart")
    $btnCopyResults = $window.FindName("btnCopyResults")

    # Populate the runs dropdown with values 1-15
    for ($i = 1; $i -le 15; $i++) {
        $cmbRuns.Items.Add($i) | Out-Null
    }
    $cmbRuns.SelectedIndex = 0  # Default to 1

    # Create a synchronized hashtable to share results between runspaces
    $script:syncHash = [hashtable]::Synchronized(@{})
    $script:syncHash.resultsText = ""

    # Browse source folder
    $btnBrowseSource.Add_Click({
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.Description = "Select source folder"
        if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $txtSourcePath.Text = $folderDialog.SelectedPath
        }
    })

    # Browse destination folder
    $btnBrowseDestination.Add_Click({
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $folderDialog.Description = "Select destination folder"
        if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $txtDestinationPath.Text = $folderDialog.SelectedPath
        }
    })

    # Copy results to clipboard
    $btnCopyResults.Add_Click({
        try {
            # Get the plain text content from the RichTextBox
            $textRange = New-Object System.Windows.Documents.TextRange($txtOutput.Document.ContentStart, $txtOutput.Document.ContentEnd)
            $plainText = $textRange.Text
            
            if (-not [string]::IsNullOrWhiteSpace($plainText)) {
                [System.Windows.Clipboard]::SetText($plainText.Trim())
                [System.Windows.MessageBox]::Show("Results copied to clipboard!", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
            } else {
                [System.Windows.MessageBox]::Show("No results to copy. Please run a transfer first.", "No Results", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning)
            }
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to copy results: $($_.Exception.Message)", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        }
    })

    # Helper function to add colored text to RichTextBox
    function Add-ColoredText {
        param(
            [string]$Text,
            [string]$Color = "White"
        )
        
        $window.Dispatcher.Invoke([Action]{
            $paragraph = New-Object System.Windows.Documents.Paragraph
            $paragraph.Margin = New-Object System.Windows.Thickness(0)
            $run = New-Object System.Windows.Documents.Run
            $run.Text = $Text
            
            switch ($Color) {
                "Green" { $run.Foreground = [System.Windows.Media.Brushes]::LightGreen }
                "Yellow" { $run.Foreground = [System.Windows.Media.Brushes]::Yellow }
                "Cyan" { $run.Foreground = [System.Windows.Media.Brushes]::Cyan }
                "Magenta" { $run.Foreground = [System.Windows.Media.Brushes]::Magenta }
                "Red" { $run.Foreground = [System.Windows.Media.Brushes]::Red }
                default { $run.Foreground = [System.Windows.Media.Brushes]::White }
            }
            
            $paragraph.Inlines.Add($run)
            $txtOutput.Document.Blocks.Add($paragraph)
            $txtOutput.ScrollToEnd()
        })
        
        # Update the synchronized results text
        $script:syncHash.resultsText += $Text + "`r`n"
    }

    # Start transfer
    $btnStart.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtSourcePath.Text) -or [string]::IsNullOrWhiteSpace($txtDestinationPath.Text)) {
            [System.Windows.MessageBox]::Show("Please specify both source and destination paths.", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            return
        }

        $txtOutput.Document.Blocks.Clear()
        $script:syncHash.resultsText = ""
        $btnStart.IsEnabled = $false
        $btnCopyResults.IsEnabled = $false

        # Run transfer in background
        $runspace = [runspacefactory]::CreateRunspace()
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable("SourcePath", $txtSourcePath.Text)
        $runspace.SessionStateProxy.SetVariable("DestinationPath", $txtDestinationPath.Text)
        $runspace.SessionStateProxy.SetVariable("Recurse", $chkRecurse.IsChecked)
        $runspace.SessionStateProxy.SetVariable("CheckSignature", $chkCheckSignature.IsChecked)
        $runspace.SessionStateProxy.SetVariable("NumberOfRuns", [int]$cmbRuns.SelectedItem)
        $runspace.SessionStateProxy.SetVariable("window", $window)
        $runspace.SessionStateProxy.SetVariable("txtOutput", $txtOutput)
        $runspace.SessionStateProxy.SetVariable("btnStart", $btnStart)
        $runspace.SessionStateProxy.SetVariable("btnCopyResults", $btnCopyResults)

        $powershell = [powershell]::Create()
        $powershell.Runspace = $runspace
        
        # Import the main function into the runspace
        $functionDef = ${function:Measure-SMBTransferSpeed}.ToString()
        $runspace.SessionStateProxy.SetVariable("MeasureSMBTransferSpeedFunction", $functionDef)
        
        # Pass the synchronized hashtable to the runspace
        $runspace.SessionStateProxy.SetVariable("syncHash", $script:syncHash)
        
        $powershell.AddScript({
            # Define the function in the runspace
            Invoke-Expression "function Measure-SMBTransferSpeed { $MeasureSMBTransferSpeedFunction }"
            
            # Helper function to add colored text to RichTextBox
            function Add-ColoredText {
                param(
                    [string]$Text,
                    [string]$Color = "White"
                )
                
                $window.Dispatcher.Invoke([Action]{
                    $paragraph = New-Object System.Windows.Documents.Paragraph
                    $paragraph.Margin = New-Object System.Windows.Thickness(0)
                    $run = New-Object System.Windows.Documents.Run
                    $run.Text = $Text
                    
                    switch ($Color) {
                        "Green" { $run.Foreground = [System.Windows.Media.Brushes]::LightGreen }
                        "Yellow" { $run.Foreground = [System.Windows.Media.Brushes]::Yellow }
                        "Cyan" { $run.Foreground = [System.Windows.Media.Brushes]::Cyan }
                        "Magenta" { $run.Foreground = [System.Windows.Media.Brushes]::Magenta }
                        "Red" { $run.Foreground = [System.Windows.Media.Brushes]::Red }
                        default { $run.Foreground = [System.Windows.Media.Brushes]::White }
                    }
                    
                    $paragraph.Inlines.Add($run)
                    $txtOutput.Document.Blocks.Add($paragraph)
                    $txtOutput.ScrollToEnd()
                })
                
                # Update the synchronized results text
                $syncHash.resultsText += $Text + "`r`n"
            }
            
            function Write-Host {
                param(
                    [Parameter(Position=0)]
                    [string]$Object = "",
                    [string]$ForegroundColor = "White"
                )
                Add-ColoredText -Text $Object -Color $ForegroundColor
            }
            
            function Write-Progress {
                param(
                    [string]$Activity,
                    [string]$Status,
                    [int]$PercentComplete,
                    [string]$CurrentOperation,
                    [switch]$Completed
                )
                if (-not $Completed) {
                    Add-ColoredText -Text "Progress: $Activity - $Status ($PercentComplete%)" -Color "Cyan"
                }
            }
            
            # Function to run multiple transfer tests
            function Run-MultipleTransfers {
                param(
                    [string]$SourcePath,
                    [string]$DestinationPath,
                    [bool]$Recurse,
                    [bool]$CheckSignature,
                    [int]$NumberOfRuns
                )
                
                $allDurations = @()
                $allSpeeds = @()
                $totalSize = 0
                
                Add-ColoredText -Text "Starting $NumberOfRuns transfer test(s)..." -Color "Green"
                Add-ColoredText -Text "================================================" -Color "Yellow"
                
                for ($run = 1; $run -le $NumberOfRuns; $run++) {
                    Add-ColoredText -Text "`nRun $run of $NumberOfRuns" -Color "Yellow"
                    Add-ColoredText -Text "----------------------------------------" -Color "Yellow"
                    
                    # Create a unique destination folder for each run to avoid conflicts
                    $runDestination = Join-Path $DestinationPath "Run$run"
                    
                    try {
                        # Remove destination folder if it exists to ensure clean test
                        if (Test-Path $runDestination) {
                            Remove-Item -Path $runDestination -Recurse -Force
                        }
                        
                        # Get the result from the transfer function with CheckSignature parameter
                        $splatParams = @{
                            SourcePath = $SourcePath
                            DestinationPath = $runDestination
                            Recurse = $Recurse
                        }
                        if ($CheckSignature) {
                            $splatParams.CheckSignature = $true
                        }
                        
                        $result = Measure-SMBTransferSpeed @splatParams
                        
                        # Since we modified the function to track internally, we need to track duration manually
                        $startTime = Get-Date
                        
                        # Validate source path exists
                        if (!(Test-Path $SourcePath)) {
                            throw "Source path does not exist: $SourcePath"
                        }
                        
                        # Create destination directory if it doesn't exist
                        if (!(Test-Path $runDestination)) {
                            New-Item -ItemType Directory -Path $runDestination -Force | Out-Null
                        }
                        
                        # Get files to copy for timing purposes
                        if ($Recurse) {
                            $files = Get-ChildItem -Path $SourcePath -Recurse -File
                        } else {
                            $files = Get-ChildItem -Path $SourcePath -File
                        }
                        
                        $runTotalSize = ($files | Measure-Object -Property Length -Sum).Sum
                        $runTotalSizeMB = [math]::Round($runTotalSize / 1MB, 2)
                        
                        if ($run -eq 1) {
                            $totalSize = $runTotalSizeMB
                        }
                        
                        # Copy files
                        foreach ($file in $files) {
                            $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\')
                            $destFile = Join-Path -Path $runDestination -ChildPath $relativePath
                            $destDir = Split-Path -Path $destFile -Parent
                            
                            # Create destination directory if needed
                            if (!(Test-Path $destDir)) {
                                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
                            }
                            
                            # Copy the file
                            Copy-Item -Path $file.FullName -Destination $destFile -Force
                        }
                        
                        $endTime = Get-Date
                        $duration = $endTime - $startTime
                        $transferSpeedMBps = [math]::Round($runTotalSizeMB / $duration.TotalSeconds, 2)
                        
                        $allDurations += $duration.TotalSeconds
                        $allSpeeds += $transferSpeedMBps
                        
                        Add-ColoredText -Text "Run $run completed - Duration: $($duration.ToString('hh\:mm\:ss\.fff')) - Speed: $transferSpeedMBps MB/s" -Color "Green"
                        
                        # Clean up the run folder
                        if (Test-Path $runDestination) {
                            Remove-Item -Path $runDestination -Recurse -Force
                        }
                    }
                    catch {
                        Add-ColoredText -Text "Run $run failed: $($_.Exception.Message)" -Color "Red"
                    }
                }
                
                # Calculate averages
                if ($allDurations.Count -gt 0) {
                    $avgDurationSeconds = ($allDurations | Measure-Object -Average).Average
                    $avgSpeed = ($allSpeeds | Measure-Object -Average).Average
                    $avgDuration = [TimeSpan]::FromSeconds($avgDurationSeconds)
                    
                    $minSpeed = ($allSpeeds | Measure-Object -Minimum).Minimum
                    $maxSpeed = ($allSpeeds | Measure-Object -Maximum).Maximum
                    
                    Add-ColoredText -Text "`n================================================" -Color "Yellow"
                    Add-ColoredText -Text "SUMMARY STATISTICS" -Color "Yellow"
                    Add-ColoredText -Text "================================================" -Color "Yellow"
                    Add-ColoredText -Text "Number of runs: $NumberOfRuns" -Color "Cyan"
                    Add-ColoredText -Text "Total size per run: $totalSize MB" -Color "Cyan"
                    Add-ColoredText -Text "Average duration: $($avgDuration.ToString('hh\:mm\:ss\.fff'))" -Color "Green"
                    Add-ColoredText -Text "Average speed: $([math]::Round($avgSpeed, 2)) MB/s" -Color "Green"
                    Add-ColoredText -Text "Minimum speed: $([math]::Round($minSpeed, 2)) MB/s" -Color "Magenta"
                    Add-ColoredText -Text "Maximum speed: $([math]::Round($maxSpeed, 2)) MB/s" -Color "Magenta"
                    Add-ColoredText -Text "Speed variation: $([math]::Round($maxSpeed - $minSpeed, 2)) MB/s" -Color "Magenta"
                    Add-ColoredText -Text "================================================" -Color "Yellow"
                }
            }
            
            try {
                Run-MultipleTransfers -SourcePath $SourcePath -DestinationPath $DestinationPath -Recurse $Recurse -CheckSignature $CheckSignature -NumberOfRuns $NumberOfRuns
            }
            catch {
                Add-ColoredText -Text "Error: $($_.Exception.Message)" -Color "Red"
            }
            finally {
                $window.Dispatcher.Invoke([Action]{
                    $btnStart.IsEnabled = $true
                    $btnCopyResults.IsEnabled = $true
                })
            }
        })
        
        $asyncResult = $powershell.BeginInvoke()
        
        # Monitor completion
        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({
            if ($asyncResult.IsCompleted) {
                $timer.Stop()
                $runspace.Close()
                $powershell.Dispose()
            }
        })
        $timer.Start()
    })

    $window.ShowDialog() | Out-Null
}

# Example usage:
# Measure-SMBTransferSpeed -ShowGUI Yes
# Measure-SMBTransferSpeed -SourcePath "\\server\yourfiles" -DestinationPath "C:\temp" -Recurse -Runs 1 -ShowGUI No -CheckSignature