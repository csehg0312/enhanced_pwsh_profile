#region Profile Configuration
## Enhanced PowerShell Profile for Backend & DevOps Engineers
## Author: PowerShell Profile Generator
## Version: 2.0

# Profile performance tracking
$ProfileStartTime = Get-Date
#endregion

#region Registry Drives
## Map PSDrives to other registry hives for easier access
if (!(Test-Path HKCR:)) {
    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
}
#endregion

#region Enhanced Custom Prompt
## Enhanced prompt with Git status, admin status, and debug context
function prompt {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal] $identity
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

    # Check for debug context
    $prefix = if (Test-Path Variable:/PSDebugContext) { '[DBG]: ' } else { '' }
    
    # Add admin indicator if elevated
    if ($principal.IsInRole($adminRole)) {
        $prefix = "[ADMIN]:$prefix"
    }

    # Git status integration
    $gitStatus = ""
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $gitBranch = git rev-parse --abbrev-ref HEAD 2>$null
        if ($gitBranch) {
            $gitStatus = " git:($gitBranch)"
            
            # Check for changes
            $gitChanges = git status --porcelain 2>$null
            if ($gitChanges) {
                $gitStatus += "*"
            }
        }
    }

    # Kubernetes context (if kubectl is available)
    $k8sContext = ""
    if (Get-Command kubectl -ErrorAction SilentlyContinue) {
        $currentContext = kubectl config current-context 2>$null
        if ($currentContext) {
            $k8sContext = " k8s:($currentContext)"
        }
    }

    # Azure context (if az cli is available)
    $azContext = ""
    if (Get-Command az -ErrorAction SilentlyContinue) {
        $azAccount = az account show --query name -o tsv 2>$null
        if ($azAccount) {
            $azContext = " az:($azAccount)"
        }
    }
    
    # Build the prompt with colors
    $locationColor = if ($principal.IsInRole($adminRole)) { 'Red' } else { 'Green' }
    $path = $PWD.Path.Replace($HOME, '~')
    
    Write-Host "$prefix" -NoNewline -ForegroundColor Red
    Write-Host "PS " -NoNewline -ForegroundColor White
    Write-Host "$path" -NoNewline -ForegroundColor $locationColor
    Write-Host "$gitStatus" -NoNewline -ForegroundColor Yellow
    Write-Host "$k8sContext" -NoNewline -ForegroundColor Blue
    Write-Host "$azContext" -NoNewline -ForegroundColor Cyan
    
    $suffix = $(if ($NestedPromptLevel -ge 1) { '>>' }) + '> '
    return $suffix
}
#endregion

#region PSReadLine Configuration

# Initialize PSStyle if not available (for PS versions < 7.2)
if (-not (Get-Variable PSStyle -ErrorAction SilentlyContinue)) {
    $esc = [char]0x1b
    $PSStyle = [pscustomobject]@{
        Foreground = @{
            Black   = "${esc}[30m"
            Red     = "${esc}[31m"
            Green   = "${esc}[32m"
            Yellow  = "${esc}[33m"
            Blue    = "${esc}[34m"
            Magenta = "${esc}[35m"
            Cyan    = "${esc}[36m"
            White   = "${esc}[37m"
            BrightBlack   = "${esc}[90m"
            BrightRed     = "${esc}[91m"
            BrightGreen   = "${esc}[92m"
            BrightYellow  = "${esc}[93m"
            BrightBlue    = "${esc}[94m"
            BrightMagenta = "${esc}[95m"
            BrightCyan    = "${esc}[96m"
            BrightWhite   = "${esc}[97m"
        }
        Background = @{
            Black   = "${esc}[40m"
            Red     = "${esc}[41m"
            Green   = "${esc}[42m"
            Yellow  = "${esc}[43m"
            Blue    = "${esc}[44m"
            Magenta = "${esc}[45m"
            Cyan    = "${esc}[46m"
            White   = "${esc}[47m"
            BrightBlack   = "${esc}[100m"
            BrightRed     = "${esc}[101m"
            BrightGreen   = "${esc}[102m"
            BrightYellow  = "${esc}[103m"
            BrightBlue    = "${esc}[104m"
            BrightMagenta = "${esc}[105m"
            BrightCyan    = "${esc}[106m"
            BrightWhite   = "${esc}[107m"
        }
        Reset      = "${esc}[0m"
    }
}

# Only configure PSReadLine if the module is available
if (Get-Module PSReadLine -ErrorAction SilentlyContinue) {
    $PSReadlineVersion = (Get-Module PSReadLine).Version

    # Base options that work in all versions
    $PSROptions = @{
        ContinuationPrompt = '  '
        HistorySearchCursorMovesToEnd = $true
    }

    # Add colors if PSStyle is available
    if ($PSStyle) {
        $PSROptions.Colors = @{
            Operator  = $PSStyle.Foreground.Magenta
            Parameter = $PSStyle.Foreground.Magenta
            Selection = $PSStyle.Background.BrightBlack
            Command   = $PSStyle.Foreground.Green
            String    = $PSStyle.Foreground.Cyan
            Variable  = $PSStyle.Foreground.Blue
        }
    }

    # Add version-specific features
    if ($PSReadlineVersion -ge [version]'2.1.0') {
        $PSROptions.PredictionSource = 'History'
        
        if ($PSReadlineVersion -ge [version]'2.2.0') {
            $PSROptions.PredictionViewStyle = 'ListView'
            
            if ($PSReadlineVersion -ge [version]'2.2.2') {
                if ($PSStyle) {
                    $PSROptions.Colors['InLinePrediction'] = $PSStyle.Foreground.BrightYellow + $PSStyle.Background.BrightBlack
                }
            }
        }
    }

    # Apply the options with error handling
    try {
        Set-PSReadLineOption @PSROptions -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to set some PSReadLine options: $_"
        # Try with minimal options
        try {
            Set-PSReadLineOption -ContinuationPrompt '  ' -HistorySearchCursorMovesToEnd $true
        }
        catch {
            Write-Warning "Could not configure basic PSReadLine options"
        }
    }

    # Set key bindings with error handling
    $keyBindings = @(
        @{Chord='Ctrl+f'; Function='ForwardWord'},
        @{Chord='Enter'; Function='ValidateAndAcceptLine'},
        @{Chord='Alt+d'; Function='DeleteWord'},
        @{Chord='Ctrl+Backspace'; Function='BackwardKillWord'},
        @{Chord='Ctrl+w'; Function='BackwardKillWord'},
        @{Chord='Ctrl+LeftArrow'; Function='BackwardWord'},
        @{Chord='Ctrl+RightArrow'; Function='ForwardWord'},
        @{Chord='Ctrl+z'; Function='Undo'}
    )

    foreach ($binding in $keyBindings) {
        try {
            Set-PSReadLineKeyHandler @binding -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to set key binding $($binding.Chord): $_"
        }
    }

    # Handle F1 key with fallback
    try {
        Set-PSReadLineKeyHandler -Chord 'F1' -Function ShowCommandHelp -ErrorAction Stop
    }
    catch {
        try {
            Set-PSReadLineKeyHandler -Chord 'F1' -Function WhatIsKey -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not set F1 key handler"
        }
    }
}
else {
    Write-Warning "PSReadLine module not loaded - skipping configuration"
}
#endregion

#region Enhanced Argument Completers
## Add argument completer for the dotnet CLI tool
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $dotnetCompleter = {
        param($wordToComplete, $commandAst, $cursorPosition)
        dotnet complete --position $cursorPosition $commandAst.ToString() |
            ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
    }
    Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $dotnetCompleter
}

## Add argument completer for git
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitCompleter = {
        param($wordToComplete, $commandAst, $cursorPosition)
        $gitOutput = git completion powershell 2>$null
        if ($gitOutput) {
            $gitOutput | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
            }
        }
    }
    Register-ArgumentCompleter -Native -CommandName git -ScriptBlock $gitCompleter
}

## Add argument completer for kubectl
if (Get-Command kubectl -ErrorAction SilentlyContinue) {
    $kubectlCompleter = {
        param($wordToComplete, $commandAst, $cursorPosition)
        $env:COMP_LINE = $commandAst.ToString()
        $env:COMP_POINT = $cursorPosition
        kubectl completion powershell | Out-String | Invoke-Expression
    }
    Register-ArgumentCompleter -Native -CommandName kubectl -ScriptBlock $kubectlCompleter
}

## Add argument completer for docker
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $dockerCompleter = {
        param($wordToComplete, $commandAst, $cursorPosition)
        docker completion powershell | Out-String | Invoke-Expression
    }
    Register-ArgumentCompleter -Native -CommandName docker -ScriptBlock $dockerCompleter
}

## Add argument completer for az CLI
if (Get-Command az -ErrorAction SilentlyContinue) {
    Register-ArgumentCompleter -Native -CommandName az -ScriptBlock {
        param($wordToComplete, $commandAst, $cursorPosition)
        $completion_file = New-TemporaryFile
        $env:ARGCOMPLETE_USE_TEMPFILES = 1
        $env:_ARGCOMPLETE_STDOUT_FILENAME = $completion_file
        $env:COMP_LINE = $commandAst.ToString()
        $env:COMP_POINT = $cursorPosition
        $env:_ARGCOMPLETE = 1
        $env:_ARGCOMPLETE_SUPPRESS_SPACE = 0
        $env:_ARGCOMPLETE_IFS = "`n"
        az 2>&1 | Out-Null
        Get-Content $completion_file | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
        Remove-Item $completion_file, Env:\_ARGCOMPLETE_STDOUT_FILENAME, Env:\ARGCOMPLETE_USE_TEMPFILES, Env:\COMP_LINE, Env:\COMP_POINT, Env:\_ARGCOMPLETE, Env:\_ARGCOMPLETE_SUPPRESS_SPACE, Env:\_ARGCOMPLETE_IFS
    }
}
#endregion

#region DevOps Utility Functions
## Quick navigation function with more locations
function goto {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Location
    )
    
    $locations = @{
        home       = $HOME
        docs       = [Environment]::GetFolderPath('MyDocuments')
        desktop    = [Environment]::GetFolderPath('Desktop')
        dl         = Join-Path $HOME 'Downloads'
        dev        = Join-Path $HOME 'source'
        repos      = Join-Path $HOME 'repos'
        scripts    = Join-Path $HOME 'scripts'
        projects   = Join-Path $HOME 'projects'
        logs       = Join-Path $HOME 'logs'
        temp       = $env:TEMP
        profile    = Split-Path $PROFILE
        modules    = Join-Path (Split-Path $PROFILE) 'Modules'
    }
    
    if ($locations.ContainsKey($Location)) {
        Set-Location $locations[$Location]
        Write-Host "Navigated to: $($locations[$Location])" -ForegroundColor Green
    }
    else {
        Write-Host "Unknown location alias: $Location" -ForegroundColor Red
        Write-Host "Available locations:" -ForegroundColor Yellow
        $locations.GetEnumerator() | Sort-Object Name | ForEach-Object {
            Write-Host "  $($_.Key) -> $($_.Value)" -ForegroundColor Cyan
        }
    }
}

## Enhanced file finder with multiple search types
function ff { 
    param(
        [string]$Pattern,
        [string]$Extension,
        [switch]$CaseSensitive,
        [string]$Path = "."
    )
    
    $params = @{
        Path = $Path
        Recurse = $true
    }
    
    if ($Extension) {
        $params.Filter = "*.$Extension"
    }
    elseif ($Pattern) {
        $params.Filter = "*$Pattern*"
    }
    
    Get-ChildItem @params | Where-Object { 
        if ($Extension -and $Pattern) {
            $_.Name -like "*$Pattern*"
        } else {
            $true
        }
    } | Select-Object FullName, LastWriteTime, Length | Format-Table -AutoSize
}

## Function to open Windows Terminal with Admin rights
function admin {
    if (Get-Command wt -ErrorAction SilentlyContinue) {
        Start-Process wt -Verb RunAs
    } else {
        Start-Process PowerShell -Verb RunAs
    }
}

## Function to edit profile quickly
function Edit-Profile {
    if ($env:EDITOR) {
        & $env:EDITOR $PROFILE
    } else {
        notepad $PROFILE
    }
}

## Function to reload profile
function Reload-Profile {
    . $PROFILE
    Write-Host "Profile reloaded!" -ForegroundColor Green
}

function sysinfo {
    Write-Host "`nSystem Information" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    
    # Operating System Info
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Write-Host "OS: $($os.Caption)" -ForegroundColor Cyan
        Write-Host "Version: $($os.Version)" -ForegroundColor Cyan
        Write-Host "Architecture: $($os.OSArchitecture)" -ForegroundColor Cyan
        Write-Host "Build: $($os.BuildNumber)" -ForegroundColor Cyan
        
        # Handle Install Date with error checking
        if ($os.InstallDate) {
            try {
                $installDate = [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
                Write-Host "Install Date: $($installDate.ToString('yyyy-MM-dd'))" -ForegroundColor Cyan
            } catch {
                Write-Host "Install Date: [Not Available]" -ForegroundColor Cyan
            }
        } else {
            Write-Host "Install Date: [Not Available]" -ForegroundColor Cyan
        }
        
        # Handle Uptime with error checking
        if ($os.LastBootUpTime) {
            try {
                $lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
                $uptime = (Get-Date) - $lastBoot
                Write-Host "Uptime: $($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes" -ForegroundColor Cyan
            } catch {
                Write-Host "Uptime: [Not Available]" -ForegroundColor Cyan
            }
        } else {
            Write-Host "Uptime: [Not Available]" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "OS Information: [Not Available]" -ForegroundColor Red
    }
    
    # Hardware Info
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        Write-Host "`nHardware Information" -ForegroundColor Yellow
        Write-Host "===================" -ForegroundColor Yellow
        Write-Host "Manufacturer: $($cs.Manufacturer)" -ForegroundColor Cyan
        Write-Host "Model: $($cs.Model)" -ForegroundColor Cyan
        
        if ($cs.TotalPhysicalMemory) {
            Write-Host "Total RAM: $([Math]::Round($cs.TotalPhysicalMemory / 1GB, 2)) GB" -ForegroundColor Cyan
        } else {
            Write-Host "Total RAM: [Not Available]" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "`nHardware Information: [Not Available]" -ForegroundColor Red
    }
    
    # CPU Info
    try {
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        Write-Host "CPU: $($cpu.Name)" -ForegroundColor Cyan
        Write-Host "Cores: $($cpu.NumberOfCores)" -ForegroundColor Cyan
        Write-Host "Logical Processors: $($cpu.NumberOfLogicalProcessors)" -ForegroundColor Cyan
    } catch {
        Write-Host "CPU Information: [Not Available]" -ForegroundColor Red
    }
    
    # Disk Info
    try {
        $disks = Get-CimInstance Win32_LogicalDisk -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 }
        if ($disks) {
            Write-Host "`nDisk Information" -ForegroundColor Yellow
            Write-Host "===============" -ForegroundColor Yellow
            foreach ($disk in $disks) {
                $freeGB = if ($disk.FreeSpace) { [Math]::Round($disk.FreeSpace / 1GB, 2) } else { 0 }
                $totalGB = if ($disk.Size) { [Math]::Round($disk.Size / 1GB, 2) } else { 0 }
                $usedGB = $totalGB - $freeGB
                $percentFree = if ($totalGB -gt 0) { [Math]::Round(($freeGB / $totalGB) * 100, 2) } else { 0 }
                Write-Host "$($disk.DeviceID) - Total: ${totalGB}GB, Used: ${usedGB}GB, Free: ${freeGB}GB ($percentFree%)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "`nDisk Information: [No drives found]" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "`nDisk Information: [Not Available]" -ForegroundColor Red
    }
    
    # PowerShell Info
    Write-Host "`nPowerShell Information" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor Yellow
    Write-Host "Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
    Write-Host "Host: $($Host.Version)" -ForegroundColor Cyan
    
    # Network Info
    try {
        $network = Get-NetIPAddress -ErrorAction Stop | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' }
        if ($network) {
            Write-Host "`nNetwork Information" -ForegroundColor Yellow
            Write-Host "==================" -ForegroundColor Yellow
            foreach ($adapter in $network) {
                Write-Host "$($adapter.InterfaceAlias): $($adapter.IPAddress)/$($adapter.PrefixLength)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "`nNetwork Information: [No adapters found]" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "`nNetwork Information: [Not Available]" -ForegroundColor Red
    }
    
    Write-Host ""
}

## Function to show network info
function netinfo {
    Write-Host "`nNetwork Information" -ForegroundColor Yellow
    Write-Host "===================" -ForegroundColor Yellow
    
    try {
        # Get all network adapters with IPv4 addresses (excluding loopback)
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }
        
        if (-not $adapters) {
            Write-Host "No active network adapters found" -ForegroundColor Red
            return
        }

        foreach ($adapter in $adapters) {
            # Basic adapter information
            Write-Host "`nInterface: $($adapter.Name)" -ForegroundColor Cyan
            Write-Host "Description: $($adapter.InterfaceDescription)" -ForegroundColor Cyan
            Write-Host "Status: $($adapter.Status)" -ForegroundColor Cyan
            Write-Host "MAC Address: $($adapter.MacAddress)" -ForegroundColor Cyan
            Write-Host "Speed: $($adapter.Speed / 1MB) MB/s" -ForegroundColor Cyan
            
            # IP configuration
            $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ipConfig) {
                Write-Host "IP Address: $($ipConfig.IPAddress)" -ForegroundColor Green
                Write-Host "Subnet Mask: $(ConvertTo-SubnetMask $ipConfig.PrefixLength)" -ForegroundColor Green
                Write-Host "Prefix Length: $($ipConfig.PrefixLength)" -ForegroundColor Green
            }

            # DNS information
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dns -and $dns.ServerAddresses) {
                Write-Host "DNS Servers: $($dns.ServerAddresses -join ', ')" -ForegroundColor Green
            }

            # Connection information
            $connection = Get-NetConnectionProfile -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
            if ($connection) {
                Write-Host "Network Category: $($connection.NetworkCategory)" -ForegroundColor Green
                Write-Host "Network Name: $($connection.Name)" -ForegroundColor Green
            }

            # TCP connections
            $tcpConnections = Get-NetTCPConnection -State Established -LocalAddress $ipConfig.IPAddress -ErrorAction SilentlyContinue | 
                            Select-Object -First 5
            if ($tcpConnections) {
                Write-Host "Active TCP Connections:" -ForegroundColor Yellow
                $tcpConnections | Format-Table -AutoSize
            }
        }
    }
    catch {
        Write-Host "Error retrieving network information: $_" -ForegroundColor Red
    }
}

# Helper function to convert prefix length to subnet mask
function ConvertTo-SubnetMask {
    param([int]$PrefixLength)
    $mask = [IPAddress](([math]::Pow(2, $PrefixLength) - 1) * [math]::Pow(2, 32 - $PrefixLength))
    return $mask.ToString()
}

## Function to show disk usage
function diskinfo {
    Write-Host "`nDisk Information" -ForegroundColor Yellow
    Write-Host "===============" -ForegroundColor Yellow
    
    try {
        # Get all logical disks
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop
        
        if (-not $disks) {
            Write-Host "No disks found" -ForegroundColor Red
            return
        }

        # Calculate disk information
        $diskInfo = $disks | ForEach-Object {
            $sizeGB = if ($_.Size) { [math]::Round($_.Size/1GB, 2) } else { 0 }
            $freeGB = if ($_.FreeSpace) { [math]::Round($_.FreeSpace/1GB, 2) } else { 0 }
            $usedGB = $sizeGB - $freeGB
            $percentFree = if ($sizeGB -gt 0) { [math]::Round(($freeGB/$sizeGB)*100, 2) } else { 0 }
            $percentUsed = 100 - $percentFree

            # Get volume information if available
            $volume = Get-Volume -DriveLetter $_.DeviceID[0] -ErrorAction SilentlyContinue

            [PSCustomObject]@{
                Drive = $_.DeviceID
                'File System' = $_.FileSystem
                'Volume Name' = $volume.FileSystemLabel
                'Type' = switch ($_.DriveType) {
                    2 { "Removable" }
                    3 { "Local Disk" }
                    4 { "Network Drive" }
                    5 { "CD-ROM" }
                    default { "Unknown" }
                }
                'Total (GB)' = $sizeGB
                'Used (GB)' = $usedGB
                'Free (GB)' = $freeGB
                '% Free' = $percentFree
                '% Used' = $percentUsed
                'Health Status' = $volume.HealthStatus
                'Drive Type' = $volume.DriveType
            }
        }

        # Display the information
        $diskInfo | Format-Table -AutoSize -Property Drive, 'File System', 'Volume Name', 'Type', 
            'Total (GB)', 'Used (GB)', 'Free (GB)', '% Free', '% Used', 'Health Status'

        # Show disk performance information if available (Windows 8/Server 2012 or later)
        if ((Get-CimInstance Win32_OperatingSystem).Version -ge "6.2") {
            try {
                Write-Host "`nDisk Performance:" -ForegroundColor Yellow
                Get-CimInstance -ClassName Win32_PerfFormattedData_PerfDisk_LogicalDisk | 
                    Where-Object { $_.Name -ne '_Total' } |
                    Select-Object Name, 
                        @{Name='DiskReadBytesPerSec';Expression={[math]::Round($_.DiskReadBytesPerSec/1KB, 2)}},
                        @{Name='DiskWriteBytesPerSec';Expression={[math]::Round($_.DiskWriteBytesPerSec/1KB, 2)}},
                        @{Name='AvgDiskSecPerRead';Expression={[math]::Round($_.AvgDiskSecPerRead*1000, 2)}},
                        @{Name='AvgDiskSecPerWrite';Expression={[math]::Round($_.AvgDiskSecPerWrite*1000, 2)}} |
                    Format-Table -AutoSize
            }
            catch {
                Write-Host "Disk performance information not available" -ForegroundColor DarkGray
            }
        }
    }
    catch {
        Write-Host "Error retrieving disk information: $_" -ForegroundColor Red
    }
}

## Function to show running processes with high CPU/Memory
function topproc {
    param([int]$Count = 10)
    
    Write-Host "Top $Count processes by CPU usage:" -ForegroundColor Yellow
    Get-Process | Sort-Object CPU -Descending | Select-Object -First $Count Name, CPU, WorkingSet, Id | Format-Table -AutoSize
    
    Write-Host "Top $Count processes by Memory usage:" -ForegroundColor Yellow
    Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First $Count Name, CPU, WorkingSet, Id | Format-Table -AutoSize
}

## Function to test network connectivity
function testnet {
    param(
        [string]$Target = "8.8.8.8",
        [int]$Count = 4
    )
    
    Test-NetConnection -ComputerName $Target -InformationLevel Detailed
    Write-Host ""
    Test-Connection -ComputerName $Target -Count $Count
}

## Function to show listening ports
function ports {
    Get-NetTCPConnection | Where-Object State -eq Listen | 
    Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object LocalPort | Format-Table -AutoSize
}

## Function to create a new directory and navigate to it
function mkcd {
    param([string]$Path)
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Set-Location $Path
    Write-Host "Created and navigated to: $Path" -ForegroundColor Green
}

## Function to extract archives
function extract {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string]$Destination = "."
    )
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    
    switch ($extension) {
        '.zip' { 
            Expand-Archive -Path $FilePath -DestinationPath $Destination -Force
            Write-Host "Extracted ZIP archive to: $Destination" -ForegroundColor Green
        }
        '.7z' {
            if (Get-Command 7z -ErrorAction SilentlyContinue) {
                7z x $FilePath -o$Destination
                Write-Host "Extracted 7z archive to: $Destination" -ForegroundColor Green
            } else {
                Write-Host "7z command not found. Please install 7-Zip." -ForegroundColor Red
            }
        }
        default {
            Write-Host "Unsupported archive format: $extension" -ForegroundColor Red
        }
    }
}
#endregion

#region Git Shortcuts
## Enhanced Git shortcuts for common operations
function gs { git status }
function ga { git add $args }
function gc { git commit -m $args }
function gp { git push }
function gl { git pull }
function gd { git diff }
function gco { git checkout $args }
function gb { git branch $args }
function glog { git log --oneline --graph --decorate --all }
function gstash { git stash }
function gstashp { git stash pop }

## Function to create a new git repository
function gitinit {
    param([string]$RepoName)
    
    if ($RepoName) {
        New-Item -ItemType Directory -Name $RepoName -Force | Out-Null
        Set-Location $RepoName
    }
    
    git init
    Write-Host "Git repository initialized" -ForegroundColor Green
    
    if (!(Test-Path ".gitignore")) {
        @"
# Common ignore patterns
*.log
*.tmp
*.temp
node_modules/
.env
.env.local
bin/
obj/
.vs/
.vscode/
*.user
"@ | Out-File -FilePath ".gitignore" -Encoding UTF8
        Write-Host "Created .gitignore file" -ForegroundColor Green
    }
}
#endregion

#region Docker Shortcuts
## Docker shortcuts (if Docker is available)
if (Get-Command docker -ErrorAction SilentlyContinue) {
    function dps { docker ps }
    function dpsa { docker ps -a }
    function di { docker images }
    function drm { docker rm $args }
    function drmi { docker rmi $args }
    function dstop { docker stop $args }
    function dstart { docker start $args }
    function drestart { docker restart $args }
    function dlogs { docker logs $args }
    function dexec { docker exec -it $args }
    function dclean { 
        docker system prune -f
        Write-Host "Docker system cleaned" -ForegroundColor Green
    }
    function dcleanall { 
        docker system prune -a -f
        Write-Host "Docker system cleaned (including unused images)" -ForegroundColor Green
    }
}
#endregion

#region Kubernetes Shortcuts
## Kubernetes shortcuts (if kubectl is available)
if (Get-Command kubectl -ErrorAction SilentlyContinue) {
    function k { kubectl $args }
    function kgp { kubectl get pods }
    function kgs { kubectl get services }
    function kgd { kubectl get deployments }
    function kgn { kubectl get nodes }
    function kdp { kubectl describe pod $args }
    function kds { kubectl describe service $args }
    function kdd { kubectl describe deployment $args }
    function klogs { kubectl logs $args }
    function kexec { kubectl exec -it $args }
    function kctx { kubectl config current-context }
    function kns { kubectl config set-context --current --namespace=$args }
}
#endregion

#region Enhanced Colorful Directory Listing - Working Version
function Get-ColorizedContent {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string]$Path = '.',
        [switch]$All,
        [switch]$Details,
        [string]$SortBy = 'Name'
    )

    # Define colors for different file types
    $colors = @{
        Directory    = 'Cyan'
        Executable   = 'Green'
        Hidden       = 'DarkGray'
        Compressed   = 'Yellow'
        Document     = 'White'
        Image        = 'Magenta'
        System       = 'Red'
        SymLink      = 'DarkCyan'
        Config       = 'DarkYellow'
        Code         = 'Blue'
        Database     = 'DarkMagenta'
        Media        = 'DarkGreen'
        Default      = 'Gray'
    }

    # File extension mappings
    $extensionMap = @{
        # Executables
        '.exe' = $colors.Executable; '.bat' = $colors.Executable; '.cmd' = $colors.Executable
        '.ps1' = $colors.Executable; '.psm1' = $colors.Executable; '.psd1' = $colors.Executable
        '.sh' = $colors.Executable; '.bash' = $colors.Executable; '.com' = $colors.Executable
        '.msi' = $colors.Executable; '.scr' = $colors.Executable
        
        # Compressed files
        '.zip' = $colors.Compressed; '.rar' = $colors.Compressed; '.7z' = $colors.Compressed
        '.gz' = $colors.Compressed; '.tar' = $colors.Compressed; '.bz2' = $colors.Compressed
        '.xz' = $colors.Compressed; '.tgz' = $colors.Compressed; '.cab' = $colors.Compressed
        '.iso' = $colors.Compressed
        
        # Documents
        '.txt' = $colors.Document; '.md' = $colors.Document; '.docx' = $colors.Document
        '.pdf' = $colors.Document; '.xlsx' = $colors.Document; '.pptx' = $colors.Document
        '.csv' = $colors.Document; '.rtf' = $colors.Document; '.odt' = $colors.Document
        '.tex' = $colors.Document
        
        # Code files
        '.json' = $colors.Code; '.xml' = $colors.Code; '.html' = $colors.Code
        '.css' = $colors.Code; '.js' = $colors.Code; '.ts' = $colors.Code
        '.cs' = $colors.Code; '.py' = $colors.Code; '.rb' = $colors.Code
        '.go' = $colors.Code; '.java' = $colors.Code; '.cpp' = $colors.Code
        '.c' = $colors.Code; '.h' = $colors.Code; '.php' = $colors.Code
        '.sql' = $colors.Code; '.r' = $colors.Code; '.scala' = $colors.Code
        '.kt' = $colors.Code; '.swift' = $colors.Code; '.rs' = $colors.Code
        '.jsx' = $colors.Code; '.tsx' = $colors.Code; '.vue' = $colors.Code
        
        # Config files
        '.config' = $colors.Config; '.ini' = $colors.Config; '.conf' = $colors.Config
        '.yml' = $colors.Config; '.yaml' = $colors.Config; '.toml' = $colors.Config
        '.env' = $colors.Config; '.gitignore' = $colors.Config
        
        # Images
        '.jpg' = $colors.Image; '.jpeg' = $colors.Image; '.png' = $colors.Image
        '.gif' = $colors.Image; '.bmp' = $colors.Image; '.svg' = $colors.Image
        '.ico' = $colors.Image; '.webp' = $colors.Image; '.tiff' = $colors.Image
        
        # Database files
        '.db' = $colors.Database; '.sqlite' = $colors.Database; '.mdb' = $colors.Database
        '.accdb' = $colors.Database
        
        # Media files
        '.mp3' = $colors.Media; '.wav' = $colors.Media; '.flac' = $colors.Media
        '.mp4' = $colors.Media; '.avi' = $colors.Media; '.mov' = $colors.Media
        '.mkv' = $colors.Media; '.wmv' = $colors.Media
        
        # System files
        '.sys' = $colors.System; '.dll' = $colors.System; '.log' = $colors.System
        '.tmp' = $colors.System; '.bak' = $colors.System
    }

    # Get items with error handling
    try {
        $items = Get-ChildItem -Path $Path -Force:$All -ErrorAction Stop
    }
    catch {
        Write-Host "Error accessing path: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Sort items
    $items = switch ($SortBy) {
        'Size' { $items | Sort-Object @{Expression = {$_.PSIsContainer}; Descending = $true}, Length -Descending }
        'Date' { $items | Sort-Object @{Expression = {$_.PSIsContainer}; Descending = $true}, LastWriteTime -Descending }
        'Type' { $items | Sort-Object @{Expression = {$_.PSIsContainer}; Descending = $true}, Extension, Name }
        default { $items | Sort-Object @{Expression = {$_.PSIsContainer}; Descending = $true}, Name }
    }

    # Display items with colors
    foreach ($item in $items) {
        $displayName = $item.Name
        $itemColor = $colors.Default
        $prefix = ""
        
        # Determine color based on item type
        if ($item.PSIsContainer) {
            $itemColor = $colors.Directory
            $prefix = "[DIR]"
        }
        elseif ($item.Attributes -band [System.IO.FileAttributes]::Hidden) {
            $itemColor = $colors.Hidden
            $prefix = "[HID]"
        }
        else {
            $extension = $item.Extension.ToLower()
            if ($extensionMap.ContainsKey($extension)) {
                $itemColor = $extensionMap[$extension]
            }
            $prefix = "[FILE]"
        }

        # Format output
        if ($item.PSIsContainer) {
            $lastWrite = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            Write-Host ("{0,-7} {1,-50} {2,-12} {3}" -f $prefix, $displayName, "<DIR>", $lastWrite) -ForegroundColor $itemColor
        }
        else {
            $size = if ($item.Length -gt 1GB) {
                "{0:N2} GB" -f ($item.Length / 1GB)
            } elseif ($item.Length -gt 1MB) {
                "{0:N2} MB" -f ($item.Length / 1MB)
            } elseif ($item.Length -gt 1KB) {
                "{0:N2} KB" -f ($item.Length / 1KB)
            } else {
                "{0} B" -f $item.Length
            }
            
            $lastWrite = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            Write-Host ("{0,-7} {1,-50} {2,-12} {3}" -f $prefix, $displayName, $size, $lastWrite) -ForegroundColor $itemColor
        }
    }
}

function Show-ColorizedDirectory {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string]$Path = '.',
        [switch]$All,
        [switch]$Details,
        [string]$SortBy = 'Name'
    )
    
    # Resolve and validate path
    try {
        $resolvedPath = Resolve-Path $Path -ErrorAction Stop
        $Path = $resolvedPath.Path
    }
    catch {
        Write-Host "Path not found: $Path" -ForegroundColor Red
        return
    }
    
    # Display header
    Write-Host "`nDirectory: " -NoNewline -ForegroundColor Yellow
    Write-Host "$Path" -ForegroundColor Green
    Write-Host ("=" * 80) -ForegroundColor DarkGray
    
    # Column headers
    Write-Host ("{0,-7} {1,-50} {2,-12} {3}" -f "Type", "Name", "Size", "Modified") -ForegroundColor DarkGray
    Write-Host ("-" * 80) -ForegroundColor DarkGray
    
    # Display contents
    Get-ColorizedContent -Path $Path -All:$All -Details:$Details -SortBy $SortBy
    
    # Summary
    $allItems = Get-ChildItem -Path $Path -Force:$All -ErrorAction SilentlyContinue
    $fileCount = ($allItems | Where-Object { !$_.PSIsContainer }).Count
    $dirCount = ($allItems | Where-Object { $_.PSIsContainer }).Count
    
    Write-Host ("=" * 80) -ForegroundColor DarkGray
    Write-Host "Summary: $dirCount directories, $fileCount files" -ForegroundColor White
    Write-Host ""
}

# Test function to verify colors work
function Test-Colors {
    Write-Host "Testing PowerShell colors:" -ForegroundColor White
    $colors = @('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')
    foreach ($color in $colors) {
        Write-Host "This is $color" -ForegroundColor $color
    }
}

# Create aliases
Set-Alias -Name lsc -Value Show-ColorizedDirectory -Force
Set-Alias -Name ll -Value Show-ColorizedDirectory -Force

# Functions and aliases are automatically available in PowerShell profile
#endregion

# Usage examples and testing:
# Test-Colors                                # Test if colors work in your terminal
# Show-ColorizedDirectory                    # Basic colorized listing
# Show-ColorizedDirectory -All               # Include hidden files
# Show-ColorizedDirectory -SortBy Size       # Sort by file size
# lsc                                        # Using alias
# ll -All                                    # Using alias with parameters