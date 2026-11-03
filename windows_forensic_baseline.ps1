<#
.SYNOPSIS
    Windows Forensic Baseline Toolkit - Windows Server 2016 through 2025.

.DESCRIPTION
    Best-effort triage collection of host, account, process, service, network,
    persistence, security configuration, event-log and file-timeline information.

    Compatible target: Windows Server 2016, 2019, 2022 and 2025.
    Designed for Windows PowerShell 5.1. Run from an elevated PowerShell session.

.PARAMETER StartTime
    Start of the file timeline and event-log collection window.
    Example: "2026-11-01 00:00:00"

.PARAMETER EndTime
    End of the collection window.
    Example: "2026-11-03 23:59:59"

.PARAMETER OutputDirectory
    Evidence output directory. Prefer an approved external evidence volume.

.PARAMETER ScanRoots
    Directories to inspect for files whose LastWriteTime falls in the window.
    Defaults focus on common application, web and temporary locations.

.EXAMPLE
    .\windows_forensic_baseline.ps1 `
      -StartTime "2026-11-01 00:00:00" `
      -EndTime "2026-11-03 23:59:59" `
      -OutputDirectory "E:\Evidence"

.NOTES
    This is a triage helper, not a forensic disk-imaging tool.
    Review the script before use. Preserve volatile evidence first when required
    by your incident-response procedure. Timestamps are not proof of attribution.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$StartTime,

    [Parameter(Mandatory = $true)]
    [string]$EndTime,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string[]]$ScanRoots = @(
        "$env:SystemDrive\inetpub\wwwroot",
        "$env:SystemDrive\Windows\Temp",
        "$env:SystemDrive\ProgramData",
        "$env:SystemDrive\Users\Public",
        "$env:SystemDrive\Temp"
    )
)

$ErrorActionPreference = "Continue"
$Culture = [System.Globalization.CultureInfo]::InvariantCulture
$DateFormat = "yyyy-MM-dd HH:mm:ss"

try {
    $Start = [datetime]::ParseExact($StartTime, $DateFormat, $Culture)
    $End = [datetime]::ParseExact($EndTime, $DateFormat, $Culture)
}
catch {
    throw "Invalid date format. Use yyyy-MM-dd HH:mm:ss (local system time)."
}

if ($End -lt $Start) {
    throw "EndTime must be greater than or equal to StartTime."
}

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    throw "Run PowerShell as Administrator."
}

$HostName = $env:COMPUTERNAME
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$SafeHost = $HostName -replace '[^A-Za-z0-9_.-]', '_'

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path

$BaselineFile = Join-Path $OutputDirectory "${SafeHost}_baseline_${Stamp}.txt"
$ChangedFile = Join-Path $OutputDirectory "${SafeHost}_changed_files_${Stamp}.txt"
$HashFile = Join-Path $OutputDirectory "${SafeHost}_changed_sha256_${Stamp}.txt"

function Add-Section {
    param([string]$Path, [string]$Title, [scriptblock]$Command)

    Add-Content -LiteralPath $Path -Value ""
    Add-Content -LiteralPath $Path -Value ("=" * 78)
    Add-Content -LiteralPath $Path -Value $Title
    Add-Content -LiteralPath $Path -Value ("=" * 78)

    try {
        $Result = & $Command 2>&1 | Out-String -Width 300
        if ([string]::IsNullOrWhiteSpace($Result)) {
            Add-Content -LiteralPath $Path -Value "[No output]"
        } else {
            Add-Content -LiteralPath $Path -Value $Result.TrimEnd()
        }
    }
    catch {
        Add-Content -LiteralPath $Path -Value ("[ERROR] " + $_.Exception.Message)
    }
}

function Add-EventLogSection {
    param(
        [string]$Path,
        [string]$LogName,
        [int[]]$EventIds = @()
    )

    Add-Content -LiteralPath $Path -Value ""
    Add-Content -LiteralPath $Path -Value ("--- Event Log: {0} ---" -f $LogName)

    try {
        $Filter = @{
            LogName   = $LogName
            StartTime = $Start
            EndTime   = $End
        }
        if ($EventIds.Count -gt 0) {
            $Filter.Id = $EventIds
        }

        Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
            Format-List | Out-String -Width 300 |
            Add-Content -LiteralPath $Path
    }
    catch {
        Add-Content -LiteralPath $Path -Value ("[Unavailable/no matching events] " + $_.Exception.Message)
    }
}

@(
    "Windows Forensic Baseline Report"
    "Hostname       : $HostName"
    "Collection time: $(Get-Date -Format $DateFormat)"
    "Time zone      : $((Get-TimeZone).Id)"
    "Timeline start : $Start"
    "Timeline end   : $End"
    "Script         : windows_forensic_baseline.ps1"
    "PowerShell     : $($PSVersionTable.PSVersion)"
    "Run as admin   : $IsAdmin"
) | Set-Content -LiteralPath $BaselineFile -Encoding UTF8

Add-Section $BaselineFile "1. SYSTEM IDENTITY AND TIME" {
    Get-ComputerInfo |
        Select-Object CsName, CsDomain, CsPartOfDomain, WindowsProductName,
            WindowsVersion, OsBuildNumber, OsArchitecture, OsInstallDate,
            OsLastBootUpTime, BiosSerialNumber |
        Format-List
    "`r`n--- Current time ---"
    Get-Date -Format o
    "`r`n--- Time zone ---"
    Get-TimeZone | Format-List *
    "`r`n--- Time service ---"
    w32tm /query /status
}

Add-Section $BaselineFile "2. STORAGE AND VOLUMES" {
    Get-Volume | Format-Table DriveLetter, FileSystemLabel, FileSystem,
        DriveType, HealthStatus, Size, SizeRemaining -AutoSize
    "`r`n--- Physical disks ---"
    Get-Disk | Format-Table Number, FriendlyName, SerialNumber, OperationalStatus,
        PartitionStyle, Size -AutoSize
}

Add-Section $BaselineFile "3. LOCAL USERS AND GROUPS" {
    "`r`n--- Local users ---"
    Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordLastSet,
        PasswordExpires, SID -AutoSize
    "`r`n--- Local Administrators ---"
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Format-Table Name, ObjectClass, PrincipalSource, SID -AutoSize
    "`r`n--- Logged-on sessions ---"
    quser 2>&1
    "`r`n--- Recent logons (summary) ---"
    Get-WinEvent -FilterHashtable @{
        LogName='Security'; Id=4624,4625; StartTime=$Start; EndTime=$End
    } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message |
        Format-List
}

Add-Section $BaselineFile "4. PROCESSES" {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath,
            CreationDate, CommandLine |
        Sort-Object Name | Format-List
}

Add-Section $BaselineFile "5. SERVICES" {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
        Sort-Object Name | Format-Table -Wrap
}

Add-Section $BaselineFile "6. NETWORK CONFIGURATION" {
    "`r`n--- IP configuration ---"
    Get-NetIPConfiguration | Format-List *
    "`r`n--- IP addresses ---"
    Get-NetIPAddress | Format-Table InterfaceAlias, AddressFamily, IPAddress,
        PrefixLength, PrefixOrigin -AutoSize
    "`r`n--- DNS servers ---"
    Get-DnsClientServerAddress | Format-Table -AutoSize
    "`r`n--- Routes ---"
    Get-NetRoute | Sort-Object DestinationPrefix |
        Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -AutoSize
    "`r`n--- Listening TCP ports ---"
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Sort-Object LocalPort |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize
    "`r`n--- Active TCP connections ---"
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort,
            OwningProcess -AutoSize
    "`r`n--- ARP cache ---"
    Get-NetNeighbor | Format-Table -AutoSize
}

Add-Section $BaselineFile "7. PERSISTENCE: SCHEDULED TASKS AND STARTUP" {
    "`r`n--- Scheduled tasks (non-Microsoft tasks) ---"
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
        Select-Object TaskName, TaskPath, State, Author, Description |
        Format-Table -Wrap
    "`r`n--- Run keys ---"
    $RunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    foreach ($Key in $RunKeys) {
        "`r`n[$Key]"
        if (Test-Path $Key) {
            Get-ItemProperty -Path $Key | Format-List *
        } else {
            "[Key not present]"
        }
    }
    "`r`n--- Startup folders ---"
    $StartupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($Folder in $StartupFolders) {
        "`r`n[$Folder]"
        if (Test-Path $Folder) {
            Get-ChildItem -LiteralPath $Folder -Force -ErrorAction SilentlyContinue |
                Select-Object FullName, Length, CreationTimeUtc, LastWriteTimeUtc
        }
    }
}

Add-Section $BaselineFile "8. SECURITY CONTROLS" {
    "`r`n--- Windows Defender status ---"
    Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List *
    "`r`n--- Defender preferences ---"
    Get-MpPreference -ErrorAction SilentlyContinue |
        Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring,
            DisableIOAVProtection, ExclusionPath, ExclusionProcess, ExclusionExtension |
        Format-List
    "`r`n--- Firewall profiles ---"
    Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction -AutoSize
    "`r`n--- Audit policy ---"
    auditpol /get /category:*
}

Add-Section $BaselineFile "9. INSTALLED SOFTWARE / HOTFIXES" {
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Select-Object HotFixID, Description, InstalledBy, InstalledOn |
        Format-Table -AutoSize
    "`r`n--- Uninstall registry entries ---"
    $UninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    Get-ItemProperty $UninstallPaths -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        Sort-Object DisplayName | Format-Table -Wrap
}

Add-Section $BaselineFile "10. SELECTED EVENT LOGS IN INCIDENT WINDOW" {
    "Events are filtered using the target host's local time."
    "`r`nSecurity log - selected authentication and account events"
    # Authentication, account/group changes, scheduled task creation and service install.
    $SecurityIds = @(1102, 4624, 4625, 4648, 4672, 4697, 4698, 4702,
        4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733,
        4738, 4740, 4756, 4757)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=$SecurityIds; StartTime=$Start; EndTime=$End
        } -ErrorAction Stop |
            Select-Object TimeCreated, Id, ProviderName, Message |
            Format-List | Out-String -Width 300 |
            Add-Content -LiteralPath $BaselineFile
    } catch {
        Add-Content -LiteralPath $BaselineFile -Value ("[Security log unavailable] " + $_.Exception.Message)
    }

    Add-EventLogSection $BaselineFile "System"
    Add-EventLogSection $BaselineFile "Application"
    Add-EventLogSection $BaselineFile "Microsoft-Windows-PowerShell/Operational"
    Add-EventLogSection $BaselineFile "Microsoft-Windows-Windows Defender/Operational"
    Add-EventLogSection $BaselineFile "Microsoft-Windows-TaskScheduler/Operational"
}

# File timeline: existing files only; LastWriteTime is not proof of creation or attribution.
"Windows File Timeline" | Set-Content -LiteralPath $ChangedFile -Encoding UTF8
"Host: $HostName | Window: $Start to $End" | Add-Content -LiteralPath $ChangedFile
"Search roots: $($ScanRoots -join '; ')" | Add-Content -LiteralPath $ChangedFile
"Note: only existing files and LastWriteTime are searched; deleted files are not discoverable by this scan." |
    Add-Content -LiteralPath $ChangedFile

$ChangedPaths = New-Object System.Collections.Generic.List[string]

foreach ($Root in $ScanRoots) {
    Add-Content -LiteralPath $ChangedFile -Value ""
    Add-Content -LiteralPath $ChangedFile -Value ("--- Scanning: {0} ---" -f $Root)

    if (-not (Test-Path -LiteralPath $Root)) {
        Add-Content -LiteralPath $ChangedFile -Value "[Path not present]"
        continue
    }

    try {
        Get-ChildItem -LiteralPath $Root -File -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $_.LastWriteTime -ge $Start -and $_.LastWriteTime -le $End
            } |
            ForEach-Object {
                $Line = "{0}`t{1}`t{2}`t{3}" -f
                    $_.LastWriteTime.ToString("o"),
                    $_.Length,
                    $_.FullName,
                    $_.Attributes
                Add-Content -LiteralPath $ChangedFile -Value $Line
                $ChangedPaths.Add($_.FullName)
            }
    }
    catch {
        Add-Content -LiteralPath $ChangedFile -Value ("[Scan error] " + $_.Exception.Message)
    }
}

"SHA256 inventory of files found in the timeline" |
    Set-Content -LiteralPath $HashFile -Encoding UTF8
"Host: $HostName | Hash time: $(Get-Date -Format o)" |
    Add-Content -LiteralPath $HashFile

foreach ($FilePath in ($ChangedPaths | Sort-Object -Unique)) {
    try {
        $Hash = Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop
        "{0}  {1}" -f $Hash.Hash, $Hash.Path |
            Add-Content -LiteralPath $HashFile
    }
    catch {
        "[HASH ERROR] $FilePath : $($_.Exception.Message)" |
            Add-Content -LiteralPath $HashFile
    }
}

Add-Section $BaselineFile "11. COLLECTION NOTES AND LIMITATIONS" {
    @"
- This script is a triage helper, not a full forensic acquisition or disk image.
- LastWriteTime is not proof of file creation, user identity, or process attribution.
- Deleted files are not discoverable through this normal filesystem scan.
- Event collection depends on audit policy, log availability, retention and permissions.
- PowerShell Operational and other optional logs may be disabled or absent.
- File scan scope is limited to the configured ScanRoots; it does not scan every volume.
- Hashes are calculated at collection time, not historical hashes.
- Output is written to the specified OutputDirectory.
- Collection commands may create activity on the investigated host.
- Preserve original evidence, document operator/time, and follow incident-response procedures.
"@
}

Write-Host ""
Write-Host "Collection completed." -ForegroundColor Green
Write-Host "Baseline : $BaselineFile"
Write-Host "Timeline : $ChangedFile"
Write-Host "SHA256   : $HashFile"
