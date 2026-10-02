# Hostname, OS build, WSUS policy and installed hotfixes. Read-only.
$ErrorActionPreference = 'Stop'
trap { [Console]::Error.WriteLine($_.ToString()); exit 1 }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$wuPolicy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem

$hotfixes = @(Get-CimInstance Win32_QuickFixEngineering | ForEach-Object {
    $installedOn = $null
    # InstalledOn is a locale-formatted string and is sometimes empty or hex; skip what does not parse.
    $parsed = [datetime]::MinValue
    if ($_.InstalledOn -and [datetime]::TryParse($_.InstalledOn, [ref]$parsed)) { $installedOn = $parsed.ToString('yyyy-MM-dd') }
    [pscustomobject]@{ kb = $_.HotFixID; description = $_.Description; installedOn = $installedOn }
})

[pscustomobject]@{
    hostname         = $env:COMPUTERNAME
    caption          = $os.Caption
    displayVersion   = $cv.DisplayVersion
    build            = [int]$cv.CurrentBuild
    ubr              = [int]$cv.UBR
    installationType = $cv.InstallationType
    # A 32-bit host process sees x86 in PROCESSOR_ARCHITECTURE; the real one is then in PROCESSOR_ARCHITEW6432.
    architecture     = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    wsusServer       = $wuPolicy.WUServer
    lastBootTime     = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    installedUpdates = $hotfixes
} | ConvertTo-Json -Depth 4 -Compress
