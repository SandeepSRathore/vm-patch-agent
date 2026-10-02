# Machine-wide installed programs from the 64- and 32-bit uninstall keys. Read-only.
$ErrorActionPreference = 'Stop'
trap { [Console]::Error.WriteLine($_.ToString()); exit 1 }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$keys = @(
    @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x64' },
    @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x86' }
)

$apps = @(foreach ($key in $keys) {
    Get-ItemProperty -Path $key.path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName } |
        ForEach-Object {
            [pscustomobject]@{
                name         = $_.DisplayName.Trim()
                version      = $_.DisplayVersion
                publisher    = $_.Publisher
                architecture = $key.arch
            }
        }
})

ConvertTo-Json -InputObject @($apps | Sort-Object name, version, architecture -Unique) -Depth 3 -Compress
