# Asks the Windows Update Agent which applicable software updates are not installed. Read-only: searches, never
# downloads or installs. Uses WSUS when the VM is configured for it, Microsoft Update otherwise.
$ErrorActionPreference = 'Stop'
trap { [Console]::Error.WriteLine($_.ToString()); exit 1 }
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$session = New-Object -ComObject Microsoft.Update.Session
$session.ClientApplicationID = 'VmPatchAgent'
$searcher = $session.CreateUpdateSearcher()
$result = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

$updates = @(foreach ($u in $result.Updates) {
    [pscustomobject]@{
        updateId       = $u.Identity.UpdateID
        title          = $u.Title
        kbs            = @($u.KBArticleIDs | ForEach-Object { "KB$_" })
        msrcSeverity   = $u.MsrcSeverity
        cveIds         = @($u.CveIDs | ForEach-Object { $_ })
        categories     = @($u.Categories | ForEach-Object { $_.Name })
        rebootBehavior = [int]$u.InstallationBehavior.RebootBehavior
        sizeBytes      = [long]$u.MaxDownloadSize
    }
})

# ResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted.
[pscustomobject]@{ resultCode = [int]$result.ResultCode; updates = $updates } | ConvertTo-Json -Depth 5 -Compress
