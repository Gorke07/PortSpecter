$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $workspace 'assets/data/mac-vendors.json'
$temporary = "$destination.download"
try {
    $page = Invoke-WebRequest -UseBasicParsing -Uri 'https://maclookup.app/downloads/json-database'
    $link = $page.Links | Where-Object { $_.href -like '*get-db*' } | Select-Object -First 1
    if (-not $link) { throw 'MACLookup JSON download link was not found.' }
    $uri = [Uri]::new([Uri]'https://maclookup.app', [Net.WebUtility]::HtmlDecode($link.href))
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'maclookup.app') { throw 'Unexpected download host.' }
    Invoke-WebRequest -UseBasicParsing -Uri $uri.AbsoluteUri -OutFile $temporary
    $records = Get-Content -Raw -Encoding UTF8 -LiteralPath $temporary | ConvertFrom-Json
    if ($records.Count -lt 50000 -or -not $records[0].macPrefix -or -not $records[0].vendorName) { throw 'Invalid vendor database.' }
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    Write-Output "Saved $($records.Count) vendor records. Update assets/data/SOURCE.json with the new source date and hash."
    Get-FileHash -LiteralPath $destination -Algorithm SHA256
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
}
