param([string]$ServerUrl = 'http://127.0.0.1:5180/', [switch]$Build)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if ($Build) {
    Push-Location (Join-Path $projectRoot 'Frontend')
    try {
        npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
    dotnet build (Join-Path $projectRoot 'Backend/CipherSearch.Web') -c Release
    if ($LASTEXITCODE -ne 0) { throw 'Client service build failed.' }
}
if (-not (Test-Path (Join-Path $projectRoot 'Backend/CipherSearch.Web/wwwroot/index.html'))) {
    throw 'Frontend output missing. Run ./scripts/Start-Web.ps1 -Build first.'
}
$env:ServerUrl = $ServerUrl
$env:VaultRoot = Join-Path $projectRoot 'tmp/web-vaults'
dotnet run --project (Join-Path $projectRoot 'Backend/CipherSearch.Web') -c Release --no-build --no-launch-profile
exit $LASTEXITCODE
