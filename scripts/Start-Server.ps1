param([string]$Url = "http://127.0.0.1:5180")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$configPath = Join-Path $root ".env"
$settings = @{}
Get-Content -LiteralPath $configPath | ForEach-Object {
    if ($_ -match '^\s*([A-Z_]+)\s*=(.*)$') { $settings[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'") }
}
function Quote-ConnectionValue([string]$value) { return '"' + $value.Replace('"', '""') + '"' }
$env:ConnectionStrings__Postgres = "Host=127.0.0.1;Port=5432;Database=$(Quote-ConnectionValue $settings['POSTGRES_DB']);Username=$(Quote-ConnectionValue $settings['POSTGRES_USER']);Password=$(Quote-ConnectionValue $settings['POSTGRES_PASSWORD'])"
$env:Minio__AccessKey = $settings['MINIO_ROOT_USER']
$env:Minio__SecretKey = $settings['MINIO_ROOT_PASSWORD']
$env:Leakage__Path = Join-Path $root "tmp/server-leakage.jsonl"
dotnet run --project (Join-Path $root "Backend/CipherSearch.Server") -c Release --no-build --no-launch-profile -- --urls $Url --environment Development
exit $LASTEXITCODE
