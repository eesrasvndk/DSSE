param([switch]$Storage)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root "Backend/CipherSearch.Tests/CipherSearch.Tests.csproj"
if ($Storage) {
    $env:CIPHERSEARCH_INTEGRATION = "1"
    $env:CIPHERSEARCH_ENV_FILE = Join-Path $root ".env"
    dotnet test $project -c Release --no-restore --filter "Category=Integration"
} else {
    dotnet test $project -c Release --no-restore --filter "Category!=Integration"
}
exit $LASTEXITCODE
