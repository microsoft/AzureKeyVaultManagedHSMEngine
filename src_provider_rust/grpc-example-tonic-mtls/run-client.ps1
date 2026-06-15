<#
.SYNOPSIS
    Run the tonic mTLS client (Windows).

.DESCRIPTION
    Windows-native counterpart to run-client.sh. Renders the openssl config
    if not present, builds the client if needed, and runs it.
#>
[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [string]$EnvFile
)

$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir    = Join-Path $ScriptDir 'certs'
$ProviderDir = (Resolve-Path (Join-Path $ScriptDir '..\target\release')).Path
$ProviderDll = Join-Path $ProviderDir 'akv_provider.dll'

if (-not (Test-Path $ProviderDll)) {
    throw "akv_provider.dll not found at $ProviderDll. Build the provider first."
}

# ---- load .env (use -EnvFile param, then $env:ENV_FILE, then default .env) ----
if (-not $EnvFile) { $EnvFile = $env:ENV_FILE }
if (-not $EnvFile) { $EnvFile = Join-Path $ScriptDir '.env' }
if (-not [System.IO.Path]::IsPathRooted($EnvFile)) {
    $EnvFile = Join-Path $ScriptDir $EnvFile
}
if (-not (Test-Path $EnvFile)) {
    throw "Env file '$EnvFile' missing. Copy .env.example (or .env.rsa.example / .env.ec.example) and edit it."
}
Write-Host "Loading config from $EnvFile"
Get-Content $EnvFile | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    $v = $v.Trim()
    if ($v -match '^"(.*)"$' -or $v -match "^'(.*)'$") { $v = $Matches[1] }
    Set-Item -Path "env:$($k.Trim())" -Value $v
}

# ---- build if needed ----
if (-not $SkipBuild) {
    Write-Host "Building tonic-mtls-client (release)..."
    Push-Location $ScriptDir
    try { cargo build --release --bin tonic-mtls-client | Out-Host }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}
$ClientBin = Join-Path $ScriptDir 'target\release\tonic-mtls-client.exe'
if (-not (Test-Path $ClientBin)) { throw "client binary missing: $ClientBin" }

# ---- render openssl.cnf if not present (server normally creates it) ----
$cnfPath = Join-Path $ScriptDir 'openssl-provider.cnf'
if (-not (Test-Path $cnfPath)) {
    $tpl = Get-Content (Join-Path $ScriptDir 'openssl-provider.cnf.template') -Raw
    $modulePath = ($ProviderDll -replace '\\', '/')
    $rendered = $tpl -replace 'PROVIDER_PATH/libakv_provider\.so', $modulePath
    $rendered | Set-Content $cnfPath -NoNewline
}

# ---- Azure access token ----
if (-not $env:AZURE_CLI_ACCESS_TOKEN) {
    Write-Host "Acquiring Azure access token via az cli..."
    $env:AZURE_CLI_ACCESS_TOKEN = az account get-access-token `
        --output tsv --query accessToken `
        --tenant $env:AZURE_TENANT_ID `
        --resource https://managedhsm.azure.net
}

# ---- run ----
$env:OPENSSL_CONF    = $cnfPath
$env:HSM_KEY_URI     = "managedhsm:$($env:HSM_NAME):$($env:HSM_KEY_NAME)"
$env:CLIENT_CERT_PEM = Join-Path $CertsDir 'client.crt'
$env:CA_CERT_PEM     = Join-Path $CertsDir 'ca.crt'
if (-not $env:GRPC_SERVER_ADDR) { $env:GRPC_SERVER_ADDR = 'https://localhost:50443' }
if (-not $env:GRPC_SERVER_NAME) { $env:GRPC_SERVER_NAME = 'localhost' }
if (-not $env:RUST_LOG)         { $env:RUST_LOG = 'info' }

& $ClientBin
