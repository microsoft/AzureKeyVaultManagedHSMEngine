<#
.SYNOPSIS
    Render openssl-provider.cnf for Windows and start the tonic mTLS server.

.DESCRIPTION
    Windows-native counterpart to start-server.sh. Builds the example if
    needed, renders the openssl config with the absolute Windows path to
    akv_provider.dll (forward slashes), then runs tonic-mtls-server.exe.
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
    throw "akv_provider.dll not found at $ProviderDll. Build the provider first: (cd ..; cargo build --release)"
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
    Write-Host "Building tonic-mtls-server (release)..."
    Push-Location $ScriptDir
    try { cargo build --release --bin tonic-mtls-server | Out-Host }
    finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}
$ServerBin = Join-Path $ScriptDir 'target\release\tonic-mtls-server.exe'
if (-not (Test-Path $ServerBin)) { throw "server binary missing: $ServerBin" }

# ---- render openssl.cnf with the real provider path ----
# OpenSSL on Windows accepts forward slashes in module = ... and avoids
# the backslash-escape headaches in INI parsing.
$tpl = Get-Content (Join-Path $ScriptDir 'openssl-provider.cnf.template') -Raw
$modulePath = ($ProviderDll -replace '\\', '/')
$rendered   = $tpl -replace 'PROVIDER_PATH/libakv_provider\.so', $modulePath
$cnfPath    = Join-Path $ScriptDir 'openssl-provider.cnf'
$rendered | Set-Content $cnfPath -NoNewline
Write-Host "Rendered openssl config: $cnfPath"

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
$env:SERVER_CERT_PEM = Join-Path $CertsDir 'server.crt'
$env:CA_CERT_PEM     = Join-Path $CertsDir 'ca.crt'
if (-not $env:GRPC_BIND_ADDR) { $env:GRPC_BIND_ADDR = '127.0.0.1:50443' }
if (-not $env:RUST_LOG)       { $env:RUST_LOG = 'info' }

& $ServerBin
