<#
.SYNOPSIS
    Generate CA, server, and client certs all signed by the same MHSM RSA key.

.DESCRIPTION
    Windows-native counterpart to generate-certs.sh. Tested with Git for
    Windows' bundled openssl.exe 3.5.x as the CLI host; the akv_provider.dll
    must be present at ..\target\release\akv_provider.dll.

    All three certs use the same HSM key for the private operation but
    carry different identities (CA, server, client).
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir    = Join-Path $ScriptDir 'certs'
$ProviderDir = (Resolve-Path (Join-Path $ScriptDir '..\target\release')).Path
$ProviderDll = Join-Path $ProviderDir 'akv_provider.dll'

if (-not (Test-Path $ProviderDll)) {
    throw "akv_provider.dll not found at $ProviderDll. Build the provider first: (cd ..; cargo build --release)"
}

# ---- load .env ----
$EnvFile = Join-Path $ScriptDir '.env'
if (-not (Test-Path $EnvFile)) {
    throw ".env missing. Copy .env.example to .env and edit it."
}
Get-Content $EnvFile | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    Set-Item -Path "env:$($k.Trim())" -Value $v.Trim()
}

if (-not $env:HSM_NAME)        { throw 'HSM_NAME not set in .env' }
if (-not $env:HSM_KEY_NAME)    { throw 'HSM_KEY_NAME not set in .env' }
if (-not $env:AZURE_TENANT_ID) { throw 'AZURE_TENANT_ID not set in .env' }

$HsmUri  = "managedhsm:$($env:HSM_NAME):$($env:HSM_KEY_NAME)"
$ServerCN = if ($env:SERVER_CN) { $env:SERVER_CN } else { 'localhost' }
$ClientCN = if ($env:CLIENT_CN) { $env:CLIENT_CN } else { 'tonic-grpc-client' }
$Days     = if ($env:CERT_DAYS) { $env:CERT_DAYS } else { 365 }

$Country = if ($env:CERT_COUNTRY) { $env:CERT_COUNTRY } else { 'US' }
$State   = if ($env:CERT_STATE)   { $env:CERT_STATE }   else { 'Washington' }
$City    = if ($env:CERT_CITY)    { $env:CERT_CITY }    else { 'Redmond' }
$Org     = if ($env:CERT_ORG)     { $env:CERT_ORG }     else { 'Microsoft' }
$OU      = if ($env:CERT_OU)      { $env:CERT_OU }      else { 'Azure HSM gRPC Tonic Demo' }
$SubjBase = "/C=$Country/ST=$State/L=$City/O=$Org/OU=$OU"

# ---- find openssl.exe ----
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue)?.Source
if (-not $openssl) {
    $candidate = 'C:\Program Files\Git\usr\bin\openssl.exe'
    if (Test-Path $candidate) { $openssl = $candidate }
}
if (-not $openssl) {
    throw "openssl.exe not on PATH. Install OpenSSL 3.x or add Git for Windows' usr\bin to PATH."
}
Write-Host "Using openssl: $openssl"
Write-Host "HSM key URI:   $HsmUri"
Write-Host ""

# ---- Azure access token ----
if (-not $env:AZURE_CLI_ACCESS_TOKEN) {
    Write-Host "Acquiring Azure access token via az cli..."
    $env:AZURE_CLI_ACCESS_TOKEN = az account get-access-token `
        --output tsv --query accessToken `
        --tenant $env:AZURE_TENANT_ID `
        --resource https://managedhsm.azure.net
    if (-not $env:AZURE_CLI_ACCESS_TOKEN) {
        throw "az account get-access-token failed (run 'az login --tenant $env:AZURE_TENANT_ID' first)"
    }
}

New-Item -ItemType Directory -Force -Path $CertsDir | Out-Null

function Invoke-OpenSSLProvider {
    # Run openssl with the AKV provider loaded. Returns last error line if non-zero.
    & $openssl @args -provider-path "$ProviderDir" -provider akv_provider -provider default
    if ($LASTEXITCODE -ne 0) {
        throw "openssl $($args[0]) exited with code $LASTEXITCODE"
    }
}

# ---- CA ----
Write-Host "=== Step 1: CA ==="
@"
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"@ | Set-Content (Join-Path $CertsDir 'ca.ext') -NoNewline

Invoke-OpenSSLProvider req -new `
    -key $HsmUri `
    -subj "$SubjBase/CN=tonic-mTLS-CA" `
    -out (Join-Path $CertsDir 'ca.csr')

Invoke-OpenSSLProvider x509 -req `
    -in (Join-Path $CertsDir 'ca.csr') `
    -signkey $HsmUri `
    -days $Days -sha256 `
    -extfile (Join-Path $CertsDir 'ca.ext') `
    -out (Join-Path $CertsDir 'ca.crt')

# ---- Server ----
Write-Host "=== Step 2: Server ==="
@"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$ServerCN, DNS:localhost, IP:127.0.0.1, IP:::1
"@ | Set-Content (Join-Path $CertsDir 'server.ext') -NoNewline

Invoke-OpenSSLProvider req -new `
    -key $HsmUri `
    -subj "$SubjBase/CN=$ServerCN" `
    -out (Join-Path $CertsDir 'server.csr')

Invoke-OpenSSLProvider x509 -req `
    -in (Join-Path $CertsDir 'server.csr') `
    -CA (Join-Path $CertsDir 'ca.crt') `
    -CAkey $HsmUri -CAcreateserial `
    -days $Days -sha256 `
    -extfile (Join-Path $CertsDir 'server.ext') `
    -out (Join-Path $CertsDir 'server.crt')

# ---- Client ----
Write-Host "=== Step 3: Client ==="
@"
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:$ClientCN
"@ | Set-Content (Join-Path $CertsDir 'client.ext') -NoNewline

Invoke-OpenSSLProvider req -new `
    -key $HsmUri `
    -subj "$SubjBase/CN=$ClientCN" `
    -out (Join-Path $CertsDir 'client.csr')

Invoke-OpenSSLProvider x509 -req `
    -in (Join-Path $CertsDir 'client.csr') `
    -CA (Join-Path $CertsDir 'ca.crt') `
    -CAkey $HsmUri -CAcreateserial `
    -days $Days -sha256 `
    -extfile (Join-Path $CertsDir 'client.ext') `
    -out (Join-Path $CertsDir 'client.crt')

# ---- Verify ----
Write-Host ""
Write-Host "=== Step 4: Verify chains ==="
& $openssl verify -CAfile (Join-Path $CertsDir 'ca.crt') (Join-Path $CertsDir 'server.crt')
& $openssl verify -CAfile (Join-Path $CertsDir 'ca.crt') (Join-Path $CertsDir 'client.crt')

Write-Host ""
Write-Host "Certificates written to $CertsDir\"
Get-ChildItem $CertsDir -Filter '*.crt' | Select-Object Name, Length, LastWriteTime
