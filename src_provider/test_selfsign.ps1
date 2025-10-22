param(
	[string]$OpenSslConfig = "testOpenssl.cnf",
	[string]$ProviderName = "akv_provider",
	[string]$KeyUri = "managedhsm:ManagedHSMOpenSSLEngine:myrsakey",
	[string]$PropQuery = "?provider=akv_provider",
	[string]$CsrPath = "cert.csr"
)

if ([string]::IsNullOrWhiteSpace($PropQuery)) {
	$PropQuery = "?provider=$ProviderName"
}

"--Configure logging--"
$logDirectory = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $logDirectory)) {
	New-Item -Path $logDirectory -ItemType Directory | Out-Null
}

$Env:AKV_LOG_FILE = Join-Path $logDirectory "selfsign_akv.log"
$Env:AKV_LOG_LEVEL = "4" # Trace
$Env:OSSL_TRACE = "STORE,FETCH,PROVIDER,SIGNATURE"
$Env:OSSL_TRACE_FILE = Join-Path $logDirectory "selfsign_openssl.trace"

"--Acquire access token--"
$s = (az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t = $s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN = $t.accessToken

"--Generate CSR from mHSM key via OpenSSL provider--"
openssl req `
	-new `
	-x509 `
	-verbose `
	-config $OpenSslConfig `
	-provider $ProviderName `
	-propquery $PropQuery `
	-key $KeyUri `
	-out .\cert.pem

"--OpenSSL exit code--"
Write-Host $LASTEXITCODE

if (Test-Path .\cert.pem)
{
	"--cert.pem created--"
	Get-Item .\cert.pem | Select-Object FullName, Length, LastWriteTime
}
else
{
	"--cert.pem missing--"
}

