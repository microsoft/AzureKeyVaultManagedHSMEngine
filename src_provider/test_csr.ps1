param(
	[string]$OpenSslConfig = "testOpenssl.cnf",
	[string]$ProviderName = "akv_provider",
	[string]$KeyUri = "managedhsm:ManagedHSMOpenSSLEngine:myrsakey",
	[string]$CsrPath = "cert.csr"
)

"--Acquire access token--"
$s = (az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t = $s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN = $t.accessToken

"--Generate CSR from mHSM key via OpenSSL provider--"
openssl req `
	-new `
	-config $OpenSslConfig `
	-provider $ProviderName `
	-key $KeyUri `
	-sha256 `
	-sigopt rsa_padding_mode:pkcs1 `
	-out $CsrPath

"--Show CSR--"
openssl req -text -in $CsrPath -noout

"--Verify CSR with provider--"
openssl req `
	-in $CsrPath `
	-noout `
	-verify `
	-provider $ProviderName

