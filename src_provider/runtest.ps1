Write-Host '=== Azure Managed HSM signing tests ==='
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptRoot) {
	$scriptRoot = Get-Location
}
Write-Host "Working directory: $scriptRoot"
Push-Location $scriptRoot
try {
	Write-Host 'Fetching Azure CLI access token...'

	$s = (az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
	$t = $s | ConvertFrom-Json
	$Env:AZURE_CLI_ACCESS_TOKEN = $t.accessToken

	$relativeLogPath = Join-Path '.' 'logs\akv_provider.log'
	$absoluteLogPath = Join-Path $scriptRoot 'logs\akv_provider.log'
	$Env:AKV_LOG_FILE = $relativeLogPath
	$Env:AKV_LOG_LEVEL = '3'
	Write-Host "Logging to $relativeLogPath (resolved $absoluteLogPath) at level $($Env:AKV_LOG_LEVEL)."

	$logDirectory = Split-Path -Parent $absoluteLogPath
	if ($logDirectory) {
		New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
	}

	if (-not (Test-Path 'input.bin')) {
		Write-Host 'Generating input.bin payload...'
		$payload = [Text.Encoding]::UTF8.GetBytes("Azure Managed HSM signing test`n")
		[IO.File]::WriteAllBytes('input.bin', $payload)
	} else {
		Write-Host 'Found existing input.bin payload.'
	}

	$vaultName = if ($Env:AKV_VAULT) { $Env:AKV_VAULT } else { 'ManagedHSMOpenSSLEngine' }
	$rsaKeyName = if ($Env:AKV_RSA_KEY) { $Env:AKV_RSA_KEY } else { 'myrsakey' }
	$ecKeyName = if ($Env:AKV_EC_KEY) { $Env:AKV_EC_KEY } else { 'ecckey' }

	$rsaKeyId = "https://$vaultName.managedhsm.azure.net/keys/$rsaKeyName"
	$ecKeyId = "https://$vaultName.managedhsm.azure.net/keys/$ecKeyName"

	$rsaProviderPath = "managedhsm:$($vaultName):$($rsaKeyName)"
	$ecProviderPath = "managedhsm:$($vaultName):$($ecKeyName)"
	Write-Host "Using vault '$vaultName' with RSA key '$rsaKeyName' and EC key '$ecKeyName'."

	function Invoke-OpenSslCommand {
		param([string[]]$ArgumentList)

		Write-Host "Running: openssl $($ArgumentList -join ' ')"
		& openssl @ArgumentList
		if ($LASTEXITCODE -ne 0) {
			throw "openssl $($ArgumentList -join ' ') failed with exit code $LASTEXITCODE"
		}
	}

	function Invoke-AzVerification {
		param(
			[string]$KeyId,
			[string]$Algorithm,
			[byte[]]$DigestBytes,
			[byte[]]$SignatureBytes
		)

		$digestB64 = [Convert]::ToBase64String($DigestBytes)
		$signatureB64 = [Convert]::ToBase64String($SignatureBytes)

		Write-Host "Running: az keyvault key verify --id $KeyId --algorithm $Algorithm"
		$result = az keyvault key verify --id $KeyId --algorithm $Algorithm --digest $digestB64 --signature $signatureB64 --output json | ConvertFrom-Json
		if ($LASTEXITCODE -ne 0) {
			throw "az keyvault key verify failed for $Algorithm (exit $LASTEXITCODE)"
		}
		if (-not $result.value.isValid) {
			throw "az keyvault key verify returned false for $Algorithm"
		}
	}

	$inputBytes = [IO.File]::ReadAllBytes('input.bin')
	Write-Host 'Computing SHA-256 digest for input.bin...'
	$sha256 = [System.Security.Cryptography.SHA256]::Create()
	$digestBytes = $sha256.ComputeHash($inputBytes)
	$sha256.Dispose()

	Write-Host '--- Exporting public keys via provider ---'
	Invoke-OpenSslCommand @('pkey', '-provider', 'akv_provider', '-in', $rsaProviderPath, '-pubout', '-out', 'myrsakey_pub.pem')
	Invoke-OpenSslCommand @('pkey', '-provider', 'akv_provider', '-in', $ecProviderPath, '-pubout', '-out', 'ecckey_pub.pem')

	Write-Host '--- RSA PS256 signing roundtrip ---'
	Invoke-OpenSslCommand @(
		'dgst',
		'-sha256',
		'-sign', $rsaProviderPath,
		'-provider', 'akv_provider',
		'-sigopt', 'rsa_padding_mode:pss',
		'-sigopt', 'rsa_pss_saltlen:digest',
		'-sigopt', 'rsa_mgf1_md:sha256',
		'-out', 'rs256.sig',
		'input.bin'
	)
	$rsaSignatureBytes = [IO.File]::ReadAllBytes('rs256.sig')

	Invoke-OpenSslCommand @('dgst', '-sha256', '-verify', 'myrsakey_pub.pem', '-signature', 'rs256.sig', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest', '-sigopt', 'rsa_mgf1_md:sha256', 'input.bin')
	Invoke-AzVerification -KeyId $rsaKeyId -Algorithm 'PS256' -DigestBytes $digestBytes -SignatureBytes $rsaSignatureBytes

	Write-Host '--- EC ES256 signing roundtrip ---'
	Invoke-OpenSslCommand @('dgst', '-sha256', '-sign', $ecProviderPath, '-provider', 'akv_provider', '-out', 'es256.sig', 'input.bin')
	$ecSignatureBytes = [IO.File]::ReadAllBytes('es256.sig')

	Invoke-OpenSslCommand @('dgst', '-sha256', '-verify', 'ecckey_pub.pem', '-signature', 'es256.sig', 'input.bin')
	Invoke-AzVerification -KeyId $ecKeyId -Algorithm 'ES256' -DigestBytes $digestBytes -SignatureBytes $ecSignatureBytes

	Write-Host 'Azure Managed HSM signing tests completed successfully.'
}
finally {
	Pop-Location
}