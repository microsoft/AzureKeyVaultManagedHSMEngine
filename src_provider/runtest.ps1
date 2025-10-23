Write-Host '=== Azure Managed HSM signing tests ==='
$ErrorActionPreference = 'Stop'

$scriptCommandPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$usingProfile = $true
foreach ($arg in [System.Environment]::GetCommandLineArgs()) {
	if ($arg -ieq '-noprofile' -or $arg -ieq '/noprofile') {
		$usingProfile = $false
		break
	}
}
if ($usingProfile -and $scriptCommandPath) {
	$recommendedCommand = "pwsh -NoProfile -ExecutionPolicy Bypass -File `"$scriptCommandPath`""
	Write-Host "This script must run without PowerShell profiles. Re-run using: $recommendedCommand"
	Pop-Location 2>$null
	return
}

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
	$aesKeyName = if ($Env:AKV_AES_KEY) { $Env:AKV_AES_KEY } else { 'myaeskey' }

	$rsaKeyId = "https://$vaultName.managedhsm.azure.net/keys/$rsaKeyName"
	$ecKeyId = "https://$vaultName.managedhsm.azure.net/keys/$ecKeyName"

	$rsaProviderPath = "managedhsm:$($vaultName):$($rsaKeyName)"
	$ecProviderPath = "managedhsm:$($vaultName):$($ecKeyName)"
	$aesProviderPath = "managedhsm:$($vaultName):$($aesKeyName)"
	Write-Host "Using vault '$vaultName' with RSA key '$rsaKeyName', EC key '$ecKeyName', and AES key '$aesKeyName'."

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

		$cliIsValid = $null
		if ($null -ne $result) {
			if ($result.PSObject.Properties.Name -contains 'isValid') {
				$cliIsValid = [bool]$result.isValid
			}
			elseif ($result.PSObject.Properties.Name -contains 'value' -and $null -ne $result.value) {
				$cliIsValid = [bool]$result.value.isValid
			}
		}

		if ($cliIsValid -ne $true) {
			throw "az keyvault key verify returned false for $Algorithm"
		}
	}

	function Convert-DerEcdsaSignatureToP1363 {
		param(
			[byte[]]$DerSignature,
			[int]$ComponentSizeBytes
		)

		$asnReader = [System.Formats.Asn1.AsnReader]::new($DerSignature, [System.Formats.Asn1.AsnEncodingRules]::DER)
		$sequence = $asnReader.ReadSequence()
		$rBytes = $sequence.ReadIntegerBytes().ToArray()
		$sBytes = $sequence.ReadIntegerBytes().ToArray()
		$sequence.ThrowIfNotEmpty()
		$asnReader.ThrowIfNotEmpty()

		$signature = New-Object byte[] ($ComponentSizeBytes * 2)
		$rCopyLength = [Math]::Min($ComponentSizeBytes, $rBytes.Length)
		$sCopyLength = [Math]::Min($ComponentSizeBytes, $sBytes.Length)
		if ($rCopyLength -gt 0) {
			[Array]::Copy($rBytes, $rBytes.Length - $rCopyLength, $signature, $ComponentSizeBytes - $rCopyLength, $rCopyLength)
		}
		if ($sCopyLength -gt 0) {
			[Array]::Copy($sBytes, $sBytes.Length - $sCopyLength, $signature, ($ComponentSizeBytes * 2) - $sCopyLength, $sCopyLength)
		}
		return $signature
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
		'-out', 'ps256.sig',
		'input.bin'
	)
	$rsaSignatureBytes = [IO.File]::ReadAllBytes('ps256.sig')

	Invoke-OpenSslCommand @('dgst', '-sha256', '-verify', 'myrsakey_pub.pem', '-signature', 'ps256.sig', '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest', '-sigopt', 'rsa_mgf1_md:sha256', 'input.bin')
	Invoke-AzVerification -KeyId $rsaKeyId -Algorithm 'PS256' -DigestBytes $digestBytes -SignatureBytes $rsaSignatureBytes

	Write-Host '--- RSA RS256 signing roundtrip ---'
	Invoke-OpenSslCommand @(
		'dgst',
		'-sha256',
		'-sign', $rsaProviderPath,
		'-provider', 'akv_provider',
		'-sigopt', 'rsa_padding_mode:pkcs1',
		'-out', 'rs256.sig',
		'input.bin'
	)
	$rs256SignatureBytes = [IO.File]::ReadAllBytes('rs256.sig')

	Invoke-OpenSslCommand @('dgst', '-sha256', '-verify', 'myrsakey_pub.pem', '-signature', 'rs256.sig', '-sigopt', 'rsa_padding_mode:pkcs1', 'input.bin')
	Invoke-AzVerification -KeyId $rsaKeyId -Algorithm 'RS256' -DigestBytes $digestBytes -SignatureBytes $rs256SignatureBytes

	Write-Host '--- RSA OAEP decrypt roundtrip ---'
	Invoke-OpenSslCommand @(
		'pkeyutl',
		'-encrypt',
		'-pubin',
		'-inkey', 'myrsakey_pub.pem',
		'-in', 'input.bin',
		'-out', 'rsa_cipher.bin',
		'-pkeyopt', 'rsa_padding_mode:oaep',
		'-pkeyopt', 'rsa_oaep_md:sha1',
		'-pkeyopt', 'rsa_mgf1_md:sha1'
	)
	Invoke-OpenSslCommand @(
		'pkeyutl',
		'-decrypt',
		'-provider', 'akv_provider',
		'-inkey', $rsaProviderPath,
		'-in', 'rsa_cipher.bin',
		'-out', 'rsa_roundtrip.bin'
	)
	$roundtripBytes = [IO.File]::ReadAllBytes('rsa_roundtrip.bin')
	if (-not [System.Linq.Enumerable]::SequenceEqual($inputBytes, $roundtripBytes)) {
		throw 'RSA decrypt roundtrip mismatch (input.bin vs rsa_roundtrip.bin)'
	}
	Write-Host 'RSA decrypt roundtrip matches input.bin.'

	Write-Host '--- EC ES256 signing roundtrip ---'
	Invoke-OpenSslCommand @('dgst', '-sha256', '-sign', $ecProviderPath, '-provider', 'akv_provider', '-out', 'es256.sig', 'input.bin')
	$ecSignatureDer = [IO.File]::ReadAllBytes('es256.sig')
	$ecSignatureBytes = Convert-DerEcdsaSignatureToP1363 -DerSignature $ecSignatureDer -ComponentSizeBytes 32

	Invoke-OpenSslCommand @('dgst', '-sha256', '-verify', 'ecckey_pub.pem', '-signature', 'es256.sig', 'input.bin')
	Invoke-AzVerification -KeyId $ecKeyId -Algorithm 'ES256' -DigestBytes $digestBytes -SignatureBytes $ecSignatureBytes

	Write-Host ''
	Write-Host '=== X.509 CSR and Certificate Tests ==='
	Write-Host ''

	$opensslConfig = 'testOpenssl.cnf'
	if (-not (Test-Path $opensslConfig)) {
		Write-Host "Warning: OpenSSL config '$opensslConfig' not found. Using default config for CSR/cert tests."
		$opensslConfig = $null
	}

	Write-Host '--- RSA CSR generation and verification ---'
	$csrPath = 'cert.csr'
	
	$reqArgs = @(
		'req'
		'-new'
		'-provider', 'akv_provider'
		'-key', $rsaProviderPath
		'-sha256'
		'-sigopt', 'rsa_padding_mode:pkcs1'
		'-out', $csrPath
	)
	if ($opensslConfig) {
		$reqArgs = @('req', '-config', $opensslConfig) + $reqArgs[1..($reqArgs.Length - 1)]
	} else {
		# Add subject directly if no config file
		$reqArgs += @('-subj', '/CN=Azure Managed HSM Test/O=Microsoft/C=US')
	}
	
	Invoke-OpenSslCommand $reqArgs
	
	Write-Host 'Displaying CSR contents:'
	Invoke-OpenSslCommand @('req', '-text', '-in', $csrPath, '-noout')
	
	Write-Host 'Verifying CSR signature with provider:'
	Invoke-OpenSslCommand @('req', '-in', $csrPath, '-noout', '-verify', '-provider', 'akv_provider')
	
	Write-Host 'CSR verification successful.'

	Write-Host '--- RSA self-signed certificate generation ---'
	$certPath = 'cert.pem'
	
	$certArgs = @(
		'req'
		'-new'
		'-x509'
		'-provider', 'akv_provider'
		'-propquery', '?provider=akv_provider'
		'-key', $rsaProviderPath
		'-sha256'
		'-days', '365'
		'-out', $certPath
	)
	if ($opensslConfig) {
		$certArgs = @('req', '-config', $opensslConfig) + $certArgs[1..($certArgs.Length - 1)]
	} else {
		# Add subject directly if no config file
		$certArgs += @('-subj', '/CN=Azure Managed HSM Self-Signed/O=Microsoft/C=US')
	}
	
	Invoke-OpenSslCommand $certArgs
	
	if (Test-Path $certPath) {
		Write-Host "Self-signed certificate created: $certPath"
		Get-Item $certPath | Select-Object FullName, Length, LastWriteTime | Format-List
		
		Write-Host 'Displaying certificate contents:'
		Invoke-OpenSslCommand @('x509', '-in', $certPath, '-text', '-noout')
		
		Write-Host 'Verifying certificate signature:'
		Invoke-OpenSslCommand @('verify', '-provider', 'akv_provider', '-CAfile', $certPath, $certPath)
		
		Write-Host 'Self-signed certificate verification successful.'
	} else {
		throw "Certificate file '$certPath' was not created."
	}

	Write-Host '--- EC CSR generation and verification ---'
	$ecCsrPath = 'ec_cert.csr'
	
	$ecReqArgs = @(
		'req'
		'-new'
		'-provider', 'akv_provider'
		'-key', $ecProviderPath
		'-sha256'
		'-out', $ecCsrPath
	)
	if ($opensslConfig) {
		$ecReqArgs = @('req', '-config', $opensslConfig) + $ecReqArgs[1..($ecReqArgs.Length - 1)]
	} else {
		$ecReqArgs += @('-subj', '/CN=Azure Managed HSM EC Test/O=Microsoft/C=US')
	}
	
	Invoke-OpenSslCommand $ecReqArgs
	
	Write-Host 'Displaying EC CSR contents:'
	Invoke-OpenSslCommand @('req', '-text', '-in', $ecCsrPath, '-noout')
	
	Write-Host 'Verifying EC CSR signature with provider:'
	Invoke-OpenSslCommand @('req', '-in', $ecCsrPath, '-noout', '-verify', '-provider', 'akv_provider')
	
	Write-Host 'EC CSR verification successful.'

	Write-Host '--- EC self-signed certificate generation ---'
	$ecCertPath = 'ec_cert.pem'
	
	$ecCertArgs = @(
		'req'
		'-new'
		'-x509'
		'-provider', 'akv_provider'
		'-propquery', '?provider=akv_provider'
		'-key', $ecProviderPath
		'-sha256'
		'-days', '365'
		'-out', $ecCertPath
	)
	if ($opensslConfig) {
		$ecCertArgs = @('req', '-config', $opensslConfig) + $ecCertArgs[1..($ecCertArgs.Length - 1)]
	} else {
		$ecCertArgs += @('-subj', '/CN=Azure Managed HSM EC Self-Signed/O=Microsoft/C=US')
	}
	
	Invoke-OpenSslCommand $ecCertArgs
	
	if (Test-Path $ecCertPath) {
		Write-Host "EC self-signed certificate created: $ecCertPath"
		Get-Item $ecCertPath | Select-Object FullName, Length, LastWriteTime | Format-List
		
		Write-Host 'Displaying EC certificate contents:'
		Invoke-OpenSslCommand @('x509', '-in', $ecCertPath, '-text', '-noout')
		
		Write-Host 'Verifying EC certificate signature:'
		Invoke-OpenSslCommand @('verify', '-provider', 'akv_provider', '-CAfile', $ecCertPath, $ecCertPath)
		
		Write-Host 'EC self-signed certificate verification successful.'
	} else {
		throw "EC certificate file '$ecCertPath' was not created."
	}

	Write-Host ''
	Write-Host '=== AES Key Wrap/Unwrap Tests ==='
	Write-Host ''

	Write-Host '--- Generating 32-byte test key ---'
	Invoke-OpenSslCommand @('rand', '-out', 'local.key', '32')
	$keySize = (Get-Item 'local.key').Length
	Write-Host "Generated local.key ($keySize bytes)"

	Write-Host '--- Wrapping key with Azure Managed HSM AES key ---'
	Invoke-OpenSslCommand @(
		'pkeyutl',
		'-encrypt',
		'-inkey', $aesProviderPath,
		'-provider', 'akv_provider',
		'-in', 'local.key',
		'-out', 'local.key.wrap'
	)
	$wrappedSize = (Get-Item 'local.key.wrap').Length
	Write-Host "Wrapped successfully -> local.key.wrap ($wrappedSize bytes)"

	Write-Host '--- Unwrapping key with Azure Managed HSM AES key ---'
	Invoke-OpenSslCommand @(
		'pkeyutl',
		'-decrypt',
		'-inkey', $aesProviderPath,
		'-provider', 'akv_provider',
		'-in', 'local.key.wrap',
		'-out', 'local.key.unwrapped'
	)
	$unwrappedSize = (Get-Item 'local.key.unwrapped').Length
	Write-Host "Unwrapped successfully -> local.key.unwrapped ($unwrappedSize bytes)"

	Write-Host '--- Comparing original and unwrapped keys ---'
	$originalKey = [System.IO.File]::ReadAllBytes('local.key')
	$unwrappedKey = [System.IO.File]::ReadAllBytes('local.key.unwrapped')

	if ($originalKey.Length -ne $unwrappedKey.Length) {
		throw "AES wrap/unwrap failed: Size mismatch (original=$($originalKey.Length) unwrapped=$($unwrappedKey.Length))"
	}

	$keysMatch = $true
	for ($i = 0; $i -lt $originalKey.Length; $i++) {
		if ($originalKey[$i] -ne $unwrappedKey[$i]) {
			$keysMatch = $false
			break
		}
	}

	if (-not $keysMatch) {
		throw 'AES wrap/unwrap failed: Keys do not match'
	}
	Write-Host 'Keys match perfectly!'

	Write-Host '--- Negative test: Tamper with wrapped key ---'
	$wrappedBytes = [System.IO.File]::ReadAllBytes('local.key.wrap')
	$wrappedBytes[0] = $wrappedBytes[0] -bxor 0xFF  # Flip first byte
	[System.IO.File]::WriteAllBytes('local.key.wrap.tampered', $wrappedBytes)

	Write-Host 'Attempting to unwrap tampered key (should fail)...'
	& openssl pkeyutl -decrypt -inkey $aesProviderPath -provider akv_provider -in local.key.wrap.tampered -out local.key.bad 2>$null
	if ($LASTEXITCODE -eq 0) {
		throw 'Tampered key unwrap should have failed but succeeded'
	}
	Write-Host 'Expected failure on tampered key - PASSED'

	Write-Host ''
	Write-Host '=== All tests completed successfully ==='
	Write-Host ''
}
finally {
	Pop-Location
}