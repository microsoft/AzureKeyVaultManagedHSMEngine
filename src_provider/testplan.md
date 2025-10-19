# Azure Key Vault Provider Plan

## Get Openssl settings
```
openssl version -a
```
Looking for OPENSSLDIR and MODULESDIR, for example
```
OPENSSLDIR: "C:\OpenSSL\ssl"
MODULESDIR: "C:\OpenSSL\lib\ossl-modules"
```
The openssl.cnf will be stored in OPENSSLDIR
The provider DLL will be deployed to MODULESDIR

## Get the access token for Azure managed HSM
use the following powershell
```
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```
## Build 
run `src_provider/build_with_vsdev.bat`

## Deploy
run `copy .\x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules`

## Initialize the openssl.cnf
```
[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
akv_provider = akv_provider_sect

[default_sect]
activate = 1
[akv_provider_sect]
activate = 1
```

## Check if provider is activated
run `openssl list -providers`

## Managed HSM keys
Ensure the Managed HSM contains the pre-provisioned keys: `myrsakey` (RSA 2048 sign/decrypt), `myaeskey` (AES-256 wrap/unwrap), and `ecckey` (P-256 sign). Run `az keyvault key list --id https://ManagedHSMOpenSSLEngine.managedhsm.azure.net/` and confirm each key reports `enabled: true`.

## Smoke Checks
After algorithms are registered, verify they appear via `openssl list -signature-algorithms -provider akv_provider` and the equivalent decrypt listings.

## Signing Flow
- Export `myrsakey` or `ecckey` via the provider once URI support exists (e.g. `openssl pkey -provider akv_provider -in "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -pubout -out myrsakey_pub.pem`). Repeat for `ecckey` with `managedhsm:ManagedHSMOpenSSLEngine:ecckey`.
- RSA signing: `openssl dgst -sha256 -sign "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -provider akv_provider -provider_path <stage-dir> -out rs256.sig input.bin`. Verify with the exported public key: `openssl dgst -sha256 -verify myrsakey_pub.pem -signature rs256.sig input.bin`.
- ECC signing: `openssl dgst -sha256 -sign "managedhsm:ManagedHSMOpenSSLEngine:ecckey" -provider akv_provider -provider_path <stage-dir> -out es256.sig input.bin`. Verify with the exported EC public key: `openssl dgst -sha256 -verify ecckey_pub.pem -signature es256.sig input.bin`.
- Negative test: request an unsupported hash/algorithm pairing (e.g. ES384 with `myrsakey`) and confirm a helpful error surfaces.

## Decrypt Flow
- Encrypt sample plaintext locally with `myrsakey_pub.pem`: `openssl pkeyutl -encrypt -pubin -inkey myrsakey_pub.pem -in plain.txt -out rsa_cipher.bin`.
- Decrypt through AKV: `openssl pkeyutl -decrypt -inkey "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" -provider akv_provider -provider_path <stage-dir> -in rsa_cipher.bin -out rsa_roundtrip.txt`.
- Compare `plain.txt` and `rsa_roundtrip.txt` to confirm success; add cases for oversized payloads or disabled algorithms to validate error handling.

## AES Wrap Flow
- Generate a 32-byte local key to wrap: `openssl rand 32 > local.key`.
- Wrap using `myaeskey`: `openssl pkeyutl -wrap -inkey "managedhsm:ManagedHSMOpenSSLEngine:myaeskey" -provider akv_provider -provider_path <stage-dir> -in local.key -out local.key.wrap`.
- Unwrap with the same key: `openssl pkeyutl -unwrap -inkey "managedhsm:ManagedHSMOpenSSLEngine:myaeskey" -provider akv_provider -provider_path <stage-dir> -in local.key.wrap -out local.key.unwrapped`.
- Compare `local.key` and `local.key.unwrapped`; tamper with the wrapped blob to ensure unwrap fails cleanly.

## Automation
- Wrap the commands in a PowerShell script that sets environment variables (`AKV_TYPE`, `AKV_VAULT`, `AKV_KEY`, credential secrets). Make the script exit non-zero on failures.
- Allow enabling verbose logging via `AKV_LOG_LEVEL=2` to capture REST traces during CI or troubleshooting.
