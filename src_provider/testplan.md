# Azure Key Vault Provider Test Plan

## Preparation
- Build the provider using `src_provider/winbuild.bat` or `src_provider/build_with_vsdev.bat`. Copy the resulting `akv_provider.dll` into a staging folder (e.g. `out/modules`).
- Ensure an Azure Key Vault or Managed HSM key is available (name, version, algorithm). Confirm the test host has credentials (Managed Identity or service principal) granting sign/decrypt permissions.
- Locate the OpenSSL 3 binary from vcpkg (e.g. `./vcpkg_installed/x64-windows/tools/openssl/openssl.exe`). Export `OPENSSL_MODULES=<stage-dir>` or prepare to pass `-provider_path` on the command line.
- Create a minimal OpenSSL config (e.g. `openssl_akv.cnf`) that loads both the default provider and `akv_provider`. Export `OPENSSL_CONF` or supply `-config` when running tests.

## Smoke Checks
- Run `openssl list -providers -provider akv_provider -provider_path <stage-dir>` to confirm the provider loads and exposes metadata.
- After algorithms are registered, verify they appear via `openssl list -signature-algorithms -provider akv_provider ...` and the equivalent decrypt listings.

## Signing Flow
- Export the public key using the provider once URI support exists (e.g. `openssl pkey -provider akv_provider -provider_path <stage-dir> -in "akv:keyvault_type=managedHsm,keyvault_name=<vault>,key_name=<key>,alg=RS256" -pubout`).
- Sign a digest: `openssl dgst -sha256 -sign "akv:keyvault_type=...,keyvault_name=...,key_name=...,alg=RS256" -provider akv_provider -provider_path <stage-dir> -out sig.bin input.bin`.
- Verify the signature with the default provider and the exported public key: `openssl dgst -sha256 -verify exported_pub.pem -signature sig.bin input.bin`.
- Negative test: request an unsupported hash/algorithm pairing and confirm a helpful error surfaces.

## Decrypt Flow
- Encrypt sample plaintext locally with the exported public key: `openssl pkeyutl -encrypt -pubin -inkey exported_pub.pem -in plain.txt -out cipher.bin`.
- Decrypt through AKV: `openssl pkeyutl -decrypt -inkey "akv:keyvault_type=...,keyvault_name=...,key_name=...,alg=RSA-OAEP" -provider akv_provider -provider_path <stage-dir> -in cipher.bin -out roundtrip.txt`.
- Compare `plain.txt` and `roundtrip.txt` to confirm success; add cases for oversized payloads or disabled algorithms to validate error handling.

## Automation
- Wrap the commands in a PowerShell script that sets environment variables (`AKV_TYPE`, `AKV_VAULT`, `AKV_KEY`, credential secrets). Make the script exit non-zero on failures.
- Allow enabling verbose logging via `AKV_LOG_LEVEL=2` to capture REST traces during CI or troubleshooting.
