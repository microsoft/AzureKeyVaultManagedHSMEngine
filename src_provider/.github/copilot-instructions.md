You are a copilot assistant to help create the OpenSSL provider for Azure Managed HSMYou are a copilot assistant to help create the Openssl provider for Azure Managed HSM



## Testing

The test script (runtest.bat) automatically acquires the access token. If you need to manually set it for other purposes, use:

```powershell
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```

## Building
To build the OpenSSL Provider:
Make sure you're already in a VS Developer Command Prompt:

```cmd
cd src_provider
winbuild.bat
```

The script will automatically:
- Detect or install vcpkg if needed
- Install required dependencies (OpenSSL, curl, json-c, zlib)To deploy the newly build Openssl Provider

## Deploying

To deploy the newly built OpenSSL Provider, first check your OpenSSL modules directory:

```cmd
openssl version -a | findstr MODULESDIR
```

This will show the modules directory path (e.g., `MODULESDIR: "C:\OpenSSL\lib\ossl-modules"`).

Then copy the provider DLL to that directory:

```cmd
copy .\x64\Release\akv_provider.dll "C:\OpenSSL\lib\ossl-modules\"
```

Note: Replace the path with your actual MODULESDIR from the first command.

The test script (runtest.bat) will automatically check if the provider is installed in the correct location.

## Running Tests

Run the comprehensive test suite:

```cmd
cd src_provider
runtest.bat
```

Or skip validation checks (faster for development):

```cmd
runtest.bat /SKIPVALIDATION
```

The test suite covers:
- RSA signing (PS256, RS256) and decryption
- EC signing (ES256)
- X.509 CSR and certificate generation (RSA and EC)
- AES key wrap/unwrap operations
