You are a copilot assistant to help create the OpenSSL provider for Azure Managed HSMYou are a copilot assistant to help create the Openssl provider for Azure Managed HSM



## Testing



When testing, always use the following PowerShell to acquire access token:When testing, always use the following powershell to acquire access token



```powershell```

$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)

$t=$s | ConvertFrom-Json$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)

$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken

```$t=$s | ConvertFrom-Json



## Building$Env:AZURE\_CLI\_ACCESS\_TOKEN=$t.accessToken



To build the OpenSSL Provider:```



### Option 1: Automated Build (Recommended)

```cmd

cd src_providerTo build the Openssl Provider

winbuild.bat

```run `src\_provider/build\_with\_vsdev.bat`



The script will automatically:

- Detect or install vcpkg if needed

- Install required dependencies (OpenSSL, curl, json-c, zlib)To deploy the newly build Openssl Provider

- Build akv_provider.dll

run `copy .\\x64\\Release\\akv\_provider.dll C:\\OpenSSL\\lib\\ossl-modules`

### Option 2: Visual Studio Developer Command Prompt

If you're already in a VS Developer Command Prompt:

```cmd

cd src_provider

set VCPKG_ROOT=C:\path\to\vcpkg

winbuild.bat
```

### Option 3: Visual Studio IDE
Open `src_provider\akv_provider.vcxproj` in Visual Studio 2022 and build.

## Deploying

To deploy the newly built OpenSSL Provider:

```cmd
copy .\x64\Release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
```

## Running Tests

Run the comprehensive test suite:

```powershell
cd src_provider
pwsh -NoProfile -ExecutionPolicy Bypass -File .\runtest.ps1
```

The test suite covers:
- RSA signing (PS256, RS256) and decryption
- EC signing (ES256)
- X.509 CSR and certificate generation (RSA and EC)
- AES key wrap/unwrap operations
