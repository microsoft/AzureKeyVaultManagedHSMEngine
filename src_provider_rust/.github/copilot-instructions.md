# Copilot Instructions for Azure Managed HSM OpenSSL Provider (Rust)You are a copilot assistant to help create the OpenSSL provider for Azure Managed HSM



You are a copilot assistant to help develop the Rust implementation of the OpenSSL provider for Azure Managed HSM.## Testing



## Project ContextThe test script (runtest.bat) automatically acquires the access token. If you need to manually set it for other purposes, use:



This is a **Rust conversion** of the C-based OpenSSL provider. The Rust implementation provides:```powershell

- Memory safety and thread safety guarantees$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)

- Modern error handling with Result types$t=$s | ConvertFrom-Json

- Improved maintainability and testability$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken

- Full compatibility with the C provider's functionality```



## Building## Building

To build the OpenSSL Provider:

To build the Rust OpenSSL Provider:Make sure you're already in a VS Developer Command Prompt:



```powershell```cmd

cd src_provider_rust
cargo build --release

# Set environment variables for OpenSSL```

$env:OPENSSL_DIR="Q:\src\AzureKeyVaultManagedHSMEngine\src_provider\vcpkg_installed\x64-windows-static"

$env:OPENSSL_STATIC="1"The script will automatically:

- Detect or install vcpkg if needed

# Build release version- Install required dependencies (OpenSSL, curl, json-c, zlib)To deploy the newly build Openssl Provider

cargo build --release

```## Deploying



The build will produce: `target/release/akv_provider.dll`To deploy the newly built OpenSSL Provider, first check your OpenSSL modules directory:



## Deploying```cmd

openssl version -a | findstr MODULESDIR

To deploy the newly built Rust provider, first check your OpenSSL modules directory:```



```cmdThis will show the modules directory path (e.g., `MODULESDIR: "C:\OpenSSL\lib\ossl-modules"`).

openssl version -a | findstr MODULESDIR

```Then copy the provider DLL to that directory:



This will show the modules directory path (e.g., `MODULESDIR: "C:\OpenSSL\lib\ossl-modules"`).```cmd

copy .\x64\Release\akv_provider.dll "C:\OpenSSL\lib\ossl-modules\"

Then copy the provider DLL to that directory:```



```powershellNote: Replace the path with your actual MODULESDIR from the first command.

Copy-Item -Path .\target\release\akv_provider.dll -Destination "C:\OpenSSL\lib\ossl-modules\" -Force

```The test script (runtest.bat) will automatically check if the provider is installed in the correct location.



## Testing## Running Tests



The test script (runtest.bat) automatically acquires the access token. If you need to manually set it for other purposes:Run the comprehensive test suite:



```powershell```cmd

$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)cd src_provider_rust

$t=$s | ConvertFrom-Jsonruntest.bat

$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken```

```

Or skip validation checks (faster for development):

### Running Tests

```cmd

Run the comprehensive test suite:runtest.bat /SKIPVALIDATION

```

```cmd

runtest.batThe test suite covers:

```- RSA signing (PS256, RS256) and decryption

- EC signing (ES256)

Or skip validation checks (faster for development):- X.509 CSR and certificate generation (RSA and EC)

- AES key wrap/unwrap operations

```cmd
runtest.bat /SKIPVALIDATION
```

### Logging

The provider supports detailed logging via environment variables:

```powershell
# Enable file logging
$env:AKV_LOG_FILE=".\logs\akv_provider.log"
$env:AKV_LOG_LEVEL="3"
$env:RUST_LOG="akv_provider=trace,reqwest=warn"

# Run tests to generate logs
.\runtest.bat /SKIPVALIDATION

# View logs
Get-Content .\logs\akv_provider.log
```

Log levels:
- `trace` - Very detailed function entry/exit
- `debug` - Debugging information
- `info` - General information
- `warn` - Warnings
- `error` - Errors only

## Project Structure

```
src_provider_rust/
├── src/
│   ├── lib.rs              # Provider initialization and main entry point
│   ├── provider.rs         # Provider context and key structures
│   ├── store.rs            # Store loader (URI parsing, key loading)
│   ├── keymgmt.rs          # Key management operations
│   ├── signature.rs        # Signature operations
│   ├── cipher.rs           # Cipher operations (RSA decrypt, AES wrap/unwrap)
│   ├── dispatch.rs         # OpenSSL dispatch tables
│   ├── http_client.rs      # Azure Managed HSM HTTP client
│   ├── auth.rs             # Azure authentication
│   ├── ossl_param.rs       # OpenSSL parameter handling
│   ├── openssl_helpers.rs  # OpenSSL utility functions
│   ├── base64.rs           # Base64 encoding/decoding
│   └── logging.rs          # Logging configuration
├── Cargo.toml              # Rust dependencies
├── build.rs                # Build script
└── runtest.bat             # Test script
```

## Current Status

### ✅ Implemented
- Provider initialization and teardown
- URI parsing (akv: and managedhsm: formats)
- Store loader structure and dispatch
- Azure HTTP client (all 6 REST API methods)
- Access token authentication
- OSSL_PARAM handling
- Base64 encoding/decoding
- Logging infrastructure with file support

### 🚧 In Progress
- Key management dispatch (export logic implemented, callback issue)
- KEYMGMT export functionality (RSA/EC key serialization complete)

### ⏳ Not Started
- Signature operations (RSA, ECDSA)
- Cipher operations (RSA decrypt, AES wrap/unwrap)

### 🐛 Known Issues
- **Store loader callback fails**: OpenSSL rejects KEYMGMT functions with "invalid provider functions" error
  - Store successfully loads keys from Azure ✅
  - Public key construction works ✅
  - OSSL_PARAM array built correctly ✅
  - Callback returns 0 before calling akv_keymgmt_load ❌
  - Needs investigation of KEYMGMT function pointer validation

## Test Suite Coverage

The test suite covers:
- ✅ Store loader initialization
- ✅ URI parsing (both formats)
- ✅ Azure API integration
- ❌ RSA public key export (currently failing)
- ⏳ RSA signing (PS256, RS256)
- ⏳ EC signing (ES256)
- ⏳ X.509 CSR and certificate generation
- ⏳ AES key wrap/unwrap operations

## Development Guidelines

1. **Use the logging extensively** - File logging is configured, use it for debugging
2. **Match C implementation behavior** - Reference `src_provider/` for expected functionality
3. **Maintain FFI safety** - All `extern "C"` functions must be `unsafe`
4. **Error handling** - Use Result types internally, convert to C int at FFI boundary
5. **Memory management** - Use Box for heap allocation, careful with pointer ownership
6. **Testing** - Run `runtest.bat /SKIPVALIDATION` frequently during development
