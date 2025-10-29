# Copilot Instructions for Azure Managed HSM OpenSSL Provider (Rust)

You are a copilot assistant to help develop the Rust implementation of the OpenSSL provider for Azure Managed HSM.

## Project Context

This is a **Rust conversion** of the C-based OpenSSL provider. The Rust implementation provides:

- Memory safety and thread safety guarantees
- Modern error handling with Result types
- Improved maintainability and testability
- Full compatibility with the C provider's functionality

## Building

To build the Rust OpenSSL Provider:

```cmd
cd src_provider_rust
winbuild.bat
```

This will:
- Build the provider in release mode
- Automatically copy `akv_provider.dll` to the OpenSSL modules directory

The build will produce: `target/release/akv_provider.dll`

## Deploying

To deploy the newly built OpenSSL Provider, first check your OpenSSL modules directory:

```cmd
openssl version -a | findstr MODULESDIR
```

This will show the modules directory path (e.g., `MODULESDIR: "C:\OpenSSL\lib\ossl-modules"`).

Then copy the provider DLL to that directory:

```powershell
Copy-Item -Path .\target\release\akv_provider.dll -Destination "C:\OpenSSL\lib\ossl-modules\" -Force
```

Note: Replace the path with your actual MODULESDIR from the first command.

The test script (runtest.bat) will automatically check if the provider is installed in the correct location.

## Testing

### Running Tests

Run the comprehensive test suite:

```cmd
cd src_provider_rust
runtest.bat
```

**By default, Azure HSM validation is SKIPPED** for faster testing. The script will:
- Check local prerequisites (OpenSSL, Azure CLI, provider DLL)
- Acquire access token automatically
- Run all cryptographic tests

To run with full Azure HSM validation (slower, ~20-30 seconds):

```cmd
runtest.bat /VALIDATE
```

This validates:
- Managed HSM accessibility
- RSA, EC, and AES key existence
- Proper permissions and authentication

The test suite covers:
- RSA signing (PS256, RS256) and decryption
- EC signing (ES256)
- X.509 CSR and certificate generation (RSA and EC)
- AES key wrap/unwrap operations

### Manual Token Setup

The test script automatically acquires the access token. If you need to manually set it for other purposes:

```powershell
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```

### Logging

The provider supports detailed logging via environment variables:

```powershell
# Enable file logging
$env:AKV_LOG_FILE=".\logs\akv_provider.log"
$env:AKV_LOG_LEVEL="3"
$env:RUST_LOG="akv_provider=trace,reqwest=warn"

# Run tests to generate logs
.\runtest.bat

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
 src/
    lib.rs              # Provider initialization and main entry point
    provider.rs         # Provider context and key structures
    store.rs            # Store loader (URI parsing, key loading)
    keymgmt.rs          # Key management operations
    signature.rs        # Signature operations
    cipher.rs           # Cipher operations (RSA decrypt, AES wrap/unwrap)
    dispatch.rs         # OpenSSL dispatch tables
    http_client.rs      # Azure Managed HSM HTTP client
    auth.rs             # Azure authentication
    ossl_param.rs       # OpenSSL parameter handling
    openssl_helpers.rs  # OpenSSL utility functions
    base64.rs           # Base64 encoding/decoding
    logging.rs          # Logging configuration
 Cargo.toml              # Rust dependencies
 build.rs                # Build script
 runtest.bat             # Test script
```

## Current Status

###  Implemented
- Provider initialization and teardown
- URI parsing (akv: and managedhsm: formats)
- Store loader structure and dispatch
- Azure HTTP client (all 6 REST API methods)
- Access token authentication
- OSSL_PARAM handling
- Base64 encoding/decoding
- Logging infrastructure with file support
- RSA and EC key management (load, export)
- RSA signing (PS256, RS256)
- EC signing (ES256)
- RSA OAEP decryption
- AES key wrap/unwrap
- X.509 CSR and certificate generation

###  Test Suite
All tests passing:
-  Store loader initialization
-  URI parsing (both akv: and managedhsm: formats)
-  Azure API integration
-  RSA public key export
-  EC public key export
-  RSA signing (PS256, RS256) with verification
-  EC signing (ES256) with verification
-  RSA OAEP decrypt roundtrip
-  X.509 CSR generation (RSA and EC)
-  X.509 self-signed certificate generation (RSA and EC)
-  AES key wrap/unwrap roundtrip
-  AES tamper detection

## Development Guidelines

1. **Use logging extensively** - File logging is configured, use it for debugging
2. **Match C implementation behavior** - Reference `src_provider/` for expected functionality
3. **Maintain FFI safety** - All `extern "C"` functions must be `unsafe`
4. **Error handling** - Use Result types internally, convert to C int at FFI boundary
5. **Memory management** - Use Box for heap allocation, careful with pointer ownership
6. **Testing** - Run `runtest.bat` frequently during development (validation is skipped by default for speed)

## Important Notes

- **runtest.bat validation**: By default, the test script skips Azure HSM validation to run faster. Multi-line if/else blocks don't work properly in batch files with `enabledelayedexpansion`, so the script uses simple single-line `if` statements with `goto`.
- **Provider loading**: The provider must be in the OpenSSL MODULESDIR for the tests to work.
- **Access tokens**: Automatically acquired from Azure CLI, valid for the session.
