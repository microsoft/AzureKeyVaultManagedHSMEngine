# Copilot Instructions for Azure Managed HSM OpenSSL Provider (Rust)

You are a copilot assistant to help develop the Rust implementation of the OpenSSL provider for Azure Managed HSM.

## Project Context

This is a **Rust conversion** of the C-based OpenSSL provider. The Rust implementation provides:

- Memory safety and thread safety guarantees
- Modern error handling with Result types
- Improved maintainability and testability
- Full compatibility with the C provider's functionality

## Building

### Windows

```cmd
cd src_provider_rust
winbuild.bat
```

This will:
- Build the provider in release mode
- Automatically copy `akv_provider.dll` to the OpenSSL modules directory

The build will produce: `target/release/akv_provider.dll`

### Ubuntu/Linux

```bash
cd src_provider_rust
./ubuntubuild.sh
```

This will:
- Check for Rust toolchain and OpenSSL development packages
- Build the provider in release mode
- Deploy `libakv_provider.so` to `/usr/lib/x86_64-linux-gnu/ossl-modules/`

**Prerequisites for Ubuntu:**
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install OpenSSL development packages
sudo apt-get install libssl-dev pkg-config

# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

## Deploying

### Windows

Check your OpenSSL modules directory:

```cmd
openssl version -a | findstr MODULESDIR
```

Copy the provider DLL to that directory:

```powershell
Copy-Item -Path .\target\release\akv_provider.dll -Destination "C:\OpenSSL\lib\ossl-modules\" -Force
```

### Ubuntu/Linux

The build script automatically deploys to the modules directory. To verify:

```bash
openssl version -a | grep MODULESDIR
# Should show: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"

ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

## Testing

### Windows

```cmd
cd src_provider_rust
runtest.bat
```

With full Azure HSM validation:

```cmd
runtest.bat /VALIDATE
```

### Ubuntu/Linux

```bash
cd src_provider_rust
./runtest.sh
```

With full Azure HSM validation:

```bash
./runtest.sh --validate
```

**By default, Azure HSM validation is SKIPPED** for faster testing. The scripts will:
- Check local prerequisites (OpenSSL, Azure CLI, provider library)
- Acquire access token automatically
- Run all cryptographic tests

The test suite covers:
- RSA signing (PS256, RS256) and decryption
- EC signing (ES256)
- X.509 CSR and certificate generation (RSA and EC)
- AES key wrap/unwrap operations

### Manual Token Setup

The test scripts automatically acquire the access token. If you need to manually set it:

**Windows (PowerShell):**
```powershell
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```

**Ubuntu/Linux (Bash):**
```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token --output tsv --query accessToken --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
```

### Logging

The provider supports detailed logging via environment variables:

**Windows:**
```powershell
$env:AKV_LOG_FILE=".\logs\akv_provider.log"
$env:AKV_LOG_LEVEL="3"
$env:RUST_LOG="akv_provider=trace,reqwest=warn"
```

**Ubuntu/Linux:**
```bash
export AKV_LOG_FILE="./logs/akv_provider.log"
export AKV_LOG_LEVEL="3"
export RUST_LOG="akv_provider=trace,reqwest=warn"
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
│   ├── signature.rs        # Signature operations (RSA, ECDSA)
│   ├── cipher.rs           # Cipher operations (RSA decrypt, AES wrap/unwrap)
│   ├── dispatch.rs         # OpenSSL dispatch tables
│   ├── http_client.rs      # Azure Managed HSM HTTP client
│   ├── auth.rs             # Azure authentication
│   ├── ossl_param.rs       # OpenSSL parameter handling
│   ├── openssl_ffi.rs      # OpenSSL FFI declarations
│   ├── base64.rs           # Base64 encoding/decoding
│   └── logging.rs          # Logging configuration
├── Cargo.toml              # Rust dependencies
├── build.rs                # Build script
├── winbuild.bat            # Windows build script
├── ubuntubuild.sh          # Ubuntu/Linux build script
├── runtest.bat             # Windows test script
├── runtest.sh              # Ubuntu/Linux test script
├── testOpenssl.cnf         # OpenSSL config for CSR/cert tests
└── .gitattributes          # Line ending rules (LF for .sh, CRLF for .bat)
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
- RSA and EC key management (load, export)
- RSA signing (PS256, RS256) with DUPCTX support
- EC signing (ES256) with DUPCTX support
- RSA OAEP decryption
- AES key wrap/unwrap
- X.509 CSR and certificate generation

### ✅ Test Suite
All tests passing on Windows and Ubuntu:
- ✅ Store loader initialization
- ✅ URI parsing (both akv: and managedhsm: formats)
- ✅ Azure API integration
- ✅ RSA public key export
- ✅ EC public key export
- ✅ RSA signing (PS256, RS256) with verification
- ✅ EC signing (ES256) with verification
- ✅ RSA OAEP decrypt roundtrip
- ✅ X.509 CSR generation (RSA and EC)
- ✅ X.509 self-signed certificate generation (RSA and EC)
- ✅ AES key wrap/unwrap roundtrip
- ✅ AES tamper detection

## Development Guidelines

1. **Use logging extensively** - File logging is configured, use it for debugging
2. **Match C implementation behavior** - Reference `src_provider/` for expected functionality
3. **Maintain FFI safety** - All `extern "C"` functions must be `unsafe`
4. **Error handling** - Use Result types internally, convert to C int at FFI boundary
5. **Memory management** - Use Box for heap allocation, careful with pointer ownership
6. **Testing** - Run test scripts frequently during development (validation is skipped by default for speed)
7. **Cross-platform** - Test on both Windows and Ubuntu before merging

## Platform-Specific Notes

### Windows
- Provider file: `akv_provider.dll`
- Use `winbuild.bat` and `runtest.bat`
- OpenSSL typically installed via vcpkg or standalone installer

### Ubuntu/Linux
- Provider file: `akv_provider.so` (deployed as `libakv_provider.so`)
- Use `./ubuntubuild.sh` and `./runtest.sh`
- OpenSSL from system packages (`libssl-dev`)
- **Shell scripts must use LF line endings** (enforced by `.gitattributes`)

## Troubleshooting

### Common Issues

**CRLF line ending errors on Linux:**
```bash
# Fix shell script line endings
sed -i 's/\r$//' ubuntubuild.sh runtest.sh
```
The `.gitattributes` file prevents this for new checkouts.

**Provider not loading:**
```bash
# Check if provider is in correct location
openssl version -a | grep MODULESDIR
ls -la $(openssl version -a | grep MODULESDIR | cut -d'"' -f2)/akv_provider.so

# Test provider loading
openssl list -providers -provider akv_provider -provider default
```

**Authentication errors:**
```bash
# Ensure Azure CLI is logged in
az login
az account show

# Test token acquisition
az account get-access-token --resource https://managedhsm.azure.net
```

**TLS/HTTP errors on Ubuntu:**
The provider rejects foreign keys (keys without HSM metadata) to prevent a circular dependency where the provider tries to use itself for TLS connections. This is handled in `keymgmt.rs`.

### Debug Logging

Enable verbose logging to diagnose issues:
```bash
export AKV_LOG_FILE="./akv_debug.log"
export AKV_LOG_LEVEL="3"
export RUST_LOG="akv_provider=trace"

# Run your OpenSSL command
openssl pkey -provider akv_provider -provider default \
    -in managedhsm:ManagedHSMOpenSSLEngine:myrsakey -pubout

# Check logs
cat ./akv_debug.log
```
