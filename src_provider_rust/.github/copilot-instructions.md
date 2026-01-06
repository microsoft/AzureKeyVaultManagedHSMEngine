# Copilot Instructions for Azure Managed HSM OpenSSL Provider (Rust)

You are a copilot assistant to help develop the Rust implementation of the OpenSSL provider for Azure Managed HSM.

## Project Context

This is a **Rust conversion** of the C-based OpenSSL provider. The Rust implementation provides:

- Memory safety and thread safety guarantees
- Modern error handling with Result types
- Improved maintainability and testability
- Full compatibility with the C provider's functionality

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

---

## Windows

### Prerequisites

- Rust toolchain (install from https://rustup.rs)
- OpenSSL 3.x (via vcpkg or standalone installer)
- Azure CLI

### Building

```cmd
cd src_provider_rust
winbuild.bat
```

This will:
- Build the provider in release mode
- Automatically copy `akv_provider.dll` to the OpenSSL modules directory

Output: `target/release/akv_provider.dll`

### Deploying

Check your OpenSSL modules directory:

```cmd
openssl version -a | findstr MODULESDIR
```

Copy the provider DLL to that directory:

```powershell
Copy-Item -Path .\target\release\akv_provider.dll -Destination "C:\OpenSSL\lib\ossl-modules\" -Force
```

### Testing

Run the test suite:

```cmd
cd src_provider_rust
runtest.bat
```

With full Azure HSM validation (slower, ~20-30 seconds):

```cmd
runtest.bat /VALIDATE
```

### Manual Token Setup

```powershell
$s=(az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net)
$t=$s | ConvertFrom-Json
$Env:AZURE_CLI_ACCESS_TOKEN=$t.accessToken
```

### Logging

```powershell
$env:AKV_LOG_FILE=".\logs\akv_provider.log"
$env:AKV_LOG_LEVEL="3"
$env:RUST_LOG="akv_provider=trace,reqwest=warn"

# Run tests to generate logs
.\runtest.bat

# View logs
Get-Content .\logs\akv_provider.log
```

### Troubleshooting (Windows)

**Provider not loading:**
```cmd
openssl version -a | findstr MODULESDIR
dir "C:\OpenSSL\lib\ossl-modules\akv_provider.dll"
openssl list -providers -provider akv_provider -provider default
```

**Authentication errors:**
```cmd
az login
az account show
az account get-access-token --resource https://managedhsm.azure.net
```

---

## Ubuntu/Linux

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install OpenSSL development packages
sudo apt-get update
sudo apt-get install libssl-dev pkg-config

# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

### Building

```bash
cd src_provider_rust
./ubuntubuild.sh
```

This will:
- Check for Rust toolchain and OpenSSL development packages
- Build the provider in release mode
- Create symlink `akv_provider.so` in build directory
- Deploy `akv_provider.so` to `/usr/lib/x86_64-linux-gnu/ossl-modules/`

Output: `target/release/akv_provider.so`

### Deploying

The build script automatically deploys. To verify:

```bash
openssl version -a | grep MODULESDIR
# Should show: MODULESDIR: "/usr/lib/x86_64-linux-gnu/ossl-modules"

ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

### Testing

Run the test suite:

```bash
cd src_provider_rust
./runtest.sh
```

With full Azure HSM validation:

```bash
./runtest.sh --validate
```

### Manual Token Setup

```bash
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --output tsv --query accessToken \
    --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 \
    --resource https://managedhsm.azure.net)
```

### Logging

```bash
export AKV_LOG_FILE="./logs/akv_provider.log"
export AKV_LOG_LEVEL="3"
export RUST_LOG="akv_provider=trace,reqwest=warn"

# Run tests to generate logs
./runtest.sh

# View logs
cat ./logs/akv_provider.log
```

### Troubleshooting (Ubuntu/Linux)

**CRLF line ending errors:**
```bash
# Fix shell script line endings
sed -i 's/\r$//' ubuntubuild.sh runtest.sh
```
The `.gitattributes` file prevents this for new checkouts.

**Provider not loading:**
```bash
openssl version -a | grep MODULESDIR
ls -la /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
openssl list -providers -provider akv_provider -provider default
```

**Authentication errors:**
```bash
az login
az account show
az account get-access-token --resource https://managedhsm.azure.net
```

**TLS/HTTP errors:**
The provider rejects foreign keys (keys without HSM metadata) to prevent a circular dependency where the provider tries to use itself for TLS connections. This is handled in `keymgmt.rs`.

---

## Development Guidelines

1. **Use logging extensively** - File logging is configured, use it for debugging
2. **Match C implementation behavior** - Reference `src_provider/` for expected functionality
3. **Maintain FFI safety** - All `extern "C"` functions must be `unsafe`
4. **Error handling** - Use Result types internally, convert to C int at FFI boundary
5. **Memory management** - Use Box for heap allocation, careful with pointer ownership
6. **Testing** - Run test scripts frequently during development (validation is skipped by default for speed)
7. **Cross-platform** - Test on both Windows and Ubuntu before merging
8. **Line endings** - Shell scripts (.sh) must use LF; batch files (.bat) use CRLF

## Log Levels

| Level | Description |
|-------|-------------|
| `trace` | Very detailed function entry/exit |
| `debug` | Debugging information |
| `info` | General information |
| `warn` | Warnings |
| `error` | Errors only |
