# Azure Key Vault Managed HSM OpenSSL Provider - Rust Implementation

This is a Rust implementation of the OpenSSL Provider for Azure Managed HSM, converted from the original C implementation in `src_provider`.

## Supported Platforms

| Platform | Build Script | Test Script | Output |
|----------|-------------|-------------|--------|
| Windows  | `winbuild.bat` | `runtest.bat` | `akv_provider.dll` |
| Ubuntu/Linux | `./ubuntubuild.sh` | `./runtest.sh` | `akv_provider.so` |

## Quick Start

### Prerequisites

**Common:**
- Rust toolchain (1.70+)
- Azure CLI (`az`)
- OpenSSL 3.x command-line tools

**Windows:**
- Visual Studio Build Tools
- Git (for vcpkg if setting up OpenSSL locally)

**Ubuntu/Linux:**
- OpenSSL development headers (`libssl-dev`)

```bash
# Ubuntu/Debian
sudo apt-get install openssl libssl-dev
```

---

## Windows Build and Deploy

The easiest way to build and deploy the provider:

```cmd
winbuild.bat
```

That's it! This single command will:
- ✅ Check for Rust toolchain
- ✅ Detect or install OpenSSL dependencies
- ✅ Configure Visual Studio environment
- ✅ Build the provider in release mode
- ✅ Deploy to OpenSSL modules directory
- ✅ Ready to test with `runtest.bat`

Options:
- `--debug` - Build in debug mode instead of release
- `--skip-deps` - Skip dependency checks (faster for rebuilds)

### Windows Testing

After building with winbuild.bat, simply run:

```cmd
runtest.bat
```

#### Windows Test Options

- `runtest.bat` - Run all tests (fast, uses environment variable authentication)
- `runtest.bat /VALIDATE` - Run with full Azure HSM validation (slower)
- `runtest.bat /NOENV` - Use DefaultAzureCredential instead of environment variable
- `runtest.bat /VALIDATE /NOENV` - Full validation with Azure SDK authentication

### Windows Advanced: Manual OpenSSL Setup

If you want to pre-install OpenSSL before running winbuild.bat:

```powershell
.\bootstrap_openssl.ps1
```

The bootstrap script will:
- Clone and bootstrap vcpkg locally
- Install OpenSSL static libraries (`x64-windows-static`)
- Take ~5-10 minutes on first run

Then build with `winbuild.bat` (which detects the installed OpenSSL automatically).

### Windows Advanced: Manual Build with Cargo

If you prefer to build with cargo directly:

```powershell
# Set OpenSSL location
$env:OPENSSL_DIR = "Q:\src\AzureKeyVaultManagedHSMEngine\src_provider_rust\vcpkg_installed\x64-windows-static"
$env:OPENSSL_STATIC = "1"

# Build
cargo build --release

# Deploy manually
copy target\release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
```

The compiled provider DLL will be at: `target/release/akv_provider.dll`

---

## Ubuntu/Linux Build and Deploy

Build and deploy on Ubuntu/Linux:

```bash
./ubuntubuild.sh
```

This will:
- ✅ Check for Rust toolchain
- ✅ Verify OpenSSL 3.x installation
- ✅ Build the provider in release mode
- ✅ Deploy to OpenSSL modules directory (`/usr/lib/x86_64-linux-gnu/ossl-modules/`)
- ✅ Ready to test with `./runtest.sh`

Options:
- `--debug` - Build in debug mode instead of release
- `--skip-deps` - Skip dependency checks (faster for rebuilds)

### Linux Testing

After building with ubuntubuild.sh, simply run:

```bash
./runtest.sh
```

#### Linux Test Options

- `./runtest.sh` - Run all tests (fast, uses environment variable authentication)
- `./runtest.sh --validate` - Run with full Azure HSM validation (slower)
- `./runtest.sh --noenv` - Use DefaultAzureCredential instead of environment variable
- `./runtest.sh --validate --noenv` - Full validation with Azure SDK authentication

### Linux Advanced: Manual Build with Cargo

```bash
# Build
cargo build --release

# Create symlink with correct name (OpenSSL expects akv_provider.so, not libakv_provider.so)
ln -sf libakv_provider.so target/release/akv_provider.so

# Deploy manually (requires sudo)
sudo cp target/release/akv_provider.so /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

The compiled provider library will be at: `target/release/akv_provider.so`

---

## Testing Overview

Both platforms support the same test suite covering:
- RSA PS256/RS256 signing roundtrip
- RSA OAEP decrypt roundtrip  
- EC ES256 signing roundtrip
- X.509 CSR generation and verification
- Self-signed certificate generation
- AES key wrap/unwrap

The `--noenv`/`/NOENV` flag tests the Azure SDK DefaultAzureCredential authentication chain (Managed Identity → Azure CLI → Azure PowerShell) instead of using the `AZURE_CLI_ACCESS_TOKEN` environment variable.

### Verify Provider Installation

After building and deploying, verify the provider is loadable:

```bash
openssl list -providers -provider akv_provider -provider default
```

---

## Docker Testing

A Docker container is available for testing the provider without installing dependencies locally.

### Basic Provider Test

```bash
cd src_provider_rust

# Build the test container
docker build -f Dockerfile.test -t akv-provider-test .

# Run the test (verifies provider loads correctly)
docker run --rm akv-provider-test

# Run interactively for debugging
docker run --rm -it akv-provider-test bash
```

### nginx with Azure Key Vault Test

Complete end-to-end test with nginx and Key Vault:

```bash
# Build nginx container with AKV provider
docker build -f Dockerfile.nginx-keyvault -t nginx-akv .

# Set your Key Vault details
export KEYVAULT_NAME="your-keyvault-name"
export RSA_KEY_NAME="rsa-tls-key"
export EC_KEY_NAME="ec-tls-key"

# Get access token
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net --query accessToken -o tsv)

# Run nginx with Key Vault
docker run --rm -it \
    -p 8443:8443 -p 8444:8444 \
    -e KEYVAULT_NAME="$KEYVAULT_NAME" \
    -e RSA_KEY_NAME="$RSA_KEY_NAME" \
    -e EC_KEY_NAME="$EC_KEY_NAME" \
    -e AZURE_CLI_ACCESS_TOKEN="$AZURE_CLI_ACCESS_TOKEN" \
    nginx-akv

# Test (in another terminal)
curl -k https://localhost:8443  # RSA TLS
curl -k https://localhost:8444  # EC TLS
```

See [DOCKER-KEYVAULT-TESTING.md](DOCKER-KEYVAULT-TESTING.md) for detailed instructions.

### Expected Output

```
=== Loaded Providers ===
Providers:
  akv_provider
  default
    name: OpenSSL Default Provider
    version: 3.0.x
    status: active

=== Store Loaders ===
Provided STORE LOADERs:
  managedhsm @ akv_provider
  hsm @ akv_provider
  keyvault @ akv_provider
  kv @ akv_provider
  akv @ akv_provider
  file @ default
```

---

## Troubleshooting

### Provider Loading Errors

#### "unable to load provider" or "could not load the shared library"

**Symptom:**
```
openssl list -providers -provider akv_provider -provider-path "/path/to/modules"
list: unable to load provider akv_provider
error: could not load the shared library: /some/other/path/akv_provider.so: No such file or directory
```

**Cause:** OpenSSL ignores the `-provider-path` flag in some builds (especially NixOS, Alpine, or custom OpenSSL installations) and uses its compiled-in `MODULESDIR`.

**Solutions:**

1. **Use `OPENSSL_MODULES` environment variable** (most reliable):
   ```bash
   export OPENSSL_MODULES="/usr/lib/x86_64-linux-gnu/ossl-modules"
   openssl list -providers -provider akv_provider -provider default
   ```

2. **Deploy to the correct OpenSSL modules directory:**
   ```bash
   # Find OpenSSL's module directory
   MODULES_DIR=$(openssl version -m | sed 's/MODULESDIR: "\(.*\)"/\1/')
   echo "OpenSSL modules directory: $MODULES_DIR"
   
   # Copy provider
   sudo cp target/release/akv_provider.so "$MODULES_DIR/akv_provider.so"
   ```

3. **Use an OpenSSL config file** (recommended for production):
   ```bash
   cat > /tmp/openssl-akv.cnf << 'EOF'
   openssl_conf = openssl_init

   [openssl_init]
   providers = provider_sect

   [provider_sect]
   default = default_sect
   akv_provider = akv_provider_sect

   [default_sect]
   activate = 1

   [akv_provider_sect]
   module = /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
   activate = 1
   EOF

   OPENSSL_CONF=/tmp/openssl-akv.cnf openssl list -providers
   ```

4. **For NixOS/custom OpenSSL:** Copy provider to the hardcoded path shown in the error message.

#### Provider file naming (Linux only)

On Linux, Cargo automatically adds a `lib` prefix to shared libraries - this is **standard Linux convention**, not a typo:

| Platform | Cargo Output | OpenSSL Expects | Action Needed |
|----------|--------------|-----------------|---------------|
| Windows | `akv_provider.dll` | `akv_provider.dll` | None |
| Linux | `libakv_provider.so` | `akv_provider.so` | Rename/symlink |

The build scripts (`ubuntubuild.sh`, `Dockerfile.test`) automatically create a symlink. If building manually:

```bash
# Create symlink in build directory (recommended)
ln -sf libakv_provider.so target/release/akv_provider.so

# Or copy with rename when deploying
cp target/release/libakv_provider.so /path/to/modules/akv_provider.so
```

**Why does this happen?** Cargo follows the Linux convention where shared libraries are named `lib<name>.so`. This cannot be changed in `Cargo.toml`. OpenSSL provider names don't follow this convention, hence the rename.

#### Check shared library dependencies

```bash
# Verify all dependencies are satisfied
ldd /usr/lib/x86_64-linux-gnu/ossl-modules/akv_provider.so
```

### Authentication Errors

#### "401 Unauthorized" or "access token invalid"

1. **Refresh access token:**
   ```bash
   # For Managed HSM
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://managedhsm.azure.net --query accessToken -o tsv)
   
   # For Key Vault
   export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
       --resource https://vault.azure.net --query accessToken -o tsv)
   ```

2. **Verify you're logged in:**
   ```bash
   az account show
   ```

3. **Check token hasn't expired** (tokens typically last 1 hour).

### Provider Order Matters

When using both `akv_provider` and `default` providers, list `default` first in config files:

```ini
[provider_sect]
default = default_sect      # FIRST - handles normal RSA/EC operations
akv_provider = akv_provider_sect  # SECOND - handles HSM operations
```

---

## Project Structure

- `src/lib.rs` - Main library entry point and OpenSSL provider initialization
- `src/provider.rs` - Provider core functionality and URI parsing (from `akv_provider.c`)
- `src/store.rs` - Store loader for loading keys from Azure (store functions from `akv_provider.c`)
- `src/dispatch.rs` - OpenSSL dispatch tables and algorithm definitions
- `src/keymgmt.rs` - Key management operations (from `akv_keymgmt.c`, `akv_keymgmt_aes.c`)
- `src/signature.rs` - Signature operations for RSA and EC (from `akv_signature.c`)
- `src/cipher.rs` - AES cipher operations (from `akv_cipher.c`, `akv_cipher_aes.c`)
- `src/auth.rs` - Azure authentication (environment variable + DefaultAzureCredential)
- `src/logging.rs` - Logging utilities (from `akv_logging.c`)
- `src/base64.rs` - Base64 encoding/decoding (from `base64.c`)
- `src/http_client.rs` - HTTP client for Azure Key Vault API (from `curl.c`)
- `Cargo.toml` - Rust dependencies and build configuration
- `build.rs` - Build script for OpenSSL bindings
- `winbuild.bat` - Windows build and deploy script
- `runtest.bat` - Windows comprehensive test suite
- `ubuntubuild.sh` - Ubuntu/Linux build and deploy script
- `runtest.sh` - Ubuntu/Linux comprehensive test suite

## Current Implementation Status

### Recent Update (2025-10-29)
- **Added Azure SDK Authentication**: Implemented DefaultAzureCredential support with automatic fallback
  - Environment variable authentication (fast path, <1ms)
  - DefaultAzureCredential fallback (Managed Identity → Azure CLI → Azure PowerShell)
  - Smart `AccessToken::acquire()` method checks env var first, then falls back to SDK
  - Added `azure_core`, `azure_identity`, and `tokio` dependencies
- **Enhanced Test Suite**: Added `/NOENV` flag to `runtest.bat` for testing Azure SDK authentication
- **Performance Optimization**: Environment variable authentication is checked first to avoid SDK overhead

### Recent Update (2025-10-27)
- Reworked RSA/ECDSA verification to call the low-level `EVP_PKEY_verify*` APIs directly, preventing OpenSSL from double hashing pre-digested data.
- Normalized RSA modulus/exponent byte order during import/export so Azure big-endian material is reversed exactly once before reaching `OSSL_PARAM`.
- Added the `foreign-types` dependency and new OpenSSL FFI bindings required for the verification path.
- Checked in the shared `testOpenssl.cnf` used by the test harness so CSR/signing scenarios run without manual setup.
- `runtest.bat /SKIPVALIDATION` now succeeds for RSA (RS256/PS256), ECDSA, CSR, and certificate flows; AES wrap/unwrap still requires implementation.

### ✅ Completed Components

1. **Provider Core** (`provider.rs`)
   - `ProviderContext` structure (corresponds to `AKV_PROVIDER_CTX`)
   - `AkvKey` structure (corresponds to `AKV_KEY`)
   - `AkvAesKey` structure for symmetric keys
   - URI parsing functions:
     - `parse_uri_keyvalue()` - Parse `akv:vault=X,name=Y,version=Z` format
     - `parse_uri_simple()` - Parse `managedhsm:vault:keyname` format
     - `parse_uri()` - Try both formats
   - Helper functions for case-insensitive string operations

2. **Authentication** (`auth.rs`)
   - `AccessToken` structure for Azure authentication
   - `from_env()` - Fast path using AZURE_CLI_ACCESS_TOKEN environment variable
   - `from_default_credential()` - Azure SDK DefaultAzureCredential with Tokio runtime
   - `acquire()` - Smart method: env var first, DefaultAzureCredential fallback
   - Support for Managed Identity, Azure CLI, and Azure PowerShell authentication

3. **Store Loader** (`store.rs`)
   - `StoreContext` structure (corresponds to `AKV_STORE_CTX`)
   - Store C FFI functions:
     - `akv_store_open()` - Open store from URI
     - `akv_store_attach()` - Attach to BIO (not supported)
     - `akv_store_settable_ctx_params()` - Get settable params
     - `akv_store_set_ctx_params()` - Set params (no-op)
     - `akv_store_load()` - Load key (skeleton, needs Azure API integration)
     - `akv_store_eof()` - Check if exhausted
     - `akv_store_close()` - Close and free context

4. **Dispatch Tables** (`dispatch.rs`)
   - `OsslDispatch` structure matching OpenSSL's definition
   - `OsslAlgorithm` structure matching OpenSSL's definition
   - `AKV_STORE_FUNCTIONS` - Store loader dispatch table
   - `AKV_STORE_ALGS` - Store algorithm table
   - `AKV_DISPATCH_TABLE` - Main provider dispatch table
   - `query_operation_impl()` - Operation query implementation

4. **Main Provider** (`lib.rs`)
   - `OSSL_provider_init()` - Provider initialization entry point
   - `akv_teardown()` - Provider cleanup
   - `akv_get_params()` - Get provider parameters (skeleton)
   - `akv_gettable_params()` - Get gettable parameters (skeleton)
   - `akv_query_operation()` - Query operations
   - `ossl_prov_is_running()` - Provider status check

5. **Base64 Utilities** (`base64.rs`)
   - URL-safe base64 encoding/decoding
   - Standard base64 encoding/decoding
   - Unit tests

6. **Logging** (`logging.rs`)
   - `init_logging()` - Initialize env_logger
   - Logging macros

7. **HTTP Client Skeleton** (`http_client.rs`)
   - `AkvHttpClient` structure
   - POST and GET method skeletons

### 🚧 To Be Implemented

#### High Priority (Core Functionality)

1. **OSSL_PARAM Handling**
   - Implement proper OSSL_PARAM structures in Rust
   - Add parameter get/set functions
   - Update `akv_get_params()` to return actual provider info

2. **Store Loader - Azure Integration** (`store.rs`)
   - Implement `GetAccessTokenFromEnv()` equivalent
   - Add HTTP calls to Azure Key Vault API
   - Implement key type detection
   - Handle AES key loading (symmetric)
   - Handle RSA/EC key loading (asymmetric with public key material)
   - Call object callback with proper OSSL_PARAM arrays

3. **HTTP Client** (`http_client.rs`)
   - Implement actual Azure Key Vault API calls:
     - `AkvGetKey()` - Get public key material
     - `AkvGetKeyType()` - Get key type and size
     - `AkvSign()` - Sign operation
     - `AkvDecrypt()` - RSA decrypt
     - `AkvEncrypt()` - RSA encrypt
     - `AkvWrap()` - AES key wrap
     - `AkvUnwrap()` - AES key unwrap

4. **Key Management** (`keymgmt.rs`)
   - Implement RSA KEYMGMT dispatch functions
   - Implement EC KEYMGMT dispatch functions
   - Implement AES KEYMGMT dispatch functions
   - Add to dispatch table

5. **Signature Operations** (`signature.rs`)
   - Implement RSA signature dispatch functions
   - Implement ECDSA signature dispatch functions
   - Add signing logic with Azure API
   - Add to dispatch table

6. **Cipher Operations** (`cipher.rs`)
   - Implement RSA asymmetric cipher dispatch functions
   - Implement AES key wrap/unwrap dispatch functions
   - Add encryption/decryption logic with Azure API
   - Add to dispatch table

#### Medium Priority

7. **Error Handling**
   - Implement proper OpenSSL error reporting
   - Add comprehensive error types
   - Map Rust errors to OpenSSL error codes

8. **Memory Management**
   - Ensure proper cleanup of all allocated resources
   - Add reference counting where needed
   - Verify no memory leaks

9. **Testing**
   - Unit tests for all modules
   - Integration tests with mock HSM
   - Test URI parsing edge cases
   - Test error conditions

#### Low Priority

10. **Documentation**
    - Add rustdoc comments to all public functions
    - Create examples
    - Document architecture decisions

11. **Optimization**
    - Performance profiling
    - Reduce allocations where possible
    - Optimize hot paths

12. **Build System**
    - Windows build script
    - Automated deployment
    - CI/CD integration

## Building

### Prerequisites

1. **Install Rust** (if not already installed)
   ```powershell
   # Download and run rustup-init.exe from https://rustup.rs/
   # Or use winget:
   winget install Rustlang.Rustup
   ```

2. **Install OpenSSL Development Libraries**
   - The project uses vcpkg (already configured)
   - OpenSSL headers will be found via vcpkg

### Build Commands

```powershell
# Navigate to the project directory
cd q:\src\AzureKeyVaultManagedHSMEngine\src_provider_rust

# Check code without building (fast)
cargo check

# Build debug version
cargo build

# Build release version (optimized)
cargo build --release

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Build documentation
cargo doc --open
```

The compiled library will be located at:
- Debug: `target/debug/akv_provider.dll`
- Release: `target/release/akv_provider.dll`

## Deployment

Copy the compiled DLL to your OpenSSL modules directory:

```powershell
# Check your OpenSSL modules directory
openssl version -a | findstr MODULESDIR

# Copy the provider DLL (example path, adjust to your MODULESDIR)
copy target\release\akv_provider.dll "C:\OpenSSL\lib\ossl-modules\"
```

## Configuration

The provider supports two authentication methods:

### 1. Environment Variable Authentication (Default - Fast)

Set the access token directly via environment variable:

```powershell
# Get access token from Azure CLI
$token = (az account get-access-token --output json --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 --resource https://managedhsm.azure.net | ConvertFrom-Json).accessToken
$env:AZURE_CLI_ACCESS_TOKEN = $token
```

**Note**: `runtest.bat` automatically acquires and sets this token for you.

### 2. Azure SDK DefaultAzureCredential (Fallback)

If no environment variable is set, the provider automatically falls back to Azure SDK's DefaultAzureCredential, which tries:
1. **Managed Identity** - For Azure VMs, App Service, Functions
2. **Azure CLI** - Uses `az login` credentials
3. **Azure PowerShell** - Uses `Connect-AzAccount` credentials

No configuration needed - just ensure you're logged in with `az login` or `Connect-AzAccount`.

**Performance Note**: DefaultAzureCredential has ~2-3 seconds overhead per operation due to runtime initialization. Use environment variable authentication for best performance.

### Optional Configuration

- `AZURE_MANAGEDHSM_URL` - Your Azure Managed HSM URL (optional, parsed from URI)
- `AKV_LOG_LEVEL` - Log level (0=Error, 1=Info, 2=Debug, 3=Trace)
- `AKV_LOG_FILE` - Log file path (optional, e.g., `.\logs\akv_provider.log`)
- `RUST_LOG` - Rust logging filter (e.g., `akv_provider=debug,reqwest=warn`)

## Security

### TLS Certificate Validation

The provider uses **reqwest** with **native-tls** for HTTPS connections to Azure Managed HSM. Certificate validation works as follows:

#### On Windows
- Uses **SChannel** (Windows' native TLS implementation)
- Certificate validation uses the **Windows Certificate Store**
- Trusts certificates from:
  - `Trusted Root Certification Authorities` (system store)
  - `Intermediate Certification Authorities`

#### On Linux
- Uses **OpenSSL** via native-tls (system OpenSSL)
- Certificate validation uses the system CA certificates (typically `/etc/ssl/certs/`)

#### Avoiding Circular Dependencies

When the provider makes HTTPS calls to Azure Managed HSM, OpenSSL performs TLS handshake and certificate verification. During this process, OpenSSL attempts to import the server's TLS certificate public keys - and it queries **all loaded providers**, including our AKV provider.

Without proper handling, this creates a **circular dependency**:
1. Provider needs to call Azure HSM API (HTTPS)
2. OpenSSL verifies TLS certificate
3. OpenSSL tries to import certificate keys via our provider
4. Our provider tries to call Azure HSM API → infinite loop

**Note**: This issue was discovered during Ubuntu/Linux testing. On Windows, SChannel handles TLS separately from OpenSSL, so the circular dependency doesn't occur. On Linux, `native-tls` uses the system OpenSSL for TLS, which queries all loaded providers including ours.

**The Fix** (see `keymgmt.rs` line ~690): The provider **rejects keys that don't have HSM metadata** (vault name, key name). In `akv_keymgmt_import_common()`:

```rust
// Only accept imports for keys that were loaded via our store (have HSM metadata).
// Keys without metadata are foreign keys (e.g., TLS certificate chains) that should
// be handled by the default provider. This prevents circular dependencies when
// our provider makes HTTPS calls to Azure - the TLS certificate verification
// must use the default provider, not us.
if !akv_key_has_private(key) {
    return 0;  // Reject - let default provider handle
}
```

When OpenSSL queries our provider to import TLS certificate keys, we return 0 (failure) because those keys don't have HSM metadata. This allows the **default provider** to handle TLS certificate verification properly.

#### How Azure Managed HSM Certificates are Validated
1. Azure Managed HSM uses certificates signed by **DigiCert** (or similar public CA)
2. The DigiCert root CA is pre-installed in the Windows Certificate Store / Linux CA bundle
3. The TLS library automatically validates the full certificate chain:
   - Server presents: `*.managedhsm.azure.net` → DigiCert Intermediate → DigiCert Root
   - System checks the root is in the Trusted Root store ✅

#### Security Settings
The HTTP client uses secure defaults:
- ✅ Certificate validation is **enabled**
- ✅ Hostname verification is **enabled**
- ✅ Uses system CA certificates

No additional configuration is required - the provider automatically trusts Azure's publicly-signed certificates through the operating system's certificate store.

## Key Differences from C Implementation

1. **Memory Safety**: Rust's ownership system eliminates many memory-related bugs
   - No manual malloc/free
   - Automatic cleanup via Drop trait
   - Borrow checker prevents use-after-free

2. **Error Handling**: Using Result<T, E> instead of error codes
   - Explicit error propagation with `?` operator
   - Type-safe error handling
   - No silent failures

3. **Type Safety**: Strong type system prevents many common errors
   - No void* casting unless in FFI boundary
   - Compile-time type checking
   - Pattern matching for exhaustive case handling

4. **Dependencies**: Using crates instead of manual implementations
   - `reqwest` for HTTP instead of libcurl
   - `serde_json` for JSON instead of json-c
   - `base64` crate instead of custom base64
   - `azure_core` and `azure_identity` for Azure SDK authentication
   - `tokio` async runtime for Azure SDK integration
   - Less code to maintain

5. **Testing**: Built-in test framework
   - Unit tests colocated with code
   - Integration tests in `tests/` directory
   - `cargo test` to run all tests

6. **Module System**: Clear separation of concerns
   - Each module in separate file
   - Public/private visibility control
   - No header files needed

## Development Workflow

To continue the conversion from C to Rust:

1. **Pick a component** from the "To Be Implemented" list
2. **Read the C implementation** in `src_provider/`
3. **Implement in Rust** following the patterns established
4. **Add tests** to verify functionality
5. **Update this README** with progress

### Example: Implementing a new function

```rust
// 1. Read C implementation (e.g., akv_signature.c)
// 2. Create Rust equivalent in signature.rs
pub fn rsa_sign(key_name: &str, digest: &[u8]) -> Result<Vec<u8>, String> {
    // Implementation
}

// 3. Add FFI wrapper for OpenSSL
#[no_mangle]
pub unsafe extern "C" fn akv_rsa_sign(...) -> c_int {
    // Call rust_rsa_sign and handle errors
}

// 4. Add to dispatch table in dispatch.rs
// 5. Add unit tests
#[cfg(test)]
mod tests {
    #[test]
    fn test_rsa_sign() {
        // Test implementation
    }
}
```

## Current Branch

This work is on the `rust-conversion` branch. To switch back to main:

```powershell
git checkout main
```

## Contributing

When converting C code to Rust:
1. Maintain the same functionality and API surface
2. Use Rust idioms and best practices (avoid unnecessary `unsafe`)
3. Add comprehensive tests for new implementations
4. Document public APIs with rustdoc comments
5. Update this README with progress

## License

MIT License - Copyright (c) Microsoft Corporation

## Test Environment Configuration

### Azure Managed HSM Test Resources

The following Azure resources are used for testing with **Managed HSM**:

| Resource | Value | Description |
|----------|-------|-------------|
| **HSM Vault Name** | `ManagedHSMOpenSSLEngine` | Azure Managed HSM instance |
| **HSM URL** | `https://ManagedHSMOpenSSLEngine.managedhsm.azure.net` | Full HSM endpoint URL |

### Azure Key Vault Test Resources

For testing with **Azure Key Vault** (standard, not HSM):

| Resource | Value | Description |
|----------|-------|-------------|
| **Key Vault Name** | `<your-keyvault-name>` | Azure Key Vault instance |
| **Key Vault URL** | `https://<your-keyvault-name>.vault.azure.net` | Full Key Vault endpoint URL |

### Test Keys

| Key Name | Key Type | Algorithm Support | Description |
|----------|----------|-------------------|-------------|
| `myrsakey` | RSA-3072 | RS256, RS384, RS512, PS256, PS384, PS512 | RSA signing and encryption |
| `ecckey` | EC P-256 | ES256 | ECDSA signing |
| `myaeskey` | AES-256 | A256KW | AES key wrap/unwrap |

### URI Formats

Keys can be referenced using different URI schemes:

```bash
# ═══════════════════════════════════════════════════════════════════
# Azure Managed HSM URIs
# ═══════════════════════════════════════════════════════════════════

# Simple format (recommended for Managed HSM)
managedhsm:<vault>:<keyname>
managedhsm:ManagedHSMOpenSSLEngine:myrsakey

# With version
managedhsm:ManagedHSMOpenSSLEngine:myrsakey?version=<version>

# Aliases: hsm:, akv: also work for Managed HSM
hsm:ManagedHSMOpenSSLEngine:myrsakey

# ═══════════════════════════════════════════════════════════════════
# Azure Key Vault URIs (standard Key Vault, not HSM)
# ═══════════════════════════════════════════════════════════════════

# Simple format for Key Vault
keyvault:<vault>:<keyname>
keyvault:my-keyvault:myrsakey

# With version
keyvault:my-keyvault:myrsakey?version=<version>

# Alias: kv: also works
kv:my-keyvault:myrsakey

# ═══════════════════════════════════════════════════════════════════
# Key-value format (works for both)
# ═══════════════════════════════════════════════════════════════════
akv:vault=ManagedHSMOpenSSLEngine,name=myrsakey,version=<version>
```

### Environment Variables

```bash
# ═══════════════════════════════════════════════════════════════════
# For Azure Managed HSM
# ═══════════════════════════════════════════════════════════════════
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net --query accessToken -o tsv)

# ═══════════════════════════════════════════════════════════════════
# For Azure Key Vault (standard)
# ═══════════════════════════════════════════════════════════════════
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net --query accessToken -o tsv)

# Optional: Default vault (if not specified in URI)
export AKV_DEFAULT_VAULT=ManagedHSMOpenSSLEngine

# Optional: Logging
export AKV_PROVIDER_LOG=/tmp/akv.log
export RUST_LOG=akv_provider=debug
```

### Quick Test Commands

#### Testing with Managed HSM

```bash
# Set up environment for Managed HSM
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://managedhsm.azure.net --query accessToken -o tsv)

# Generate CSR with RSA key from Managed HSM
openssl req -new \
    -provider akv_provider -provider default \
    -key "managedhsm:ManagedHSMOpenSSLEngine:myrsakey" \
    -subj "/CN=Test" -out test.csr

# Generate CSR with EC key from Managed HSM
openssl req -new \
    -provider akv_provider -provider default \
    -key "managedhsm:ManagedHSMOpenSSLEngine:ecckey" \
    -subj "/CN=Test" -out test-ec.csr

# List available keys in HSM
az keyvault key list --hsm-name ManagedHSMOpenSSLEngine \
    --query "[].{name:name, kty:kty}" -o table
```

#### Testing with Azure Key Vault

```bash
# Set up environment for Key Vault (note different resource URL)
export AZURE_CLI_ACCESS_TOKEN=$(az account get-access-token \
    --resource https://vault.azure.net --query accessToken -o tsv)

# Generate CSR with RSA key from Key Vault
openssl req -new \
    -provider akv_provider -provider default \
    -key "keyvault:my-keyvault-name:myrsakey" \
    -subj "/CN=Test" -out test.csr

# Generate CSR with EC key from Key Vault
openssl req -new \
    -provider akv_provider -provider default \
    -key "kv:my-keyvault-name:ecckey" \
    -subj "/CN=Test" -out test-ec.csr

# List available keys in Key Vault
az keyvault key list --vault-name my-keyvault-name \
    --query "[].{name:name, kty:kty}" -o table
```

**Important:** Use the correct resource URL for access tokens:
- Managed HSM: `https://managedhsm.azure.net`
- Key Vault: `https://vault.azure.net`
