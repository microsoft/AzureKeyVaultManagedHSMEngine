# Azure Key Vault Managed HSM OpenSSL Provider - Rust Implementation

This is a Rust implementation of the OpenSSL Provider for Azure Managed HSM, converted from the original C implementation in `src_provider`.

## Quick Start

### Prerequisites
- Rust toolchain (1.70+)
- Git (for vcpkg if setting up locally)
- Visual Studio Build Tools (for Windows)
- OpenSSL command-line tools

### Build and Deploy (One Command!)

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

### Testing

After building with winbuild.bat, simply run:

```cmd
runtest.bat
```

This will execute all test cases (validation is skipped by default for speed).

#### Test Options

- `runtest.bat` - Run all tests (fast, uses environment variable authentication)
- `runtest.bat /VALIDATE` - Run with full Azure HSM validation (slower)
- `runtest.bat /NOENV` - Use DefaultAzureCredential instead of environment variable
- `runtest.bat /VALIDATE /NOENV` - Full validation with Azure SDK authentication

The `/NOENV` flag tests the Azure SDK DefaultAzureCredential authentication chain (Managed Identity → Azure CLI → Azure PowerShell) instead of using the `AZURE_CLI_ACCESS_TOKEN` environment variable.

### Advanced: Manual OpenSSL Setup

If you want to pre-install OpenSSL before running winbuild.bat:

```powershell
.\bootstrap_openssl.ps1
```

The bootstrap script will:
- Clone and bootstrap vcpkg locally
- Install OpenSSL static libraries (`x64-windows-static`)
- Take ~5-10 minutes on first run

Then build with `winbuild.bat` (which detects the installed OpenSSL automatically).

### Advanced: Manual Build with Cargo

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

## Testing

Run the full test suite:

```cmd
runtest.bat
```

Use `/VALIDATE` flag for comprehensive Azure validation (slower):

```cmd
runtest.bat /VALIDATE
```

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
- `runtest.bat` - Comprehensive test suite

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
