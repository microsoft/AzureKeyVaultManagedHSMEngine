# Azure Key Vault Managed HSM OpenSSL Provider - Rust Implementation

This is a Rust implementation of the OpenSSL Provider for Azure Managed HSM, converted from the original C implementation in `src_provider`.

## Quick Start

### Prerequisites
- Rust toolchain (1.70+)
- Git (for vcpkg if setting up locally)
- Visual Studio Build Tools (for Windows)
- OpenSSL command-line tools

### One-Step Build and Deploy

The easiest way to build and deploy the provider:

```cmd
winbuild.bat --deploy
```

This will:
- Check for Rust toolchain
- Detect or install OpenSSL dependencies
- Configure Visual Studio environment
- Build the provider in release mode
- Deploy to OpenSSL modules directory

Options:
- `--debug` - Build in debug mode instead of release
- `--skip-deps` - Skip dependency checks (faster for rebuilds)
- `--deploy` - Automatically deploy to OpenSSL modules directory

### Manual Build Options

#### Option 1: Use Parent Directory's OpenSSL (Recommended)

If you already have the C provider built with vcpkg:

```powershell
.\bootstrap_openssl.ps1 -UseParent
cargo build --release
```

#### Option 2: Local OpenSSL Setup

To install OpenSSL locally in this directory:

```powershell
.\bootstrap_openssl.ps1
```

Then build using winbuild.bat (which sets up environment variables):

```cmd
winbuild.bat
```

Or manually with environment variables:

```powershell
$env:OPENSSL_DIR = "Q:\src\AzureKeyVaultManagedHSMEngine\src_provider_rust\vcpkg_installed\x64-windows-static"
$env:OPENSSL_STATIC = "1"
cargo build --release
```

The bootstrap script will:
- Clone and bootstrap vcpkg locally
- Install OpenSSL static libraries (`x64-windows-static`)
- Take ~5-10 minutes on first run

### Building

**Recommended:** Use the unified build script (handles all environment setup):

```cmd
winbuild.bat
```

**Manual build:** Set environment variables first:

```powershell
# Set OpenSSL location
$env:OPENSSL_DIR = "path\to\vcpkg_installed\x64-windows-static"
$env:OPENSSL_STATIC = "1"

# Build
cargo build --release
```

The compiled provider DLL will be at: `target/release/akv_provider.dll`

### Deploying

Option 1 - Automatic (via winbuild.bat):
```cmd
winbuild.bat --deploy
```

Option 2 - Manual:
```powershell
copy target\release\akv_provider.dll C:\OpenSSL\lib\ossl-modules\
```

### Testing

Run the full test suite:

```powershell
.\runtest.bat
```

Or skip validation for faster testing:

```powershell
.\runtest.bat /SKIPVALIDATION
```

## Project Structure

- `src/lib.rs` - Main library entry point and OpenSSL provider initialization
- `src/provider.rs` - Provider core functionality and URI parsing (from `akv_provider.c`)
- `src/store.rs` - Store loader for loading keys from Azure (store functions from `akv_provider.c`)
- `src/dispatch.rs` - OpenSSL dispatch tables and algorithm definitions
- `src/keymgmt.rs` - Key management operations (from `akv_keymgmt.c`, `akv_keymgmt_aes.c`)
- `src/signature.rs` - Signature operations for RSA and EC (from `akv_signature.c`)
- `src/cipher.rs` - AES cipher operations (from `akv_cipher.c`, `akv_cipher_aes.c`)
- `src/logging.rs` - Logging utilities (from `akv_logging.c`)
- `src/base64.rs` - Base64 encoding/decoding (from `base64.c`)
- `src/http_client.rs` - HTTP client for Azure Key Vault API (from `curl.c`)

## Current Implementation Status

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

2. **Store Loader** (`store.rs`)
   - `StoreContext` structure (corresponds to `AKV_STORE_CTX`)
   - Store C FFI functions:
     - `akv_store_open()` - Open store from URI
     - `akv_store_attach()` - Attach to BIO (not supported)
     - `akv_store_settable_ctx_params()` - Get settable params
     - `akv_store_set_ctx_params()` - Set params (no-op)
     - `akv_store_load()` - Load key (skeleton, needs Azure API integration)
     - `akv_store_eof()` - Check if exhausted
     - `akv_store_close()` - Close and free context

3. **Dispatch Tables** (`dispatch.rs`)
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

The provider requires the following environment variables:

- `AZURE_MANAGEDHSM_URL` - Your Azure Managed HSM URL (optional, parsed from URI)
- `AZURE_CLI_ACCESS_TOKEN` - Access token for authentication
- `AKV_LOG_LEVEL` - Log level (0=Error, 1=Info, 2=Debug, 3=Trace)
- `AKV_LOG_FILE` - Log file path (optional)

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
